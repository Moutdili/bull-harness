"""bh-recon archive step (issue 32): gau output filtered to the scope, one endpoint per route family, gf classes.
No network: gau, subfinder and httpx-toolkit are shell stubs on PATH."""

import json
import shutil
import stat
from pathlib import Path

import pytest

from bh.agent import contract as c
from bh.agent import tools as t

SCOPE = """\
schema: 1
program: demo
platform: local
in_scope:
  - "*.example.com"
  - example.com
  - "https://api.example.org/v2/"
out_of_scope:
  - admin.example.com
  - "https://www.example.com/checkout/"
"""

GF = {
    "sqli": {"flags": "-iE", "patterns": ["id=", "query="]},
    "xss": {"flags": "-iE", "patterns": ["q=", "search="]},
    "redirect": {"flags": "-iE", "patterns": ["next=", "url="]},
    "broken": {"flags": "-iE", "patterns": ["("]},
}

ARCHIVED = [
    "https://www.example.com/item/1?id=1",
    "https://www.example.com/item/2?id=2&sort=asc",
    "https://www.example.com/search?q=a",
    "https://www.example.com/login?next=/home",
    "https://www.example.com/checkout/pay?id=9",  # out of scope (URL rule)
    "https://admin.example.com/panel?id=1",  # out of scope (domain rule)
    "https://example.com/",
    "http://example.com/old.php?query=x",
    "https://evil.test/?id=1",  # not in scope
    "https://www.example.com/static/app.js",  # static asset
    "https://api.example.org/v2/users?id=3",  # in scope (URL rule)
    "https://api.example.org/v1/users?id=3",  # outside the URL rule's path
]


def _exe(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def bh(tmp_path, monkeypatch):
    d = tmp_path / "bh"
    d.mkdir()
    (d / c.SCOPE).write_text(SCOPE)
    gf = tmp_path / "gf"
    gf.mkdir()
    for name, doc in GF.items():
        (gf / f"{name}.json").write_text(json.dumps(doc))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("cat", "sleep"):  # PATH is only this directory: no real gau, subfinder or httpx can run
        (bindir / tool).symlink_to(shutil.which(tool))
    monkeypatch.setenv("BH_DIR", str(d))
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setattr(t, "GF_DIR", gf)
    monkeypatch.setattr(t, "GF_CLASSES", ("sqli", "xss", "redirect", "broken", "absent"))
    return d, bindir


def _fake_gau(bindir: Path, urls: list[str], args_file: Path) -> None:
    lines = "\n".join(urls)
    _exe(bindir / "gau", f'printf "%s\\n" "$@" > {args_file}\ncat <<"EOF"\n{lines}\nEOF\n')


def _job(target: str = "example.com", timeout: int = 30) -> t.Job:
    return t.Job("recon", f"https://{target}", None, timeout)


def test_scope_filter_from_file(tmp_path):
    (tmp_path / "scope.yaml").write_text(SCOPE)
    rules = t.scope_rules(tmp_path / "scope.yaml")
    kept = [u for u in ARCHIVED if t.in_scope(u, rules, "example.com")]
    assert kept == [
        "https://www.example.com/item/1?id=1",
        "https://www.example.com/item/2?id=2&sort=asc",
        "https://www.example.com/search?q=a",
        "https://www.example.com/login?next=/home",
        "https://example.com/",
        "http://example.com/old.php?query=x",
        "https://www.example.com/static/app.js",
        "https://api.example.org/v2/users?id=3",
    ]
    # broken or missing scope file: only the queried domain and its subdomains
    assert t.scope_rules(tmp_path / "missing.yaml") is None
    (tmp_path / "bad.yaml").write_text("in_scope: [unclosed")
    assert t.scope_rules(tmp_path / "bad.yaml") is None
    assert t.in_scope("https://a.example.com/x", None, "example.com")
    assert not t.in_scope("https://example.com.evil.test/x", None, "example.com")
    assert not t.in_scope("ftp://example.com/x", None, "example.com")


def test_archive_query(tmp_path):
    (tmp_path / "scope.yaml").write_text(SCOPE)
    rules = t.scope_rules(tmp_path / "scope.yaml")
    assert t.archive_query("example.com", rules) == ("example.com", True)
    assert t.archive_query("www.example.com", rules) == ("www.example.com", True)
    assert t.archive_query("example.org", rules) == ("example.org", True)  # api.example.org is under it
    assert t.archive_query("https://api.example.org/v2/", rules) == ("api.example.org", False)
    assert t.archive_query("other.test", rules) is None
    assert t.archive_query("web.archive.org", None) is None  # a passive source is never a target
    (tmp_path / "apex.yaml").write_text("in_scope: [shop.test]\n")
    assert t.archive_query("shop.test", t.scope_rules(tmp_path / "apex.yaml")) == ("shop.test", False)


def test_family_dedup(bh):
    d, _ = bh
    c.append_jsonl(d / c.ENDPOINTS, {"origin": "https://www.example.com:443", "key": "GET /known/{id}"})
    urls = [
        "https://www.example.com/item/1?id=1",
        "https://www.example.com/item/2?sort=asc",
        "https://www.example.com/rest/basket/",
        "https://www.example.com/rest/basket/5?x=1",
        "http://www.example.com/item/3",  # another origin
        "https://www.example.com/known/7?a=1",  # family already known
        "https://www.example.com/app.js",
    ]
    fams, new, per_origin = t._add_archive_endpoints(urls)
    assert (fams, new) == (4, 3)
    assert per_origin == {"https://www.example.com:443": 2, "http://www.example.com:80": 1}
    eps = [e for e in c.read_jsonl(d / c.ENDPOINTS) if e.get("source") == "archive"]
    by_key = {(e["origin"], e["key"]): e for e in eps}
    assert by_key[("https://www.example.com:443", "GET /item/{id}")]["params"] == ["id", "sort"]
    assert by_key[("https://www.example.com:443", "GET /rest/basket/")]["params"] == ["x"]
    assert all(e["source"] == "archive" and e["status"] is None for e in eps)


def test_gf_counts(bh):
    pats = t.gf_patterns()
    assert set(pats) == {"sqli", "xss", "redirect"}  # broken regex and missing file are skipped
    classes = t.gf_classify(
        [
            "https://x.test/a?id=1",
            "https://x.test/b?q=1&url=http://y",
            "https://x.test/c?ID=2",
            "https://x.test/id=1/path",  # no query string: not classed
        ],
        pats,
    )
    assert {k: len(v) for k, v in classes.items()} == {"sqli": 2, "xss": 1, "redirect": 1}


def test_archive_step(bh, tmp_path):
    d, bindir = bh
    args = tmp_path / "gau-args.txt"
    _fake_gau(bindir, ARCHIVED, args)
    job = _job()
    lines = t.archive(job, "example.com")
    argv = args.read_text().split()
    assert argv[argv.index("--providers") + 1] == "wayback,otx,urlscan"
    assert argv[argv.index("--proxy") + 1] == c.gate()
    assert "--subs" in argv and argv[-1] == "example.com"
    conf = Path(argv[argv.index("--config") + 1]).read_text()
    assert "commoncrawl" not in conf and 'providers = ["wayback", "otx", "urlscan"]' in conf
    eps = c.read_jsonl(d / c.ENDPOINTS)
    assert eps and {e["source"] for e in eps} == {"archive"}
    hosts = {c.host_of(e["url"]) for e in eps}
    assert hosts == {"www.example.com", "example.com", "api.example.org"}
    assert not any("/checkout" in e["key"] for e in eps)
    assert "12 URLs" in lines[0] and "8 in scope" in lines[0] and "source archive" in lines[0]
    assert lines[1].startswith("gf (6 URLs with params): sqli=") and "xss=1" in lines[1]
    # raw stays on disk
    assert (job.raw / "gau.txt").read_text().count("\n") == len(ARCHIVED)
    assert (job.raw / "gf-sqli.txt").exists() and (job.raw / "archive-inscope.txt").exists()
    cov = c.read_json(d / c.COVERAGE, {})
    assert cov["https://www.example.com:443"]["archive"]["status"] == "ok"


def test_archive_cap_and_timeout(bh, tmp_path):
    _, bindir = bh
    _fake_gau(bindir, [f"https://www.example.com/p{i}" for i in range(500)], tmp_path / "a.txt")
    lines = t.archive(_job(), "example.com", max_urls=10)
    assert lines[0].startswith("archive: 10 URLs") and "cut at --max-urls" in lines[0]
    _exe(bindir / "gau", "echo https://www.example.com/slow\nexec sleep 30\n")
    lines = t.archive(_job(), "example.com", timeout=1)
    assert lines[0].startswith("archive: 1 URLs") and "timeout" in lines[0]


def test_archive_without_gau(bh):
    lines = t.archive(_job(), "example.com")
    assert lines == ["archive: skipped, gau is not installed in this sandbox (image built before issue 32?)"]


def test_archive_out_of_scope_target(bh, tmp_path):
    _, bindir = bh
    _fake_gau(bindir, ARCHIVED, tmp_path / "a.txt")
    assert "not covered by the scope" in t.archive(_job("other.test"), "other.test")[0]
    assert not (tmp_path / "a.txt").exists()  # gau never ran


def _fake_recon_tools(bindir: Path, n_live: int) -> None:
    _exe(bindir / "subfinder", "echo www.example.com\n")
    rows = "\n".join(
        json.dumps({"url": f"https://h{i}.example.com", "status_code": 200, "title": "t"}) for i in range(n_live)
    )
    _exe(bindir / "httpx-toolkit", f'cat <<"EOF"\n{rows}\nEOF\n')


def test_recon_summary_bounded(bh, tmp_path, capsys):
    _, bindir = bh
    _fake_gau(bindir, ARCHIVED, tmp_path / "a.txt")
    _fake_recon_tools(bindir, 60)
    t.recon(_job(), "example.com")
    out = capsys.readouterr().out.splitlines()
    summary = [x for x in out if x.startswith("  ") and not x.startswith("  ...")]
    assert len(summary) <= t.SUMMARY_LINES
    assert len(out) <= t.SUMMARY_LINES + 3  # headline, "... N more", raw
    assert summary[0].startswith("  archive: 12 URLs") and summary[1].startswith("  gf (")


def test_recon_without_gau(bh, capsys):
    _, bindir = bh
    _fake_recon_tools(bindir, 2)
    t.recon(_job(), "example.com")
    out = capsys.readouterr().out
    assert "archive: skipped, gau is not installed" in out
    assert "2 live HTTP services" in out and "[ok]" in out


def test_recon_cli_no_archive(bh, tmp_path, capsys):
    _, bindir = bh
    _fake_gau(bindir, ARCHIVED, tmp_path / "a.txt")
    _fake_recon_tools(bindir, 1)
    t.main("recon", ["example.com", "--no-archive", "--timeout", "30"])
    assert "archive:" not in capsys.readouterr().out
    assert not (tmp_path / "a.txt").exists()
