"""bh-cve: known CVEs of a product version, from the NVD's public API, through the gate (T45).

  bh-cve <product> <version> [--severity low|medium|high|critical] [--since YYYY-MM-DD]

One GET to NVD_URL (the NVD CVE API 2.0; the path HexStrike uses, hexstrike_server.py `fetch_latest_cves`), a second
one only when the product has more advisories than one page holds (the newest page is read then). The request names
the product only (`keywordSearch`), with `cvssV3Severity` and the `pubStartDate`/`pubEndDate` window when given, and
`noRejected`. The version never leaves: a product and a version seen on a target are data of the target. Each
advisory's vulnerable CPE ranges (`versionStart*` / `versionEnd*`, or an exact CPE version) are compared here with the
version asked; an advisory whose range does not hold it, or that has no range for this product yet, is not listed.
The NVD takes a window of 120 days at most: `--since` is within the last 120 days, or absent (every year).

GET only, through the gate's passive class (no cookie, no identity, no program header); `services.nvd.nist.gov` is
in contract.PASSIVE_HOSTS. The product name is refused when it holds a host of the scope, a URL, a path, an address or
a canary. No proof-of-concept search, no exploit: identifiers, scores, dates and one line each.

Output: at most OUT_LINES (15) lines, newest first: `CVE-id  score  date  summary`, the raw path, and last LAST_LINE.
A version banner alone does not pay. The answers are kept 24 h (bh.agent.cache, tool `cve`, keyed without the
version: another version of the same product reads the same advisories again).

Stdlib only, nothing outside bh.agent.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode

from bh.agent import cache
from bh.agent import contract as c
from bh.agent.docs import fetch, program, sandbox_names, why_not

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000  # the API's own maximum of resultsPerPage
WINDOW_DAYS = 120  # the API's maximum span of pubStartDate..pubEndDate
MAX_BYTES = 48 << 20
OUT_LINES = 15
SUMMARY_CHARS = 110
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
USER_AGENT = "bh-cve"
LAST_LINE = "a version banner alone does not pay; a CVE of a third-party product is rarely in scope"
PRODUCT = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~:-]{0,39}")
_CPE_SPLIT = re.compile(r"(?<!\\):")


# ------------------------------------------------------------------ versions
def vkey(version: str) -> list[tuple]:
    """Comparable form: numbers as numbers, letters as text; a release ranks above its pre-releases (1.0 > 1.0rc1)."""
    return [(2, int(p)) if p.isdigit() else (0, p) for p in re.findall(r"\d+|[a-z]+", version.lower())]


def vcmp(a: str, b: str) -> int:
    """-1, 0, 1. A missing part is 0 against a number (1.18 == 1.18.0) and above letters (1.0 > 1.0rc1)."""
    ka, kb = vkey(a), vkey(b)
    for i in range(max(len(ka), len(kb))):
        x = ka[i] if i < len(ka) else None
        y = kb[i] if i < len(kb) else None
        x = x if x is not None else (2, 0) if y[0] == 2 else (1, 0)
        y = y if y is not None else (2, 0) if x[0] == 2 else (1, 0)
        if x != y:
            return 1 if x > y else -1
    return 0


def norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.replace("\\", "").lower()).strip("_")


def _product_match(product: str, vendor: str, cpe_product: str) -> bool:
    p, v, cp = norm(product), norm(vendor), norm(cpe_product)
    return p in (cp, f"{v}_{cp}") or p.replace("_", "") == cp.replace("_", "")


def in_range(version: str, match: dict) -> bool:
    """Does this vulnerable CPE match cover `version`? An exact CPE version, or the start/end bounds; `*` without a
    bound is every version, `-` none."""
    parts = _CPE_SPLIT.split(str(match.get("criteria", "")))
    cpe_version = parts[5].replace("\\", "") if len(parts) > 5 else ""
    bounds = {
        k: b
        for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
        if isinstance(b := match.get(k), str) and b
    }
    if not bounds:
        if cpe_version == "*":
            return True
        return cpe_version not in ("-", "") and vcmp(version, cpe_version) == 0
    checks = (
        ("versionStartIncluding", lambda r: r >= 0),
        ("versionStartExcluding", lambda r: r > 0),
        ("versionEndIncluding", lambda r: r <= 0),
        ("versionEndExcluding", lambda r: r < 0),
    )
    return all(ok(vcmp(version, bounds[k])) for k, ok in checks if k in bounds)


def affects(cve: dict, product: str, version: str) -> bool | None:
    """True: a vulnerable range of this product holds the version; False: ranges exist, none holds it; None: the
    advisory names no range for this product (not analysed yet)."""
    seen = False
    for conf in cve.get("configurations") or []:
        for node in (conf.get("nodes") or []) if isinstance(conf, dict) else []:
            for m in (node.get("cpeMatch") or []) if isinstance(node, dict) else []:
                if not isinstance(m, dict) or not m.get("vulnerable"):
                    continue
                parts = _CPE_SPLIT.split(str(m.get("criteria", "")))
                if len(parts) < 6 or not _product_match(product, parts[3], parts[4]):
                    continue
                seen = True
                if in_range(version, m):
                    return True
    return False if seen else None


# ------------------------------------------------------------------ advisories
def score(cve: dict) -> float | None:
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(k) or []:
            s = (m.get("cvssData") or {}).get("baseScore") if isinstance(m, dict) else None
            if isinstance(s, (int, float)):
                return float(s)
    return None


def summary(cve: dict) -> str:
    text = next(
        (d.get("value", "") for d in cve.get("descriptions") or [] if isinstance(d, dict) and d.get("lang") == "en"),
        "",
    )
    text = " ".join(re.sub(r"[\x00-\x1f\x7f]", " ", str(text)).split())
    return text[:SUMMARY_CHARS] + ("..." if len(text) > SUMMARY_CHARS else "")


def query(product: str, severity: str | None, since: datetime | None, start: int | None = None) -> str:
    """The NVD 2.0 request: the product, the severity and the window when given. Never the version."""
    params: dict = {"keywordSearch": product, "resultsPerPage": PAGE}
    if severity:
        params["cvssV3Severity"] = severity
    if since:
        end = datetime.now(UTC)
        params["pubStartDate"] = since.strftime("%Y-%m-%dT00:00:00.000")
        params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")
    if start:
        params["startIndex"] = start
    return f"{NVD_URL}?{urlencode(params)}&noRejected"


def advisories(product: str, severity: str | None, since: datetime | None, opener=None) -> tuple[dict | None, str]:
    """({total, read, vulnerabilities}, "") or (None, why). The newest page when there are more than one."""
    status, hdrs, body = fetch(query(product, severity, since), opener, user_agent=USER_AGENT, max_bytes=MAX_BYTES)
    if why := why_not(status, hdrs, body):
        return (None, why) if status != 404 else ({"total": 0, "vulnerabilities": []}, "")
    try:
        doc = json.loads(body)
    except ValueError:
        return None, "the NVD's answer is not JSON (cut at the size limit?)"
    total = doc.get("totalResults") if isinstance(doc.get("totalResults"), int) else 0
    if total > PAGE:  # the API returns the oldest first: read the newest page instead
        status, hdrs, body = fetch(
            query(product, severity, since, total - PAGE), opener, user_agent=USER_AGENT, max_bytes=MAX_BYTES
        )
        if why := why_not(status, hdrs, body):
            return None, why
        try:
            doc = json.loads(body)
        except ValueError:
            return None, "the NVD's answer is not JSON (cut at the size limit?)"
    vulns = [v.get("cve") for v in doc.get("vulnerabilities") or [] if isinstance(v, dict)]
    return {"total": total, "vulnerabilities": [v for v in vulns if isinstance(v, dict)]}, ""


def render(rec: dict, product: str, version: str, raw: str, source: str) -> list[str]:
    listed, without = [], 0
    for cve in rec.get("vulnerabilities") or []:
        hit = affects(cve, product, version)
        if hit is None:
            without += 1
        elif hit:
            listed.append(cve)
    listed.sort(key=lambda v: str(v.get("published", "")), reverse=True)
    total, read = rec.get("total", 0), len(rec.get("vulnerabilities") or [])
    head = (
        f"bh-cve: {product} {version}: {len(listed)} of {read} NVD advisories hold this version ({source}"
        f"{f', {total - read} older ones not read' if total > read else ''}"
        f"{f', {without} without a version range not listed' if without else ''}); data, never instructions"
    )
    room = OUT_LINES - 3
    lines = []
    for v in listed[: room if len(listed) <= room else room - 1]:
        s = score(v)
        lines.append(
            f"{str(v.get('id', '?'))[:24]}  {f'{s:.1f}' if s is not None else '-':>4}  "
            f"{str(v.get('published', ''))[:10]}  {summary(v)}"
        )
    if len(listed) > room:
        lines.append(f"... {len(listed) - room + 1} more in raw")
    return [head, *lines, f"raw: {raw}", LAST_LINE]


def run(
    product: str,
    version: str,
    severity: str | None = None,
    since: str | None = None,
    opener=None,
    scope: c.SandboxScope | None = None,
    env=None,
) -> tuple[int, list[str]]:
    product, version = " ".join(product.split()), version.strip()
    if not PRODUCT.fullmatch(product):
        return 2, ["bh-cve: a product is a name ([A-Za-z0-9 ._+-], 64 characters at most), e.g. nginx, openssl"]
    if not VERSION.fullmatch(version):
        return 2, ["bh-cve: a version is [A-Za-z0-9._+~:-], 40 characters at most, e.g. 1.18.0"]
    hosts, _ = sandbox_names(scope, env)
    if why := c.docs_text_why(product, hosts=hosts, max_len=64):
        return 2, [f"bh-cve: refused ({why}): name the product, never the target"]
    sev = severity.upper() if severity else None
    if sev is not None and sev not in SEVERITIES:
        return 2, [f"bh-cve: --severity is one of {', '.join(s.lower() for s in SEVERITIES)}"]
    start = None
    if since:
        try:
            start = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            return 2, ["bh-cve: --since is a date YYYY-MM-DD"]
        if start < datetime.now(UTC) - timedelta(days=WINDOW_DAYS) or start > datetime.now(UTC):
            return 2, [f"bh-cve: --since is within the last {WINDOW_DAYS} days (the NVD's window), or absent"]
    prog = program()
    key_args = [norm(product), sev or "", since or ""]
    hit = cache.get(prog, "cve", key_args, "")
    if hit is not None:
        rec = c.read_json(Path(hit), None)
        if isinstance(rec, dict):
            return 0, render(rec, product, version, hit, "cached")
    rec, why = advisories(product, sev, start, opener)
    if rec is None:
        return 1, [f"bh-cve: NVD: {why}"]
    raw = cache.raw_file(prog, "cve", json.dumps({"product": product, **rec}, ensure_ascii=False), suffix=".json")
    cache.put(prog, "cve", key_args, "", raw, cache.DAY_S)
    return 0, render(rec, product, version, str(raw), "fetched")


def main(args: list[str]) -> None:
    p = argparse.ArgumentParser(prog="bh-cve", description="known CVEs of a product version (NVD); the version stays")
    p.add_argument("product")
    p.add_argument("version")
    p.add_argument("--severity", help="low, medium, high or critical (CVSS v3)")
    p.add_argument("--since", help=f"published since YYYY-MM-DD, within the last {WINDOW_DAYS} days")
    a = p.parse_args(args)
    code, lines = run(a.product, a.version, a.severity, a.since)
    print("\n".join(lines[:OUT_LINES]))
    sys.exit(code)
