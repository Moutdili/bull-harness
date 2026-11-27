"""bh-authz: authorization matrix over the known endpoints (the Autorize / AuthMatrix method, automated).

  bh-authz [<url>...] [--from endpoints|touched] [--owner ID] [--as ID,ID] [--anon] [--methods GET,HEAD]
           [--write-own] [--max N]
  bh-authz --baseline <url> [--as ID,ID]

1. Ownership markers: each identity's own "me" page (/me, /api/me, whoami, /profile, /account..., at most
   ME_PROBES requests each) gives its ids, emails and names. Only markers no other identity shares are kept.
2. Every endpoint (the URLs given, else endpoints.jsonl + touched.jsonl, API routes first, `--max`) is requested as
   the owner, as each other identity and without a session (anonymous: always without --as, with --anon if --as).
   Status, size, short hash and JSON key shape are compared. A collection the owner lists expands to at most
   EXPAND items the owner provably owns (its markers in the item, or an id the other identities do not list):
   real objects only, never an id sweep.
3. A candidate: another identity (or anonymous) gets an answer holding the owner's markers. Roles and tenants
   (BH_IDENTITY_ROLES="user-a=member@A,admin-a=admin@A"; absent: one role, one tenant per identity) type it:
   horizontal (same role, the other tenant's object), vertical (a lower role reads a higher role's data, or gets
   the same answer as the higher role on a privileged-looking route that anonymous is refused).
4. --write-own: on objects whose owner answer holds the owner's markers (ours, proven), another of our identities
   PATCHes (else PUTs) one benign text field with a unique token; the owner reads the object back to see the
   effect, then restores it. Never DELETE, never an object no identity of ours owns.

Gate: sequential requests, refusals (`X-BH-Gate: denied`) counted and shown, never retried or bypassed. 401 answers
under one identity on GUARD_401 routes stop that identity (the gate reads 401s on 3 routes as a dead session).
Output: at most 25 lines; requests and answers per identity in raw/authz-*/exchanges.jsonl, a proof.json for the
best candidate (format of bh.agent.proof, validated), coverage phase `authz`, tested endpoints in touched.jsonl.
The summary ends with `N routes in, N tested, missing: ...` (the routes given or known, against the rows tested) and
`next: <one action>`; a run where the owner got no usable answer at all (gate refusals, rate limit, unreachable, 401
everywhere) prints `[bh-fail] <class>: <action>` and marks nothing tested.
Baseline per role (T25, --baseline): no attack request at all. For each identity (BH_IDENTITIES, or --as), the routes
the interface offers it: `bh-browse <url> --routes --as <identity>` (its raw routes.txt), written to
<BH_DIR>/baseline/<identity>.json = {"routes": [...], "ts"}. The host copies it after the segment, keeping only the
routes the gate saw under that identity (bh.accounts.baseline): the judge weighs a vertical finding against it.

Classification: a mapper; with --write-own a scanner (refused where the program forbids scanners). The verifier
may not run it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlsplit

from bh.agent import contract as c
from bh.agent import fail

MAX_LINES = 25
DEFAULT_MAX = 30
ME_PROBES = 8  # "me" requests per identity at most
EXPAND = 2  # items of one collection turned into object endpoints (the gate allows 4 ids per route in 10 min)
WRITE_MAX = 3  # objects written per run
GUARD_401 = 2  # distinct routes answering 401 to one identity before it stops (the gate's threshold is 3)
BODY_KEEP = 64 << 10
TIMEOUT_S = 20
ME_PATHS = (
    "me",
    "users/me",
    "user",
    "whoami",
    "profile",
    "account",
    "user/whoami",
    "session",
)
ROLE_RANK = {
    "guest": 0,
    "viewer": 0,
    "user": 1,
    "member": 1,
    "customer": 1,
    "editor": 2,
    "manager": 2,
    "moderator": 2,
    "staff": 3,
    "admin": 3,
    "owner": 3,
    "superuser": 4,
    "root": 4,
}
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
ID_KEY = re.compile(r"^(id|uid|uuid|sub|pk|(user|account|member|customer|profile)_?id)$", re.I)
NAME_KEY = re.compile(r"^(username|user_?name|login|handle|nickname|display_?name|full_?name|name)$", re.I)
TENANT_KEY = re.compile(r"^(org|organi[sz]ation|tenant|company|team|workspace)(_?id)?$", re.I)
# keys that say "this object belongs to user X" when their value is X's id
OWNER_WORDS = (
    r"user|owner|author|creator|created_?by|member|customer|account|booked_?by|requester|reporter|profile|"
    r"organi[sz]er|host|assignee|holder"
)
OWNER_KEY = re.compile(rf"^(uid|sub|({OWNER_WORDS})(_?id)?)$", re.I)
# a nested {"id": 7} counts when its parent names an owner: {"organizer": {"id": 7, ...}}
OWNER_PARENT = re.compile(rf"^({OWNER_WORDS})$", re.I)
# GET routes never sent: they end a session or change state
UNSAFE_PATH = re.compile(r"/(log-?out|sign-?out|delete|remove|destroy|unsubscribe|deactivate|revoke|reset)\b", re.I)
PRIV_PATH = re.compile(
    r"/(admin|manage(ment)?|internal|staff|stats|reports?|audit|export|config|settings|users)\b", re.I
)
# text fields a write may touch (a benign, visible change), and keys never touched
WRITE_FIELD = re.compile(
    r"^(title|name|note|notes|description|comment|label|subject|summary|purpose|memo|topic)$", re.I
)
ITEM_ID = ("id", "uuid", "ref", "slug", "key")
API_SEG = re.compile(r"api|rest|graphql|v\d+", re.I)  # the segment an API prefix ends with


# ------------------------------------------------------------------ requests
@dataclass
class Answer:
    status: int
    body: bytes = b""
    ctype: str = ""
    denied: bool = False  # refused by the gate (X-BH-Gate: denied), never by the target

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300 and not self.denied

    @property
    def digest(self) -> str:
        return hashlib.sha1(self.body).hexdigest()[:4]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        try:
            return json.loads(self.body[: 4 << 20])
        except ValueError:
            return None


def _send(method: str, url: str, who: str | None, body: dict | None = None) -> Answer:
    """One request through the environment's proxy (the gate); redirects are answers."""
    headers = {"Accept": "application/json, */*"}
    if who:
        headers[c.IDENTITY_HEADER] = who
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=TIMEOUT_S) as resp:
            raw = resp.read(4 << 20)
            return Answer(resp.status, raw, resp.headers.get("Content-Type", ""), _refused(resp.headers))
    except urllib.error.HTTPError as err:
        raw = err.read(4 << 20) or b""
        return Answer(err.code, raw, err.headers.get("Content-Type", ""), _refused(err.headers))
    except urllib.error.URLError as err:  # an https CONNECT the gate refused never reaches the target
        refused = "403" in str(err.reason) and "unnel" in str(err.reason)
        return Answer(403 if refused else 0, str(err.reason).encode()[:200], "", refused)
    except (OSError, ValueError) as exc:
        return Answer(0, str(exc).encode()[:200])


def _refused(headers) -> bool:
    return (headers.get(c.GATE_HEADER) or "").lower() == "denied"


class Client:
    """Sequential requests, every exchange kept on disk, gate refusals counted, the 401 guard per identity."""

    def __init__(self, raw: Path) -> None:
        self.raw = raw
        self.denied = 0
        self.sent = 0
        self.unauth: dict[str, set[str]] = {}

    def stopped(self, who: str | None) -> bool:
        return bool(who) and len(self.unauth.get(who, ())) >= GUARD_401

    def __call__(self, method: str, url: str, who: str | None, body: dict | None = None) -> Answer | None:
        if self.stopped(who):
            return None
        ans = _send(method, url, who, body)
        self.sent += 1
        self.denied += ans.denied
        if who and ans.status == 401 and not ans.denied:
            self.unauth.setdefault(who, set()).add(c.path_key(urlsplit(url).path))
        c.append_jsonl(
            self.raw / "exchanges.jsonl",
            {
                "as": who,
                "method": method,
                "url": url,
                "body": body,
                "status": ans.status,
                "denied": ans.denied,
                "type": ans.ctype,
                "len": len(ans.body),
                "sha1": hashlib.sha1(ans.body).hexdigest(),
                "answer": ans.body[:BODY_KEEP].decode("utf-8", "replace"),
            },
        )
        return ans


# ------------------------------------------------------------------ identities, roles, markers
@dataclass(frozen=True)
class Role:
    role: str
    tenant: str

    @property
    def rank(self) -> int:
        return ROLE_RANK.get(self.role.lower(), 1)


def roles(names: list[str], spec: str | None = None) -> dict[str, Role]:
    """BH_IDENTITY_ROLES="user-a=member@A,admin-a=admin@A": role and tenant optional. Absent: one role, and every
    identity its own tenant."""
    spec = os.environ.get("BH_IDENTITY_ROLES", "") if spec is None else spec
    parsed: dict[str, tuple[str, str]] = {}
    for item in filter(None, (x.strip() for x in spec.split(","))):
        name, _, rest = item.partition("=")
        role, _, tenant = rest.partition("@")
        parsed[name.strip()] = (role.strip(), tenant.strip())
    out = {}
    for n in names:
        role, tenant = parsed.get(n, ("", ""))
        out[n] = Role(role or "user", tenant or n)
    return out


@dataclass(frozen=True)
class Marker:
    kind: str  # email, name, uuid, id, tenant
    key: str
    value: str


def _pairs(doc, parent: str = "", depth: int = 0):
    """(parent key, key, value) of every scalar in a JSON document, a few levels deep."""
    if depth > 4:
        return
    if isinstance(doc, dict):
        for k, v in doc.items():
            if isinstance(v, (dict, list)):
                yield from _pairs(v, str(k), depth + 1)
            elif v is not None and not isinstance(v, bool):
                yield parent, str(k), v
    elif isinstance(doc, list):
        for v in doc[:50]:
            yield from _pairs(v, parent, depth + 1)


def markers_of(doc) -> set[Marker]:
    """Ids, emails, names and tenant ids that a "me" answer gives about its identity."""
    out: set[Marker] = set()
    for parent, key, value in _pairs(doc):
        s = str(value)
        if isinstance(value, str) and EMAIL.fullmatch(s):
            out.add(Marker("email", key, s))
        elif TENANT_KEY.match(key) or (TENANT_KEY.match(parent) and ID_KEY.match(key)):
            out.add(Marker("tenant", key if TENANT_KEY.match(key) else f"{parent}_id", s))
        elif ID_KEY.match(key) and not parent:
            kind = "uuid" if isinstance(value, str) and len(s) >= 8 else "id"
            out.add(Marker(kind, key, s))
        elif NAME_KEY.match(key) and isinstance(value, str) and len(s) >= 5:
            out.add(Marker("name", key, s))
    return out


def unique_markers(all_markers: dict[str, set[Marker]]) -> dict[str, set[Marker]]:
    """Each identity's markers that no other identity shares (a shared tenant id or role value proves nothing)."""
    out = {}
    for who, ms in all_markers.items():
        others = {m.value.lower() for o, oms in all_markers.items() if o != who for m in oms}
        out[who] = {m for m in ms if m.value.lower() not in others}
    return out


def find(markers: set[Marker], ans: Answer) -> list[tuple[Marker, str]]:
    """(marker, literal needle) of each marker present in an answer. Strings match as words; a numeric or short id
    only as the value of an owner-like key (`"user_id": 7`, `"owner": {"id": 7}`), so a 7 elsewhere (an object's own
    id, a count) does not count."""
    text = ans.text
    doc = None
    hits = []
    for m in sorted(markers, key=lambda m: ("email", "uuid", "id", "name", "tenant").index(m.kind)):
        if m.kind in ("email", "uuid", "name"):
            if re.search(rf"(?<![\w@.-]){re.escape(m.value)}(?![\w@-])", text):
                hits.append((m, m.value))
            continue
        doc = ans.json() if doc is None else doc
        for parent, key, value in _pairs(doc) if doc is not None else ():
            if str(value) != m.value:
                continue
            v = rf'"?{re.escape(m.value)}"?(?![\w.-])'
            rx = rf'"{re.escape(key)}"\s*:\s*{v}'
            if m.kind == "tenant":
                k = f"{parent}_id" if parent and not TENANT_KEY.match(key) else key
                if not (TENANT_KEY.match(k) or k == m.key):
                    continue
            elif key.lower() in ("id", "pk"):  # an object's own id: only under an owner-like parent
                if not (parent and OWNER_PARENT.match(parent)):
                    continue
                rx = rf'"{re.escape(parent)}"\s*:\s*\{{[^{{}}]*?"{re.escape(key)}"\s*:\s*{v}'
            elif not (OWNER_KEY.match(key) or key == m.key):
                continue
            if found := re.search(rx, text):
                hits.append((m, found.group(0)))
                break
    return hits


def _api_bases(url: str) -> list[str]:
    """Prefixes of the URL's path that may hold a "me" route: /api/v1/bookings -> /api/v1, /api, ''."""
    segs = [s for s in urlsplit(url).path.split("/") if s]
    bases = ["/" + "/".join(segs[:i]) for i in range(len(segs), 0, -1) if API_SEG.fullmatch(segs[i - 1])]
    return [*bases, ""]


def learn(
    client: Client, origin: str, sample_url: str, who: str, *, known: list[str], hint: list[str]
) -> tuple[set[Marker], str]:
    """An identity's markers from its own "me" page: (markers, path used, or '')."""
    guesses = [f"{b}/{p}" for p in ME_PATHS for b in _api_bases(sample_url)]
    paths = list(dict.fromkeys(hint + known + guesses))
    for path in paths[:ME_PROBES]:
        ans = client("GET", origin + path, who)
        if ans is None:
            break
        doc = ans.json() if ans.ok else None
        ms = markers_of(doc) if isinstance(doc, dict) else set()
        if ms:
            return ms, path
    return set(), ""


# ------------------------------------------------------------------ endpoints
@dataclass
class Endpoint:
    method: str
    url: str
    via: str = "given"
    owned: bool = False  # expanded from the owner's own listing


def known_endpoints(sources: str, methods: set[str]) -> list[Endpoint]:
    """Known endpoints of the sandbox, API routes first, one URL per route. A route with an id comes only with a
    real URL (from endpoints.jsonl); touched.jsonl keeps no URL, so only its id-free routes are usable."""
    d = c.bh_dir()
    seen: dict[tuple[str, str], Endpoint] = {}
    if sources in ("endpoints", "both"):
        for e in c.read_jsonl(d / c.ENDPOINTS):
            method, _, path = str(e.get("key", "")).partition(" ")
            url = str(e.get("url") or "")
            if method in methods and c.origin(url) and not c.STATIC_EXT.search(path):
                k = (str(e.get("origin")), c.family(e["key"]))
                seen.setdefault(k, Endpoint(method, url.split("#", maxsplit=1)[0], "endpoints"))
    if sources in ("touched", "both"):
        for t in c.read_jsonl(d / c.TOUCHED):
            method, _, path = str(t.get("key", "")).partition(" ")
            if method in methods and "{id}" not in path and t.get("origin") and not c.STATIC_EXT.search(path):
                url = str(t["origin"]) + path
                seen.setdefault((str(t["origin"]), c.family(t["key"])), Endpoint(method, url, "touched"))
    eps = [e for e in seen.values() if not UNSAFE_PATH.search(urlsplit(e.url).path)]
    eps.sort(key=lambda e: (not c.API_PATH.search(_path(e.url)), "{id}" not in c.path_key(_path(e.url)), e.url))
    return eps


def _path(url: str) -> str:
    return urlsplit(url).path or "/"


def _items(doc) -> list[dict]:
    if isinstance(doc, list):
        return [x for x in doc if isinstance(x, dict)]
    if isinstance(doc, dict):
        for v in doc.values():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v[:5]):
                return [x for x in v if isinstance(x, dict)]
    return []


def _item_id(item: dict) -> str | None:
    for k in ITEM_ID:
        v = item.get(k)
        if isinstance(v, (int, str)) and not isinstance(v, bool) and str(v) and "/" not in str(v):
            return str(v)
    return None


def owned_items(owner_ans: Answer, others: list[Answer], owner_marks: set[Marker]) -> list[str]:
    """Ids of the owner's own items in a listing: its markers in the item, else ids no other identity lists."""
    items = _items(owner_ans.json())
    other_ids = {i for a in others for x in _items(a.json()) if (i := _item_id(x))}
    mine, private = [], []
    for item in items:
        iid = _item_id(item)
        if iid is None:
            continue
        if find(owner_marks, Answer(200, json.dumps(item).encode())):
            mine.append(iid)
        elif other_ids and iid not in other_ids:
            private.append(iid)
    return list(dict.fromkeys(mine or private))[:EXPAND]


# ------------------------------------------------------------------ judging
@dataclass
class Row:
    ep: Endpoint
    answers: dict[str, Answer | None]  # identity name, or "anon"
    hits: dict[str, list[tuple[Marker, str]]] = field(default_factory=dict)  # who -> owner markers in its answer
    owner_hits: list[tuple[Marker, str]] = field(default_factory=list)
    kind: str = ""  # horizontal, vertical, unauth, or "" (sane)
    note: str = ""


def _keys(ans: Answer) -> str:
    doc = ans.json()
    if isinstance(doc, list):
        doc = doc[0] if doc and isinstance(doc[0], dict) else {}
    return ",".join(sorted(doc)) if isinstance(doc, dict) else ""


def judge(row: Row, owner: str, rl: dict[str, Role], uniq: dict[str, set[Marker]]) -> None:
    o = row.answers.get(owner)
    if o is None or not o.ok:
        return
    row.owner_hits = find(uniq.get(owner, set()), o)
    for who, ans in row.answers.items():
        if who == owner or ans is None or not ans.ok:
            continue
        own = {m.value for m, _ in find(uniq.get(who, set()), ans)} if who != "anon" else set()
        hits = [(m, n) for m, n in find(uniq.get(owner, set()), ans) if m.value not in own]
        if not row.owner_hits or not hits:
            continue
        tenant_only = all(m.kind == "tenant" for m, _ in hits)
        if tenant_only and who != "anon" and rl[who].tenant == rl[owner].tenant:
            continue  # a shared tenant id is not the owner's object
        row.hits[who] = hits
    if row.hits:
        attackers = [w for w in row.hits if w != "anon"]
        if not attackers:
            row.kind = "unauth"
        elif any(rl[w].rank < rl[owner].rank for w in attackers):
            row.kind = "vertical"
        else:
            row.kind = "horizontal"
            if all(rl[w].tenant == rl[owner].tenant for w in attackers):
                row.note = "same tenant: check it is not shared by design"
        return
    # vertical without markers: a lower role gets the answer a higher role gets, on a route anonymous is refused
    anon = row.answers.get("anon")
    if (anon is not None and anon.ok) or not PRIV_PATH.search(urlsplit(row.ep.url).path):
        return
    for hi, ha in row.answers.items():
        if hi == "anon" or ha is None or not ha.ok:
            continue
        for lo, la in row.answers.items():
            if lo in ("anon", hi) or la is None or not la.ok or rl[lo].rank >= rl[hi].rank:
                continue
            similar = la.digest == ha.digest or (_keys(la) and _keys(la) == _keys(ha))
            if similar:
                row.kind, row.note = "vertical", f"{lo} ({rl[lo].role}) gets what {hi} ({rl[hi].role}) gets"
                row.hits.setdefault(lo, [])
                return


# ------------------------------------------------------------------ writes on our own objects
@dataclass
class Write:
    url: str
    who: str
    method: str = ""
    status: int = 0
    field_: str = ""
    value: str = ""
    token: str = ""
    effect: bool = False
    restored: bool | None = None
    echoed: bool = False
    note: str = ""


def _write_field(doc: dict) -> tuple[str, str] | None:
    for k, v in doc.items():
        if WRITE_FIELD.match(str(k)) and isinstance(v, str) and len(v) < 200 and not EMAIL.search(v):
            return str(k), v
    return None


def try_write(client: Client, row: Row, owner: str, writers: list[str], uniq: dict[str, set[Marker]]) -> Write | None:
    """Another of our identities changes one text field of the owner's object; the owner reads it back, then
    restores it. Returns None when the object is not provably the owner's (no write is sent then)."""
    o = row.answers.get(owner)
    doc = o.json() if o is not None and o.ok else None
    if not isinstance(doc, dict) or not row.owner_hits or not (row.ep.owned or "{id}" in c.path_key(_path(row.ep.url))):
        return None
    if any(find(uniq.get(w, set()), o) for w in writers):
        return None  # the object also carries another identity's markers: not the owner's alone
    pick = _write_field(doc)
    if pick is None:
        return Write(row.ep.url, writers[0] if writers else "", note="no text field to change")
    key, orig = pick
    token = "bhauthz" + secrets.token_hex(3)
    new = f"{orig} {token}" if len(orig) < 100 else token
    w = Write(row.ep.url, "", field_=key, value=new, token=token)
    for who in writers:
        w.who, sent = who, False
        for method, body in (("PATCH", {key: new}), ("PUT", {**doc, key: new})):
            ans = client(method, row.ep.url, who, body)
            if ans is None or ans.denied:
                w.note = "refused by the gate" if ans is not None else f"{who} stopped (401 guard)"
                break
            w.method, w.status, sent = method, ans.status, True
            if ans.status not in (404, 405, 501):
                w.echoed = token in ans.text
                break
        if not sent:
            continue
        back = client("GET", row.ep.url, owner)
        w.effect = back is not None and back.ok and token in back.text
        if w.effect:
            put = w.method == "PUT"
            client(w.method, row.ep.url, owner, doc if put else {key: orig})
            check = client("GET", row.ep.url, owner)
            w.restored = check is not None and check.ok and token not in check.text
            return w
    return w


# ------------------------------------------------------------------ proof
def read_proof(row: Row, owner: str) -> dict | None:
    """Best read proof of a candidate row: attack = another identity (else anonymous), control = anonymous or a third
    identity whose answer lacks the needle; the owner's own read is the setup."""
    o = row.answers[owner]
    for who, hits in sorted(row.hits.items(), key=lambda kv: kv[0] == "anon"):
        if not hits:
            continue
        needle = hits[0][1]
        a = row.answers[who]
        ctrls = [k for k in ("anon", *row.answers) if k not in (owner, who)]
        for ctrl in dict.fromkeys(ctrls):
            ca = row.answers.get(ctrl)
            if ca is None or ca.denied or needle in ca.text:
                continue
            url = row.ep.url
            mine = needle if needle in o.text else None
            setup = _step(f"{owner} reads its own object", "setup", owner, "GET", url, status=[o.status], contains=mine)
            attack = _step(f"{_name(who)} reads {owner}'s object", "attack", who, "GET", url, status=[a.status])
            attack["expect"]["contains"] = [needle]
            control = _step(f"{_name(ctrl)}: same request", "control", ctrl, "GET", url, status=[ca.status])
            control["expect"]["absent"] = [needle]
            return {"steps": [setup, attack, control]}
    return None


def write_proof(w: Write, row: Row, owner: str) -> dict | None:
    """A cross-identity write: the write, the owner reading the change, and a twin that does not see it."""
    if not w.effect:
        return None
    url = row.ep.url
    role = "attack" if w.echoed else "setup"
    write = _step(f"{w.who} writes {owner}'s object", role, w.who, w.method, url, status=[w.status])
    write["body"] = {w.field_: w.value}
    if w.method == "PUT":
        write["body"] = {**row.answers[owner].json(), w.field_: w.value}
    if w.echoed:
        write["expect"]["contains"] = [w.token]
    steps = [write, _step(f"{owner} reads the change", "attack", owner, "GET", url, status=[200], contains=w.token)]
    for ctrl in dict.fromkeys(("anon", *row.answers)):
        ca = row.answers.get(ctrl)
        if ctrl in (owner, w.who) or ca is None or ca.denied or ca.ok:
            continue
        steps.append(
            _step(f"{_name(ctrl)}: same read", "control", ctrl, "GET", url, status=[ca.status], absent=w.token)
        )
        return {"steps": steps}
    return None


def _name(who: str) -> str:
    return "without a session" if who == "anon" else who


def _step(name, role, who, method, url, *, status, contains=None, absent=None) -> dict:
    exp: dict = {"status": status}
    if contains:
        exp["contains"] = [contains]
    if absent:
        exp["absent"] = [absent]
    return {
        "name": name,
        "role": role,
        "as": None if who == "anon" else who,
        "method": method,
        "url": url,
        "expect": exp,
    }


# ------------------------------------------------------------------ CLI
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="bh-authz", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    p.add_argument("urls", nargs="*", help="endpoints (default: the known ones)")
    p.add_argument("--from", dest="source", choices=("endpoints", "touched", "both"), default="both")
    p.add_argument("--owner", help="identity whose objects are tested (default: the first)")
    p.add_argument("--as", dest="others", help="identities compared to the owner, comma-separated (default: all)")
    p.add_argument("--anon", action="store_true", help="also anonymous when --as is given (always without --as)")
    p.add_argument("--methods", default="GET", help="read methods, among GET and HEAD")
    p.add_argument("--write-own", action="store_true", help="cross-identity PATCH/PUT on the owner's objects")
    p.add_argument("--max", type=int, default=DEFAULT_MAX, help="endpoints at most")
    p.add_argument(
        "--baseline", action="store_true", help="per identity, the routes the interface offers (bh-browse --routes)"
    )
    a = p.parse_args(argv)
    if a.baseline and (len(a.urls) != 1 or a.write_own or a.owner):
        p.error("--baseline: one start URL, no --write-own, no --owner")
    a.methods = {m.strip().upper() for m in a.methods.split(",") if m.strip()}
    if a.methods - {"GET", "HEAD"}:
        p.error("--methods: GET and HEAD only (writes: --write-own)")
    return a


def main(argv: list[str]) -> None:
    a = parse_args(argv)
    if c.is_verifier():
        sys.exit(f"{c.RULES_MARK} bh-authz: the verifier re-tests with single requests only")
    if a.write_own and not c.scanners_allowed():
        sys.exit(f"{c.RULES_MARK} bh-authz --write-own: this program forbids automated scanners")
    names = [i for i in os.environ.get("BH_IDENTITIES", "").split(",") if i]
    if not names:
        sys.exit("bh-authz: no identity for this program (BH_IDENTITIES): nothing to compare")
    if a.baseline:
        who = [w for w in (a.others.split(",") if a.others else names) if w]
        if unknown := [w for w in who if w not in names]:
            sys.exit(f"bh-authz: unknown identity {unknown[0]!r}")
        url = a.urls[0] if "://" in a.urls[0] else f"https://{a.urls[0]}"
        if c.origin(url) is None:
            sys.exit("bh-authz: need an http(s) URL")
        print("\n".join(baseline(url, who)))
        return
    owner = a.owner or names[0]
    if owner not in names:
        sys.exit(f"bh-authz: unknown owner {owner!r} (identities: {', '.join(names)})")
    others = [w for w in (a.others.split(",") if a.others else names) if w and w != owner]
    if unknown := [w for w in others if w not in names]:
        sys.exit(f"bh-authz: unknown identity {unknown[0]!r}")
    with_anon = a.anon or not a.others
    if a.urls:
        eps = [Endpoint("GET", u if "://" in u else f"https://{u}") for u in a.urls]
        if any(c.origin(e.url) is None for e in eps):
            sys.exit("bh-authz: need http(s) URLs")
    else:
        eps = known_endpoints(a.source, a.methods)
        if not eps:
            sys.exit("bh-authz: no known endpoint yet: map first (bh-crawl, bh-content) or give URLs")
    routes_in = list(eps)
    eps = eps[: max(1, a.max)]
    run(eps, owner, others, with_anon=with_anon, write_own=a.write_own, limit=max(1, a.max), routes_in=routes_in)


# ------------------------------------------------------------------ baseline per role (T25)
BASELINE_DIR = "baseline"
BASELINE_TIMEOUT_S = 120
BASELINE_ROUTES_MAX = 500


def browse_routes(url: str, who: str, timeout: int = BASELINE_TIMEOUT_S) -> list[str] | None:
    """The routes `bh-browse <url> --routes --as <who>` saw (its raw routes.txt); None when it failed."""
    try:
        r = subprocess.run(
            ["bh-browse", url, "--routes", "--as", who, "--timeout", str(timeout)],
            capture_output=True,
            text=True,
            timeout=timeout + 60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"^raw: (.+?)/?$", r.stdout or "", re.M)
    if r.returncode or m is None:
        return None
    f = Path(m.group(1)) / "routes.txt"
    try:
        return [line.strip() for line in f.read_text().splitlines() if line.strip()]
    except OSError:
        return None


def baseline(url: str, names: list[str], *, browse=None, now: float | None = None) -> list[str]:
    """One bh-browse per identity, no attack; <BH_DIR>/baseline/<identity>.json each. The summary lines."""
    browse = browse or browse_routes
    d = c.bh_dir() / BASELINE_DIR
    d.mkdir(parents=True, exist_ok=True)
    lines, failed = [f"bh-authz --baseline {url}: the routes the interface offers each identity (no attack)"], []
    for who in names:
        routes = browse(url, who)
        if routes is None:
            failed.append(who)
            lines.append(f"  {who}: bh-browse failed, no baseline")
            continue
        routes = [r for r in dict.fromkeys(routes) if c.origin(r) is not None][:BASELINE_ROUTES_MAX]
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", who)[:40]
        doc = {"routes": routes, "ts": round(time.time() if now is None else now, 3)}
        (d / f"{name}.json").write_text(json.dumps(doc) + "\n")
        lines.append(f"  {who}: {len(routes)} routes -> {d / name}.json")
    lines.append("the host keeps, per identity, only the routes the gate saw under it (the judge reads that copy)")
    if failed:
        lines.append(fail.line("unreachable"))
    retry = f"bh-browse {url} --as {failed[0]} alone, to see why it failed" if failed else ""
    lines.append("next: " + (retry or "bh-authz on the known endpoints"))
    return lines[:MAX_LINES]


def _route(ep: Endpoint) -> str:
    return f"{ep.method} {c.path_key(_path(ep.url))}"


def failure(rows: list[Row], owner: str) -> str | None:
    """The fail class when the owner got no usable answer on any row; None when at least one answer came back."""
    answers = [r.answers.get(owner) for r in rows]
    if not answers or any(
        x is not None and x.status > 0 and not x.denied and x.status not in (401, 429) for x in answers
    ):
        return None
    if any(x is not None and x.denied for x in answers):
        return "gate-denied"
    if any(x is not None and x.status == 429 for x in answers):
        return "rate"
    if any(x is not None and x.status == 401 for x in answers):
        return "auth"
    return "unreachable"


def run(
    eps: list[Endpoint],
    owner: str,
    others: list[str],
    *,
    with_anon: bool,
    write_own: bool,
    limit: int,
    routes_in: list[Endpoint] | None = None,
) -> dict:
    d = c.bh_dir()
    first = urlsplit(eps[0].url)
    raw = d / c.RAW / f"authz-{re.sub(r'[^A-Za-z0-9.-]+', '_', first.netloc + first.path)[:50]}-{int(time.time())}"
    raw.mkdir(parents=True, exist_ok=True)
    client = Client(raw)
    who_all = [owner, *others]
    rl = roles(who_all)
    # 1. markers, per origin, from each identity's own "me" page
    known_me = [
        str(e.get("key", "")).partition(" ")[2]
        for e in c.read_jsonl(d / c.ENDPOINTS)
        if re.search(r"/(me|whoami|profile|account)$", str(e.get("key", "")))
    ]
    marks: dict[str, set[Marker]] = {w: set() for w in who_all}
    me_path: dict[str, str] = {}
    for origin in dict.fromkeys(c.origin(e.url) for e in eps):
        sample = next(e.url for e in eps if c.origin(e.url) == origin)
        hint: list[str] = []
        for w in who_all:
            ms, path = learn(client, str(origin), sample, w, known=known_me[:3], hint=hint)
            marks[w] |= ms
            if path:
                hint, me_path[w] = [path], path
    uniq = unique_markers(marks)
    # 2. the matrix
    rows: list[Row] = []
    queue = list(eps)
    tested: set[str] = set()
    while queue and len(rows) < limit:
        ep = queue.pop(0)
        if ep.url in tested:
            continue
        tested.add(ep.url)
        ans: dict[str, Answer | None] = {w: client(ep.method, ep.url, w) for w in who_all}
        if with_anon:
            ans["anon"] = client(ep.method, ep.url, None)
        row = Row(ep, ans)
        judge(row, owner, rl, uniq)
        rows.append(row)
        o = ans.get(owner)
        if o is not None and o.ok and "{id}" not in c.path_key(urlsplit(ep.url).path) and not ep.owned:
            peers = [x for w, x in ans.items() if w != owner and x is not None and x.ok]
            base = ep.url.split("?")[0].rstrip("/")
            for iid in owned_items(o, peers, uniq.get(owner, set())):
                queue.insert(0, Endpoint(ep.method, f"{base}/{quote(iid, safe='')}", "expand", owned=True))
    # 3. writes on the owner's own objects
    writes: list[tuple[Write, Row]] = []
    if write_own and others:
        for row in rows:
            if len([w for w, _ in writes if w.method]) >= WRITE_MAX:
                break
            if (w := try_write(client, row, owner, others, uniq)) is not None:
                writes.append((w, row))
    # 4. proof, output, records
    cands = [r for r in rows if r.kind]
    proof, proof_of = None, None
    for w, row in writes:
        if (p := write_proof(w, row, owner)) is not None:
            proof, proof_of = p, f"{w.method} {c.path_key(urlsplit(row.ep.url).path)} by {w.who}"
            break
    for row in sorted(cands, key=lambda r: ("anon" in r.hits and len(r.hits) == 1, r.kind != "horizontal")):
        if proof is not None:
            break
        if (p := read_proof(row, owner)) is not None:
            proof, proof_of = p, f"GET {c.path_key(urlsplit(row.ep.url).path)}"
    proof_path = None
    if proof is not None:
        from bh.agent import proof as pf

        if problems := pf.validate(proof):
            proof_of = f"{proof_of}: proof invalid ({problems[0]})"
        else:
            proof_path = raw / "proof.json"
            c.write_json(proof_path, proof)
    summary = {
        "owner": owner,
        "others": others,
        "anon": with_anon,
        "roles": {w: [r.role, r.tenant] for w, r in rl.items()},
        "markers": {w: sorted([m.kind, m.key, m.value] for m in ms) for w, ms in uniq.items()},
        "me": me_path,
        "rows": [
            {
                "method": r.ep.method,
                "url": r.ep.url,
                "via": r.ep.via,
                "kind": r.kind,
                "note": r.note,
                "answers": {
                    w: None if x is None else [x.status, len(x.body), x.digest, x.denied] for w, x in r.answers.items()
                },
                "hits": {w: [n for _, n in h] for w, h in r.hits.items()},
            }
            for r in rows
        ],
        "writes": [w.__dict__ for w, _ in writes],
        "denied": client.denied,
        "requests": client.sent,
        "proof": str(proof_path) if proof_path else None,
    }
    klass = failure(rows, owner)
    summary["fail"] = klass
    c.write_json(raw / "summary.json", summary)
    for origin in dict.fromkeys(c.origin(r.ep.url) for r in rows):
        n = sum(1 for r in cands if c.origin(r.ep.url) == origin)
        status = f"error: {klass}" if klass else "ok"
        c.record_phase(d, str(origin), "authz", status=status, count=n, raw=str(raw))
    if not klass:  # a failed run tested nothing
        c.record_touched(d, [r.ep.url for r in rows if r.ep.method == "GET"], via="authz")
        c.record_touched(d, [w.url for w, _ in writes if w.method], via="authz", method="PATCH")
    given = list(dict.fromkeys(_route(e) for e in (routes_in or eps)))
    done = {_route(r.ep) for r in rows} if not klass else set()
    missing = [k for k in given if k not in done]
    end = [
        *([fail.line(klass)] if klass else []),
        f"{len(given)} routes in, {len(given) - len(missing)} tested, missing: "
        + (", ".join(missing[:3]) + (f" (+{len(missing) - 3})" if len(missing) > 3 else "") if missing else "none"),
        f"next: {next_step(klass, proof_path, cands, missing, owner, others)}",
    ]
    lines = report(
        rows,
        writes,
        client,
        owner=owner,
        others=others,
        with_anon=with_anon,
        uniq=uniq,
        me_path=me_path,
        proof_path=proof_path,
        proof_of=proof_of,
    )
    print("\n".join([*lines[: MAX_LINES - len(end)], *end]))
    return summary


def next_step(klass, proof_path, cands, missing, owner, others) -> str:
    """One action, the harness's words."""
    if klass:
        return {
            "gate-denied": "bh-note frontier: another route in scope",
            "rate": "bh-note frontier: another lead; this one later (the gate sets the pace)",
            "auth": f"bh-authz --owner {others[0]} (the session of {owner} is refused)"
            if others
            else "bh-note frontier",
        }.get(klass, "curl -sS --max-time 10 -o /dev/null -w '%{http_code}' on one of the routes")
    if proof_path:
        return f"read {proof_path}, then bh-note finding --class idor|broken-access-control --proof {proof_path}"
    if cands:
        return "write the proof of the first candidate by hand: the attack, and a control without the owner's marker"
    if missing:
        return "bh-authz --max 60 for the routes left out above"
    return "bh-note frontier"


def _cell(who: str, ans: Answer | None, owner_digest: str) -> str:
    if ans is None:
        return f"{who} -"
    if ans.denied:
        return f"{who} DENIED"
    same = "=" if who != "owner" and ans.ok and ans.digest == owner_digest else ""
    return f"{who} {ans.status} {ans.digest}{same}" if ans.ok else f"{who} {ans.status}"


def report(rows, writes, client, *, owner, others, with_anon, uniq, me_path, proof_path, proof_of) -> list[str]:
    """At most MAX_LINES lines: header, one line per candidate, writes, totals, proof, raw."""
    cands = [r for r in rows if r.kind]
    found = ", ".join(
        f"{w} {len(uniq.get(w, ()))}" + (f" ({me_path[w]})" if w in me_path else "") for w in [owner, *others]
    )
    head = [f"bh-authz: owner {owner} vs {', '.join(others) or '-'}{' + anon' if with_anon else ''} · markers: {found}"]
    if not uniq.get(owner):
        head.append(f'  no marker for {owner}: no "me" page found, ownership cannot be shown (give its profile URL)')
    body = []
    for r in cands:
        o = r.answers.get(owner)
        od = o.digest if o is not None else ""
        cells = " · ".join(_cell("owner" if w == owner else w, x, od) for w, x in r.answers.items())
        mk = next((m.kind for h in r.hits.values() for m, _ in h), "")
        tail = f"  marker {mk} seen: {','.join(r.hits)}" if mk else ""
        note = f" ({r.note})" if r.note else ""
        body.append(f"  {r.ep.method} {c.path_key(_path(r.ep.url))}  {cells}{tail}  [{r.kind}]{note}")
    wlines = []
    for w, _ in writes[:3]:
        path = c.path_key(_path(w.url))
        if not w.method:
            wlines.append(f"  write {path}: skipped ({w.note or 'nothing sent'})")
        elif w.effect:
            rest = "restored" if w.restored else "NOT restored: fix it as the owner"
            wlines.append(f"  WRITE {w.method} {path} by {w.who}: {w.status}, owner reads the change [{rest}]")
        else:
            extra = f" ({w.note})" if w.note else ""
            wlines.append(f"  write {w.method} {path} by {w.who}: {w.status}, no effect for the owner{extra}")
    refused = sum(1 for r in rows if any(x is not None and x.denied for x in r.answers.values()))
    sane = len(rows) - len(cands) - refused
    foot = [
        f"tested {len(rows)} endpoints: {len(cands)} candidates, {max(0, sane)} sane, {refused} refused by the gate "
        f"({client.denied} denied requests, {client.sent} sent)"
    ]
    if stopped := [w for w in client.unauth if client.stopped(w)]:
        foot.append(f"  stopped {', '.join(stopped)}: 401 on {GUARD_401} routes (the gate would mark the session dead)")
    if proof_path:
        foot.append(f"proof ({proof_of}): {proof_path}")
    elif proof_of:
        foot.append(f"proof: {proof_of}")
    elif cands:
        foot.append("proof: none built (no control without the marker): write it by hand")
    foot.append(f"raw: {client.raw}/ (exchanges.jsonl, summary.json)")
    room = MAX_LINES - 3 - len(head) - len(wlines) - len(foot)  # 3: the coverage, failure and next lines
    if len(body) > room:
        body = [*body[: max(0, room - 1)], f"  ... {len(body) - max(0, room - 1)} more candidates in summary.json"]
    return [*head, *body, *wlines, *foot][:MAX_LINES]
