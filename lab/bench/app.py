"""Larkspur Rooms: meeting-room booking for a small company. Stdlib only, one file, in-memory SQLite.

The database is rebuilt at every start from a fictional seed, so a restart is a full reset.

    python -I -B app.py --host 0.0.0.0 --port 8000
"""

# ruff: noqa: E501
# (the single-page front end is inline HTML/JS: its template lines are not wrapped)

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import json
import re
import secrets
import sqlite3
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

VERSION = "2.4.1"
MAX_BODY = 64 * 1024
TOKEN_TTL = 12 * 3600
PBKDF2_ROUNDS = 60_000
START_CREDITS = 40
SORTABLE = {"name", "floor", "capacity", "rate"}
CATALOG = {"coffee": 2, "pastries": 3, "lunch": 6, "projector": 3, "video-kit": 5}
DOMAIN = "larkspur-freight.example"

TEAMS = [(1, "Facilities"), (2, "Engineering"), (3, "Sales"), (4, "People Ops"), (5, "Finance"), (6, "Design")]
# id, email local part, display name, title, team, role
USERS = [
    (1, "ingrid.solberg", "Ingrid Solberg", "Facilities manager", 1, "admin"),
    (2, "marcus.obi", "Marcus Obi", "Engineering lead", 2, "manager"),
    (3, "priya.raman", "Priya Raman", "Backend engineer", 2, "member"),
    (4, "tomas.ferreira", "Tomás Ferreira", "Account executive", 3, "member"),
    (5, "hanna.kowalczyk", "Hanna Kowalczyk", "Head of People", 4, "manager"),
    (6, "daniel.weiss", "Daniel Weiss", "Controller", 5, "member"),
    (7, "aiko.tanaka", "Aiko Tanaka", "Product designer", 6, "member"),
    (8, "liam.oconnor", "Liam O'Connor", "Sales manager", 3, "manager"),
]
# id, name, floor, capacity, rate (credits per hour), features
ROOMS = [
    (1, "Fjord", 1, 4, 2, "screen"),
    (2, "Harbour", 1, 10, 5, "screen, video"),
    (3, "Lantern", 2, 6, 3, "whiteboard"),
    (4, "Quay", 2, 2, 1, "phone booth"),
    (5, "Beacon", 3, 16, 8, "screen, video, stage"),
    (6, "Tideline", 3, 8, 4, "whiteboard, screen"),
]
# owner, room, day offset, hour, hours, title, notes, private
BOOKINGS = [
    (2, 3, 1, 9, 1, "Sprint planning", "Board: Q1 carrier integrations", 0),
    (5, 4, 1, 11, 1, "Interview, senior backend", "Offer band 68-74k, references pending; decision Friday", 1),
    (4, 2, 1, 14, 2, "Customer call: Nordhavn Cargo", "Renewal at risk, discount up to 12% approved", 0),
    (6, 1, 2, 10, 1, "Budget review", "Headcount freeze for Sales until March, not announced yet", 1),
    (7, 6, 2, 13, 2, "Design critique", "Tracking page v3", 0),
    (2, 4, 2, 16, 1, "1:1 Marcus / Priya", "Promotion case: draft feedback in the shared folder", 1),
    (8, 5, 3, 9, 3, "Sales kickoff", "Agenda in the team channel", 0),
    (5, 3, 3, 15, 1, "Exit interview", "Resignation of a Finance employee, keep confidential", 1),
    (1, 5, 4, 8, 1, "Fire drill briefing", "Floor wardens only", 0),
    (3, 1, 4, 11, 1, "Pairing session", "Rate-limit middleware", 0),
]
RUN_STARTED = time.time()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${_b64(salt)}${_b64(digest)}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, rounds, salt, digest = stored.split("$")
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), _unb64(salt), int(rounds))
    except ValueError:
        return False
    return hmac.compare_digest(got, _unb64(digest))


class HttpError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class App:
    """State and handlers of one instance. Every handler runs under `lock` (one SQLite connection)."""

    def __init__(self, secret: bytes | None = None, now: datetime | None = None) -> None:
        self.secret = secret or secrets.token_bytes(32)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._schema()
        self._seed(now or datetime.now(UTC))

    # ------------------------------------------------------------------ data
    def _schema(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE teams (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE users (
                id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
                display_name TEXT NOT NULL, title TEXT, team_id INTEGER, role TEXT NOT NULL DEFAULT 'member',
                credits INTEGER NOT NULL, api_token TEXT, created TEXT NOT NULL);
            CREATE TABLE rooms (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, floor INTEGER NOT NULL, capacity INTEGER NOT NULL,
                rate INTEGER NOT NULL, features TEXT NOT NULL);
            CREATE TABLE bookings (
                ref TEXT PRIMARY KEY, room_id INTEGER NOT NULL, owner_id INTEGER NOT NULL, start TEXT NOT NULL,
                end TEXT NOT NULL, title TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '', private INTEGER NOT NULL,
                extras TEXT NOT NULL DEFAULT '[]', cost INTEGER NOT NULL, created TEXT NOT NULL);
            CREATE TABLE outbox (id INTEGER PRIMARY KEY, recipient TEXT NOT NULL, subject TEXT NOT NULL,
                queued TEXT NOT NULL);
            CREATE TABLE access_requests (id INTEGER PRIMARY KEY, team_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL, created TEXT NOT NULL);
            """
        )

    def _seed(self, now: datetime) -> None:
        stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.db.executemany("INSERT INTO teams VALUES (?, ?)", TEAMS)
        for uid, local, name, title, team, role in USERS:
            token = "lkf_" + secrets.token_hex(16) if role == "admin" else None
            self.db.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (uid, f"{local}@{DOMAIN}", hash_password(secrets.token_urlsafe(18)), name, title, team, role,
                 START_CREDITS, token, stamp),
            )  # fmt: skip
        self.db.executemany("INSERT INTO rooms VALUES (?, ?, ?, ?, ?, ?)", ROOMS)
        day0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
        for owner, room, offset, hour, hours, title, notes, private in BOOKINGS:
            start = day0 + timedelta(days=offset, hours=hour)
            rate = ROOMS[room - 1][4]
            self._insert_booking(
                owner,
                room,
                start,
                hours,
                title=title,
                notes=notes,
                private=bool(private),
                extras=[],
                cost=rate * hours,
                stamp=stamp,
            )
        self.db.commit()

    def _insert_booking(self, owner, room, start, hours, *, title, notes, private, extras, cost, stamp) -> str:
        ref = "bk_" + secrets.token_hex(6)
        end = start + timedelta(hours=hours)
        self.db.execute(
            "INSERT INTO bookings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ref, room, owner, _fmt(start), _fmt(end), title, notes, int(private), json.dumps(extras), cost, stamp),
        )
        email, = self.db.execute("SELECT email FROM users WHERE id=?", (owner,)).fetchone()  # fmt: skip
        room_name = ROOMS[room - 1][1] if room <= len(ROOMS) else str(room)
        self._mail(email, f"Booking confirmed: {room_name}, {_fmt(start).replace('T', ' ')}", stamp)
        return ref

    def _mail(self, recipient: str, subject: str, stamp: str) -> None:
        self.db.execute("INSERT INTO outbox (recipient, subject, queued) VALUES (?, ?, ?)", (recipient, subject, stamp))

    # ------------------------------------------------------------------ sessions
    def issue(self, user_id: int) -> tuple[str, int]:
        exp = int(time.time()) + TOKEN_TTL
        body = _b64(json.dumps({"sub": user_id, "exp": exp}, separators=(",", ":")).encode())
        sig = _b64(hmac.new(self.secret, b"v1." + body.encode(), hashlib.sha256).digest())
        return f"v1.{body}.{sig}", exp

    def verify(self, token: str) -> int | None:
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != "v1":
            return None
        want = _b64(hmac.new(self.secret, b"v1." + parts[1].encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(want, parts[2]):
            return None
        try:
            claims = json.loads(_unb64(parts[1]))
        except ValueError:
            return None
        if not isinstance(claims, dict) or not isinstance(claims.get("sub"), int):
            return None
        if not isinstance(claims.get("exp"), int) or claims["exp"] < time.time():
            return None
        return claims["sub"]

    def user(self, user_id: int | None) -> sqlite3.Row | None:
        if user_id is None:
            return None
        return self.db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    # ------------------------------------------------------------------ views
    @staticmethod
    def me_view(u: sqlite3.Row) -> dict:
        return {
            "id": u["id"],
            "email": u["email"],
            "display_name": u["display_name"],
            "title": u["title"],
            "team_id": u["team_id"],
            "role": u["role"],
            "credits": u["credits"],
        }

    def booking_view(self, b: sqlite3.Row) -> dict:
        room = self.db.execute("SELECT id, name FROM rooms WHERE id=?", (b["room_id"],)).fetchone()
        owner = self.db.execute("SELECT id, display_name FROM users WHERE id=?", (b["owner_id"],)).fetchone()
        return {
            "ref": b["ref"],
            "room": {"id": room["id"], "name": room["name"]},
            "organizer": {"id": owner["id"], "display_name": owner["display_name"]},
            "start": b["start"],
            "end": b["end"],
            "title": b["title"],
            "notes": b["notes"],
            "private": bool(b["private"]),
            "extras": json.loads(b["extras"]),
            "cost": b["cost"],
        }

    @staticmethod
    def room_view(r: sqlite3.Row) -> dict:
        return {k: r[k] for k in ("id", "name", "floor", "capacity", "rate", "features")}

    # ------------------------------------------------------------------ handlers: auth and account
    def signup(self, req: Request) -> tuple[int, dict]:
        body = req.json()
        email = str(body.get("email", "")).strip().lower()
        password = body.get("password")
        name = str(body.get("name") or email.split("@")[0]).strip()[:60]
        if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,190}\.[a-z]{2,24}", email):
            raise HttpError(400, "a valid email is required")
        if not isinstance(password, str) or len(password) < 8:
            raise HttpError(400, "password must have at least 8 characters")
        if self.db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            raise HttpError(409, "an account already exists for this email")
        stamp = _now()
        cur = self.db.execute(
            "INSERT INTO users (email, password, display_name, title, team_id, role, credits, created) "
            "VALUES (?, ?, ?, NULL, NULL, 'member', ?, ?)",
            (email, hash_password(password), name or "New member", START_CREDITS, stamp),
        )
        self._mail(email, "Welcome to Larkspur Rooms", stamp)
        self.db.commit()
        return 201, {"user": self.me_view(self.user(cur.lastrowid))}

    def login(self, req: Request) -> tuple[int, dict]:
        body = req.json()
        email = str(body.get("email", "")).strip().lower()
        password = body.get("password")
        u = self.db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u is None or not isinstance(password, str) or not check_password(password, u["password"]):
            raise HttpError(401, "invalid email or password")
        token, exp = self.issue(u["id"])
        req.set_cookie = f"sid={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={TOKEN_TTL}"
        return 200, {"session": {"token": token, "expires": exp}, "user": self.me_view(u)}

    def logout(self, req: Request) -> tuple[int, dict]:
        req.set_cookie = "sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        return 200, {"ok": True}

    def get_me(self, req: Request) -> tuple[int, dict]:
        return 200, self.me_view(req.need_user())

    def patch_me(self, req: Request) -> tuple[int, dict]:
        u = req.need_user()
        body = req.json()
        if "display_name" in body:
            name = str(body["display_name"]).strip()
            if not 1 <= len(name) <= 80:
                raise HttpError(400, "display_name must have 1 to 80 characters")
            self.db.execute("UPDATE users SET display_name=? WHERE id=?", (name, u["id"]))
            self.db.commit()
        return 200, self.me_view(self.user(u["id"]))

    # ------------------------------------------------------------------ handlers: rooms
    def list_rooms(self, req: Request) -> tuple[int, dict]:
        floor = req.arg("floor")
        if floor is not None and not floor.isdigit():
            raise HttpError(400, "floor must be a number")
        sort = req.arg("sort") or "name"
        direction = "DESC" if sort.startswith("-") else "ASC"
        column = sort.lstrip("-")
        head = re.match(r"[a-z_]+", column)
        if not head or head.group(0) not in SORTABLE:
            raise HttpError(400, f"cannot sort by {head.group(0) if head else column!r}")
        sql = f"SELECT * FROM rooms WHERE (? IS NULL OR floor = ?) ORDER BY {column} {direction}, id"
        try:
            rows = self.db.execute(sql, (floor, floor)).fetchall()
        except sqlite3.Error:
            raise HttpError(400, "invalid query") from None
        return 200, {"rooms": [self.room_view(r) for r in rows]}

    def get_room(self, req: Request, room_id: str) -> tuple[int, dict]:
        return 200, self.room_view(self._room(room_id))

    def room_schedule(self, req: Request, room_id: str) -> tuple[int, dict]:
        room = self._room(room_id)
        today = datetime.now(UTC).strftime("%Y-%m-%dT00:00")
        rows = self.db.execute(
            "SELECT b.ref, b.start, b.end, b.title, b.private, u.display_name FROM bookings b "
            "JOIN users u ON u.id = b.owner_id WHERE b.room_id=? AND b.end >= ? ORDER BY b.start",
            (room["id"], today),
        ).fetchall()
        slots = [
            {
                "ref": r["ref"],
                "start": r["start"],
                "end": r["end"],
                "title": "Busy" if r["private"] else r["title"],
                "private": bool(r["private"]),
                "organizer": r["display_name"],
            }
            for r in rows
        ]
        return 200, {"room": self.room_view(room), "slots": slots}

    def _room(self, room_id: str) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM rooms WHERE id=?", (int(room_id),)).fetchone()
        if row is None:
            raise HttpError(404, "no such room")
        return row

    def catalog(self, req: Request) -> tuple[int, dict]:
        return 200, {"extras": [{"item": k, "price": v} for k, v in CATALOG.items()]}

    # ------------------------------------------------------------------ handlers: bookings
    def my_bookings(self, req: Request) -> tuple[int, dict]:
        u = req.need_user()
        rows = self.db.execute("SELECT * FROM bookings WHERE owner_id=? ORDER BY start", (u["id"],)).fetchall()
        return 200, {"bookings": [self.booking_view(r) for r in rows]}

    def create_booking(self, req: Request) -> tuple[int, dict]:
        u = req.need_user()
        body = req.json()
        room_id = body.get("room_id")
        if not isinstance(room_id, int) or isinstance(room_id, bool):
            raise HttpError(400, "room_id must be an integer")
        room = self._room(str(room_id))
        start_s = str(body.get("start", ""))
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:(00|30)", start_s):
            raise HttpError(400, "start must look like 2026-01-31T09:30")
        try:
            start = datetime.strptime(start_s, "%Y-%m-%dT%H:%M").replace(tzinfo=UTC)
        except ValueError:
            raise HttpError(400, "start is not a valid date") from None
        hours = body.get("hours", 1)
        if not isinstance(hours, int) or isinstance(hours, bool) or not 1 <= hours <= 8:
            raise HttpError(400, "hours must be an integer from 1 to 8")
        if start.hour < 7 or start.hour + hours > 20:
            raise HttpError(400, "rooms can be booked from 07:00 to 20:00")
        title = str(body.get("title", "")).strip()[:120]
        if not title:
            raise HttpError(400, "title is required")
        notes = str(body.get("notes", ""))[:2000]
        private = bool(body.get("private", False))
        extras_in = body.get("extras", [])
        if not isinstance(extras_in, list) or len(extras_in) > 10:
            raise HttpError(400, "extras must be a list")
        extras, extras_cost = [], 0
        for e in extras_in:
            if not isinstance(e, dict) or e.get("item") not in CATALOG:
                raise HttpError(400, f"unknown extra; see {req.base}/api/v1/catalog")
            qty = e.get("qty", 1)
            if not isinstance(qty, int) or isinstance(qty, bool) or qty > 50:
                raise HttpError(400, "qty must be an integer up to 50")
            if qty:
                extras.append({"item": e["item"], "qty": qty})
                extras_cost += CATALOG[e["item"]] * qty
        end = start + timedelta(hours=hours)
        clash = self.db.execute(
            "SELECT 1 FROM bookings WHERE room_id=? AND start < ? AND end > ?", (room["id"], _fmt(end), _fmt(start))
        ).fetchone()
        if clash:
            raise HttpError(409, "the room is already booked at that time")
        cost = room["rate"] * hours + extras_cost
        if cost > u["credits"]:
            raise HttpError(402, f"not enough credits ({u['credits']} left, {cost} needed)")
        ref = self._insert_booking(
            u["id"],
            room["id"],
            start,
            hours,
            title=title,
            notes=notes,
            private=private,
            extras=extras,
            cost=cost,
            stamp=_now(),
        )
        self.db.execute("UPDATE users SET credits = credits - ? WHERE id=?", (cost, u["id"]))
        self.db.commit()
        out = self.booking_view(self._booking(ref))
        out["credits_left"] = self.user(u["id"])["credits"]
        return 201, out

    def get_booking(self, req: Request, ref: str) -> tuple[int, dict]:
        req.need_user()
        return 200, self.booking_view(self._booking(ref))

    def patch_booking(self, req: Request, ref: str) -> tuple[int, dict]:
        req.need_user()
        b = self._booking(ref)
        body = req.json()
        fields = {}
        if "title" in body:
            fields["title"] = str(body["title"]).strip()[:120] or b["title"]
        if "notes" in body:
            fields["notes"] = str(body["notes"])[:2000]
        if "private" in body:
            fields["private"] = int(bool(body["private"]))
        for key, value in fields.items():
            self.db.execute(f"UPDATE bookings SET {key}=? WHERE ref=?", (value, ref))
        self.db.commit()
        return 200, self.booking_view(self._booking(ref))

    def delete_booking(self, req: Request, ref: str) -> tuple[int, dict]:
        u = req.need_user()
        b = self._booking(ref)
        if b["owner_id"] != u["id"] and u["role"] != "admin":
            raise HttpError(403, "only the organizer can cancel this booking")
        self.db.execute("DELETE FROM bookings WHERE ref=?", (ref,))
        self.db.execute("UPDATE users SET credits = credits + ? WHERE id=?", (b["cost"], b["owner_id"]))
        self.db.commit()
        return 200, {"ok": True, "refunded": b["cost"]}

    def _booking(self, ref: str) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM bookings WHERE ref=?", (ref,)).fetchone()
        if row is None:
            raise HttpError(404, "no such booking")
        return row

    # ------------------------------------------------------------------ handlers: people and teams
    @staticmethod
    def profile_view(r: sqlite3.Row) -> dict:
        return {"id": r["id"], "display_name": r["display_name"], "title": r["title"], "team": r["team"]}

    def list_profiles(self, req: Request) -> tuple[int, dict]:
        req.need_user()
        rows = self.db.execute(
            "SELECT u.id, u.display_name, u.title, t.name AS team FROM users u LEFT JOIN teams t ON t.id=u.team_id "
            "ORDER BY u.id"
        ).fetchall()
        return 200, {"people": [self.profile_view(r) for r in rows]}

    def get_profile(self, req: Request, user_id: str) -> tuple[int, dict]:
        req.need_user()
        row = self.db.execute(
            "SELECT u.id, u.display_name, u.title, t.name AS team FROM users u LEFT JOIN teams t ON t.id=u.team_id "
            "WHERE u.id=?",
            (int(user_id),),
        ).fetchone()
        if row is None:
            raise HttpError(404, "no such person")
        return 200, self.profile_view(row)

    def list_teams(self, req: Request) -> tuple[int, dict]:
        rows = self.db.execute(
            "SELECT t.id, t.name, count(u.id) AS size FROM teams t LEFT JOIN users u ON u.team_id=t.id "
            "GROUP BY t.id ORDER BY t.id"
        ).fetchall()
        return 200, {"teams": [dict(r) for r in rows]}

    def team_members(self, req: Request, team_id: str) -> tuple[int, dict]:
        u = req.need_user()
        team = self._team(team_id)
        if u["team_id"] != team["id"] and u["role"] != "admin":
            raise HttpError(403, "you are not a member of this team")
        rows = self.db.execute(
            "SELECT id, email, display_name, title, role FROM users WHERE team_id=? ORDER BY id", (team["id"],)
        ).fetchall()
        return 200, {"team": dict(team), "members": [dict(r) for r in rows]}

    def request_access(self, req: Request, team_id: str) -> tuple[int, dict]:
        u = req.need_user()
        team = self._team(team_id)
        self.db.execute(
            "INSERT INTO access_requests (team_id, user_id, created) VALUES (?, ?, ?)", (team["id"], u["id"], _now())
        )
        self.db.commit()
        return 202, {"status": "pending", "team": team["name"]}

    def _team(self, team_id: str) -> sqlite3.Row:
        row = self.db.execute("SELECT id, name FROM teams WHERE id=?", (int(team_id),)).fetchone()
        if row is None:
            raise HttpError(404, "no such team")
        return row

    # ------------------------------------------------------------------ handlers: service
    def status(self, req: Request) -> tuple[int, dict]:
        out = {"service": "larkspur-rooms", "version": VERSION, "uptime_s": int(time.time() - RUN_STARTED)}
        if req.arg("detail") == "full":
            count = {t: self.db.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in ("users", "bookings")}
            queue = self.db.execute("SELECT recipient, subject, queued FROM outbox ORDER BY id DESC LIMIT 25")
            out["db"] = {"engine": "sqlite " + sqlite3.sqlite_version, **count}
            out["mailer"] = {"transport": "smtp-relay (paused)", "queue": [dict(r) for r in queue.fetchall()]}
        return 200, out


# ---------------------------------------------------------------------- routing
ROUTES: list[tuple[str, str, str]] = [
    ("POST", r"/api/v1/auth/signup", "signup"),
    ("POST", r"/api/v1/auth/login", "login"),
    ("POST", r"/api/v1/auth/logout", "logout"),
    ("GET", r"/api/v1/me", "get_me"),
    ("PATCH", r"/api/v1/me", "patch_me"),
    ("GET", r"/api/v1/rooms", "list_rooms"),
    ("GET", r"/api/v1/rooms/(\d{1,9})", "get_room"),
    ("GET", r"/api/v1/rooms/(\d{1,9})/schedule", "room_schedule"),
    ("GET", r"/api/v1/catalog", "catalog"),
    ("GET", r"/api/v1/bookings", "my_bookings"),
    ("POST", r"/api/v1/bookings", "create_booking"),
    ("GET", r"/api/v1/bookings/(bk_[0-9a-f]{12})", "get_booking"),
    ("PATCH", r"/api/v1/bookings/(bk_[0-9a-f]{12})", "patch_booking"),
    ("DELETE", r"/api/v1/bookings/(bk_[0-9a-f]{12})", "delete_booking"),
    ("GET", r"/api/v1/profiles", "list_profiles"),
    ("GET", r"/api/v1/profiles/(\d{1,9})", "get_profile"),
    ("GET", r"/api/v1/teams", "list_teams"),
    ("GET", r"/api/v1/teams/(\d{1,9})/members", "team_members"),
    ("POST", r"/api/v1/teams/(\d{1,9})/requests", "request_access"),
    ("GET", r"/api/v1/status", "status"),
]
_COMPILED = [(m, re.compile(p), h) for m, p, h in ROUTES]
PAGES = ("/", "/index.html", "/help")


def resolve(method: str, path: str) -> tuple[str | None, tuple[str, ...], bool]:
    """(handler, args, path_known) for one request."""
    known = False
    for m, rx, handler in _COMPILED:
        hit = rx.fullmatch(path)
        if hit:
            known = True
            if m == method:
                return handler, hit.groups(), True
    return None, (), known


class Request:
    def __init__(self, handler: Handler, app: App) -> None:
        self.h = handler
        self.app = app
        split = urlsplit(handler.path)
        self.path = split.path.rstrip("/") or "/"
        self.query = parse_qs(split.query)
        self.set_cookie: str | None = None
        self.base = ""
        self._body: dict | None = None
        self.too_large = False
        declared = handler.headers.get("Content-Length") or "0"
        length = int(declared) if declared.isdigit() else 0
        if length > MAX_BODY:
            self.too_large, self.raw = True, b""
        else:  # always drained: a keep-alive connection must not read a leftover body as the next request
            self.raw = handler.rfile.read(length) if length else b""

    def arg(self, name: str) -> str | None:
        values = self.query.get(name)
        return values[0] if values else None

    def token(self) -> str | None:
        auth = self.h.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        for part in self.h.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "sid" and value:
                return value
        return None

    def need_user(self) -> sqlite3.Row:
        tok = self.token()
        u = self.app.user(self.app.verify(tok)) if tok else None
        if u is None:
            raise HttpError(401, "authentication required")
        return u

    def json(self) -> dict:
        if self._body is None:
            try:
                body = json.loads(self.raw or b"{}")
            except ValueError:
                raise HttpError(400, "body must be JSON") from None
            if not isinstance(body, dict):
                raise HttpError(400, "body must be a JSON object")
            self._body = body
        return self._body


class Handler(BaseHTTPRequestHandler):
    server_version = "larkspur-rooms/" + VERSION
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        if not getattr(self.server, "quiet", False):
            sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    def _send(self, status: int, body: bytes, ctype: str, cookie: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, doc: dict, cookie: str | None = None) -> None:
        self._send(status, json.dumps(doc).encode(), "application/json; charset=utf-8", cookie)

    def _dispatch(self) -> None:
        req = Request(self, self.app)
        if req.too_large:
            self.close_connection = True
            self._json(413, {"error": "body too large"})
            return
        req.base = f"http://{self.headers.get('Host', 'localhost')}"
        if self.command in ("GET", "HEAD") and req.path in PAGES:
            page = help_page(req.arg("topic")) if req.path == "/help" else SPA
            self._send(200, page.encode(), "text/html; charset=utf-8")
            return
        name, args, known = resolve(self.command, req.path)
        if name is None:
            if known:
                self._json(405, {"error": "method not allowed"})
            else:
                self._json(404, {"error": "not found"})
            return
        try:
            with self.app.lock:
                status, doc = getattr(self.app, name)(req, *args)
        except HttpError as exc:
            self._json(exc.status, {"error": exc.message})
            return
        except Exception as exc:  # noqa: BLE001 - one bad request must not kill the lab
            sys.stderr.write(f"error on {self.command} {req.path}: {type(exc).__name__}\n")
            self._json(500, {"error": "internal error"})
            return
        self._json(status, doc, req.set_cookie)

    do_GET = do_POST = do_PATCH = do_DELETE = do_PUT = do_HEAD = _dispatch

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Allow", "GET, POST, PATCH, DELETE")
        self.send_header("Content-Length", "0")
        self.end_headers()


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M")


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------- pages
HELP = {
    "booking": "Pick a room, a start time on the hour or half hour, and a duration of 1 to 8 hours.",
    "credits": f"Everyone starts the month with {START_CREDITS} credits. A room costs its hourly rate; "
    "catering and equipment are charged on top. Cancelling refunds the booking.",
    "privacy": "A private booking shows as Busy on the room screen. Only the organizer can cancel it.",
}


def help_page(topic: str | None) -> str:
    topic = (topic or "booking").strip()
    text = HELP.get(topic)
    body = (
        f"<h1>{html.escape(topic.capitalize())}</h1><p>{html.escape(text)}</p>"
        if text
        else f"<h1>Help</h1><p>No article matches &ldquo;{html.escape(topic)}&rdquo;.</p>"
    )
    links = " · ".join(f'<a href="/help?topic={k}">{k}</a>' for k in HELP)
    return (
        "<!doctype html><html><head><meta charset=utf-8><title>Help: "
        + html.escape(topic)
        + f'</title></head><body>{body}<p>{links} · <a href="/#/rooms">back to rooms</a></p></body></html>'
    )


SPA = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Larkspur Rooms</title>
<style>
body{font:15px/1.45 system-ui,sans-serif;margin:0;color:#1d2731;background:#f6f7f9}
header{display:flex;gap:16px;align-items:center;padding:10px 20px;background:#21405e;color:#fff}
header a{color:#fff;text-decoration:none}header .sp{flex:1}
main{max-width:860px;margin:20px auto;padding:0 16px}
table{border-collapse:collapse;width:100%;background:#fff}td,th{padding:6px 8px;border-bottom:1px solid #e3e6ea;text-align:left}
.card{background:#fff;padding:14px 16px;border:1px solid #e3e6ea;border-radius:6px;margin:12px 0}
.muted{color:#6b7783}.err{color:#a3261d}label{display:block;margin:6px 0}
input,select,textarea{font:inherit;padding:4px 6px}footer{text-align:center;color:#6b7783;margin:30px 0;font-size:13px}
</style></head><body>
<header><a href="#/rooms"><b>Larkspur Rooms</b></a><a href="#/bookings">My bookings</a><a href="#/people">People</a>
<a href="#/teams">Teams</a><span class="sp"></span><span id="who"></span></header>
<main id="view"></main>
<footer><span id="ver"></span> · <a href="/help?topic=booking">Help</a></footer>
<script>
const view = () => document.getElementById('view');
const store = {
  get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
  set(k, v) { try { v === null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch (e) {} },
};
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
async function api(method, path, body) {
  const headers = {'Accept': 'application/json'};
  const tok = store.get('rt');
  if (tok) headers['Authorization'] = 'Bearer ' + tok;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch('/api/v1' + path, {method, headers, credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body)});
  let data = null;
  try { data = await r.json(); } catch (e) {}
  return {status: r.status, data};
}
let me = null;
async function whoami() {
  const r = await api('GET', '/me');
  me = r.status === 200 ? r.data : null;
  document.getElementById('who').innerHTML = me
    ? `${esc(me.display_name)} · ${esc(me.credits)} cr · <a href="#/account">Account</a> · <a href="#" id="out">Sign out</a>`
    : '<a href="#/login">Sign in</a>';
  const out = document.getElementById('out');
  if (out) out.onclick = async e => { e.preventDefault(); await api('POST', '/auth/logout'); store.set('rt', null); go('/login'); };
}
function go(p) { location.hash = '#' + p; }
function fail(r) { return `<p class="err">${esc((r.data && r.data.error) || ('HTTP ' + r.status))}</p>`; }
function when(s) { return esc(String(s).replace('T', ' ')); }

const pages = {
  async login() {
    view().innerHTML = `<div class="card"><h2>Sign in</h2><form id="f">
      <label>Email <input name="email" type="email" required></label>
      <label>Password <input name="password" type="password" required></label>
      <button>Sign in</button> <a href="#/signup">Create an account</a><div id="msg"></div></form></div>`;
    document.getElementById('f').onsubmit = async e => {
      e.preventDefault();
      const f = new FormData(e.target);
      const r = await api('POST', '/auth/login', {email: f.get('email'), password: f.get('password')});
      if (r.status !== 200) { document.getElementById('msg').innerHTML = fail(r); return; }
      store.set('rt', r.data.session.token); await whoami(); go('/rooms');
    };
  },
  async signup() {
    view().innerHTML = `<div class="card"><h2>Create an account</h2><form id="f">
      <label>Name <input name="name" required></label>
      <label>Work email <input name="email" type="email" required></label>
      <label>Password <input name="password" type="password" minlength="8" required></label>
      <button>Create</button><div id="msg"></div></form></div>`;
    document.getElementById('f').onsubmit = async e => {
      e.preventDefault();
      const f = new FormData(e.target);
      const r = await api('POST', '/auth/signup', {name: f.get('name'), email: f.get('email'), password: f.get('password')});
      if (r.status !== 201) { document.getElementById('msg').innerHTML = fail(r); return; }
      go('/login');
    };
  },
  async rooms(q) {
    const floor = q.get('floor') || '', sort = q.get('sort') || 'name';
    const r = await api('GET', '/rooms?' + new URLSearchParams(floor ? {floor, sort} : {sort}));
    if (r.status !== 200) { view().innerHTML = fail(r); return; }
    const opt = (v, t, cur) => `<option value="${v}"${v === cur ? ' selected' : ''}>${t}</option>`;
    view().innerHTML = `<h2>Rooms</h2><p>Floor <select id="fl">${opt('', 'all', floor)}${opt('1', '1', floor)}${opt('2', '2', floor)}${opt('3', '3', floor)}</select>
      Sort <select id="so">${opt('name', 'name', sort)}${opt('capacity', 'capacity', sort)}${opt('-capacity', 'capacity, largest first', sort)}${opt('rate', 'rate', sort)}</select></p>
      <table><tr><th>Room</th><th>Floor</th><th>Seats</th><th>Credits/h</th><th>Equipment</th></tr>
      ${r.data.rooms.map(x => `<tr><td><a href="#/rooms/${x.id}">${esc(x.name)}</a></td><td>${esc(x.floor)}</td><td>${esc(x.capacity)}</td><td>${esc(x.rate)}</td><td>${esc(x.features)}</td></tr>`).join('')}</table>`;
    const upd = () => go('/rooms?' + new URLSearchParams({floor: document.getElementById('fl').value, sort: document.getElementById('so').value}));
    document.getElementById('fl').onchange = upd; document.getElementById('so').onchange = upd;
  },
  async room(q, id) {
    const [r, c] = await Promise.all([api('GET', `/rooms/${encodeURIComponent(id)}/schedule`), api('GET', '/catalog')]);
    if (r.status !== 200) { view().innerHTML = fail(r); return; }
    const slots = r.data.slots.map(s => `<li>${when(s.start)} to ${when(s.end.slice(11))} · ${s.private ? '<i>Busy</i>' : esc(s.title)}
      <span class="muted">· booked by ${s.organizer}</span>${me && s.organizer === me.display_name ? ` <a href="#/bookings/${esc(s.ref)}">open</a>` : ''}</li>`).join('');
    const extras = (c.data ? c.data.extras : []).map(x => `<label>${esc(x.item)} (${esc(x.price)} cr) <input type="number" min="0" max="50" value="0" data-item="${esc(x.item)}"></label>`).join('');
    view().innerHTML = `<h2>${esc(r.data.room.name)}</h2><p class="muted">Floor ${esc(r.data.room.floor)} · ${esc(r.data.room.capacity)} seats · ${esc(r.data.room.rate)} credits per hour</p>
      <div class="card"><h3>Upcoming</h3><ul>${slots || '<li class="muted">Nothing booked.</li>'}</ul></div>
      ${me ? `<div class="card"><h3>Book</h3><form id="f">
        <label>Title <input name="title" required></label><label>Start <input name="start" type="datetime-local" step="1800" required></label>
        <label>Hours <input name="hours" type="number" min="1" max="8" value="1"></label>
        <label>Notes <textarea name="notes" rows="2"></textarea></label><label><input name="private" type="checkbox"> Private</label>
        <fieldset><legend>Extras</legend>${extras}</fieldset><button>Book</button><div id="msg"></div></form></div>`
        : '<p><a href="#/login">Sign in</a> to book this room.</p>'}`;
    const f = document.getElementById('f');
    if (f) f.onsubmit = async e => {
      e.preventDefault();
      const d = new FormData(f);
      const ex = [...f.querySelectorAll('[data-item]')].map(i => ({item: i.dataset.item, qty: parseInt(i.value || '0', 10)})).filter(x => x.qty);
      const b = await api('POST', '/bookings', {room_id: Number(id), title: d.get('title'), start: d.get('start'),
        hours: parseInt(d.get('hours'), 10), notes: d.get('notes'), private: !!d.get('private'), extras: ex});
      if (b.status !== 201) { document.getElementById('msg').innerHTML = fail(b); return; }
      await whoami(); go('/bookings/' + b.data.ref);
    };
  },
  async bookings() {
    const r = await api('GET', '/bookings');
    if (r.status !== 200) { view().innerHTML = fail(r); return; }
    view().innerHTML = `<h2>My bookings</h2><table><tr><th>When</th><th>Room</th><th>Title</th><th>Cost</th></tr>
      ${r.data.bookings.map(b => `<tr><td>${when(b.start)}</td><td>${esc(b.room.name)}</td><td><a href="#/bookings/${esc(b.ref)}">${esc(b.title)}</a></td><td>${esc(b.cost)}</td></tr>`).join('')}</table>`;
  },
  async booking(q, ref) {
    const r = await api('GET', '/bookings/' + encodeURIComponent(ref));
    if (r.status !== 200) { view().innerHTML = fail(r); return; }
    const b = r.data;
    view().innerHTML = `<div class="card"><h2>${esc(b.title)}</h2><p>${esc(b.room.name)} · ${when(b.start)} to ${when(b.end.slice(11))}</p>
      <p class="muted">Organizer: ${esc(b.organizer.display_name)} · cost ${esc(b.cost)} credits</p><form id="f">
      <label>Title <input name="title" value="${esc(b.title)}"></label><label>Notes <textarea name="notes" rows="3">${esc(b.notes)}</textarea></label>
      <label><input name="private" type="checkbox"${b.private ? ' checked' : ''}> Private</label>
      <button>Save</button> <button type="button" id="del">Cancel booking</button><div id="msg"></div></form></div>`;
    const f = document.getElementById('f');
    f.onsubmit = async e => {
      e.preventDefault();
      const d = new FormData(f);
      const u = await api('PATCH', '/bookings/' + encodeURIComponent(ref), {title: d.get('title'), notes: d.get('notes'), private: !!d.get('private')});
      document.getElementById('msg').innerHTML = u.status === 200 ? '<p>Saved.</p>' : fail(u);
    };
    document.getElementById('del').onclick = async () => {
      const u = await api('DELETE', '/bookings/' + encodeURIComponent(ref));
      if (u.status !== 200) { document.getElementById('msg').innerHTML = fail(u); return; }
      await whoami(); go('/bookings');
    };
  },
  async people() {
    const r = await api('GET', '/profiles');
    if (r.status !== 200) { view().innerHTML = fail(r); return; }
    view().innerHTML = `<h2>People</h2><table><tr><th>Name</th><th>Title</th><th>Team</th></tr>
      ${r.data.people.map(p => `<tr><td>${esc(p.display_name)}</td><td>${esc(p.title || '')}</td><td>${esc(p.team || '')}</td></tr>`).join('')}</table>`;
  },
  async teams() {
    const r = await api('GET', '/teams');
    if (r.status !== 200) { view().innerHTML = fail(r); return; }
    view().innerHTML = `<h2>Teams</h2><ul>${r.data.teams.map(t => `<li><a href="#/teams/${t.id}">${esc(t.name)}</a> <span class="muted">${esc(t.size)} people</span></li>`).join('')}</ul>`;
  },
  async team(q, id) {
    const r = await api('GET', `/teams/${encodeURIComponent(id)}/members`);
    if (r.status === 403) {
      view().innerHTML = `<div class="card"><p>You are not a member of this team.</p><button id="ask">Request access</button><div id="msg"></div></div>`;
      document.getElementById('ask').onclick = async () => {
        const a = await api('POST', `/teams/${encodeURIComponent(id)}/requests`);
        document.getElementById('msg').innerHTML = a.status === 202 ? '<p>Request sent to the team lead.</p>' : fail(a);
      };
      return;
    }
    if (r.status !== 200) { view().innerHTML = fail(r); return; }
    const link = location.origin + '/#/join?' + new URLSearchParams({team: r.data.team.id, name: r.data.team.name, by: me ? me.display_name : ''});
    view().innerHTML = `<h2>${esc(r.data.team.name)}</h2><table>${r.data.members.map(m => `<tr><td>${esc(m.display_name)}</td><td>${esc(m.email)}</td><td>${esc(m.role)}</td></tr>`).join('')}</table>
      <div class="card">Invite link: <input readonly size="60" value="${esc(link)}"></div>`;
  },
  async join(q) {
    const team = q.get('team') || '', name = q.get('name') || 'a team', by = q.get('by') || 'A colleague';
    view().innerHTML = `<div class="card"><h2>Join ${name}</h2><p>${by} invited you to book rooms with ${name}.</p>
      <button id="ask">Accept invitation</button><div id="msg"></div></div>`;
    document.getElementById('ask').onclick = async () => {
      if (!me) { go('/login'); return; }
      const a = await api('POST', `/teams/${encodeURIComponent(team)}/requests`);
      document.getElementById('msg').innerHTML = a.status === 202 ? '<p>Request sent to the team lead.</p>' : fail(a);
    };
  },
  async account() {
    if (!me) { go('/login'); return; }
    view().innerHTML = `<div class="card"><h2>Account</h2><p>${esc(me.email)} · ${esc(me.credits)} credits left this month</p><form id="f">
      <label>Display name <input name="display_name" value="${esc(me.display_name)}" maxlength="80"></label><button>Save</button><div id="msg"></div></form></div>`;
    const f = document.getElementById('f');
    f.onsubmit = async e => {
      e.preventDefault();
      const u = await api('PATCH', '/me', {display_name: new FormData(f).get('display_name')});
      document.getElementById('msg').innerHTML = u.status === 200 ? '<p>Saved.</p>' : fail(u);
      await whoami();
    };
  },
};

const table = [
  [/^\/?$/, () => go('/rooms')],
  [/^\/login$/, pages.login], [/^\/signup$/, pages.signup],
  [/^\/rooms$/, pages.rooms], [/^\/rooms\/(\d+)$/, pages.room],
  [/^\/bookings$/, pages.bookings], [/^\/bookings\/([\w-]+)$/, pages.booking],
  [/^\/people$/, pages.people], [/^\/teams$/, pages.teams], [/^\/teams\/(\d+)$/, pages.team],
  [/^\/join$/, pages.join], [/^\/account$/, pages.account],
];
async function render() {
  const raw = location.hash.slice(1) || '/';
  const [path, qs] = raw.split('?');
  const q = new URLSearchParams(qs || '');
  for (const [rx, fn] of table) {
    const m = path.match(rx);
    if (m) { await fn(q, ...m.slice(1).map(decodeURIComponent)); return; }
  }
  view().innerHTML = '<p>Page not found.</p>';
}
window.addEventListener('hashchange', render);
(async () => {
  await whoami();
  render();
  const s = await api('GET', store.get('diag') === '1' ? '/status?detail=full' : '/status');
  if (s.data) document.getElementById('ver').textContent = 'v' + s.data.version;
  if (s.data && s.data.mailer) console.table(s.data.mailer.queue);
})();
</script></body></html>
"""


# ---------------------------------------------------------------------- server
def make_server(host: str, port: int, *, secret: bytes | None = None, quiet: bool = False) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    srv.app = App(secret)  # type: ignore[attr-defined]
    srv.quiet = quiet  # type: ignore[attr-defined]
    return srv


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Larkspur Rooms")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)
    srv = make_server(args.host, args.port)
    print(f"larkspur-rooms {VERSION} listening on {args.host}:{args.port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
