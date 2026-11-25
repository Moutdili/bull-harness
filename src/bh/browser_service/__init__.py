"""Persistent headful browser with a remote screen (compose service `browser`, container `bh-browser`).

Why: some programs show a human challenge (Cloudflare Turnstile) that the harness must never solve, evade or click
itself. Mio may solve it himself, in the very browser the agent uses (a Turnstile token is bound to the browser
that got it). See docs/research/18-navigateur-persistant-captcha-humain.md.

Layout:
- `controller`: runs in bh-browser. Xvfb + the distribution's Chromium (headful, persistent profile, gate proxy,
  CDP on the container's loopback only) + x11vnc on the container's loopback; one Playwright client
  (connect_over_cdp) behind two interfaces:
    * the agent's narrow HTTP API on the sandbox network (AGENT_OPS, bearer token);
    * the host's control socket, reached only through `podman exec -i` (HOST_OPS, JSON on stdin).
- `detect`: pure helpers (challenge detection, redaction), shared by the controller and the tests.
- `host`: host side (session -> cookies, `podman exec` calls, the noVNC client files, the screen tunnel).
- `notify`: the call point for "a human is needed" (empty on purpose for now).

Nothing in this package imports playwright at module level: the host has no playwright.
"""

from __future__ import annotations

API_PORT = 8790  # agent API, sandbox network (http://browser:8790)
CDP_PORT = 9222  # Chromium DevTools, the container's loopback only
VNC_PORT = 5900  # x11vnc, the container's loopback only
DISPLAY = ":99"
SCREEN = (1280, 900)
PROFILE_ROOT = "/profile"  # named volume `browser-profile`: the profile survives a restart, `reset` wipes it
RUN_DIR = "/tmp/bh-browser"  # 0700, the container user's own: control socket
CTL_SOCK = RUN_DIR + "/ctl.sock"
GATE_PROXY = "http://gate:8080"
TOKEN_ENV = "BH_BROWSER_TOKEN"

# What the agent may ask (HTTP API) and what only the host may ask (podman exec). Anything else is refused.
AGENT_OPS = frozenset({"goto", "fill", "click", "press", "text", "wait", "state"})
HOST_OPS = frozenset({"load_session", "status", "reset", "human_done"})
