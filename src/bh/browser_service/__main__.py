"""Entry points in bh-browser: `serve` (the compose command) and `host` (what `podman exec -i` runs)."""

from __future__ import annotations

import sys

# How the container starts the package: isolated mode (-I: no cwd, no PYTHONPATH, no user site), the read-only
# mount /opt/bh/lib put first by hand.
BOOT = "import sys;sys.path.insert(0,'/opt/bh/lib');from bh.browser_service.__main__ import main;main(sys.argv[1:])"


def main(argv: list[str] | None = None) -> None:
    from bh.browser_service import controller

    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["serve"]:
        raise SystemExit(controller.serve())
    if argv[:1] == ["host"]:
        raise SystemExit(controller.host_main())
    raise SystemExit("usage: python3 -m bh.browser_service serve|host")


if __name__ == "__main__":
    main()
