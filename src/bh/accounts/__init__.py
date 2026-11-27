"""The harness's own test accounts: declarative sign-up and login recipes, run through the gate (issue 25)."""

from __future__ import annotations

from typing import Any


def plant(scope, name: str, **kw: Any) -> dict[str, Any]:
    """T24: the host-planted canary in `name`'s declared private field (bh.accounts.canary.plant)."""
    from bh.accounts.canary import plant as _plant  # lazy: importing the package costs nothing

    return _plant(scope, name, **kw)
