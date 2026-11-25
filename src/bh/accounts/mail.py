"""Confirmation mail: the interface enrollment reads a sign-up mail through, and the "no mailbox" implementation.

A mailbox answers `wait(alias, sender_domain, since, timeout)` with the confirmation link of the newest mail from
`sender_domain` to `alias` received after `since`, or None. The Gmail connector (read-only API) comes later
(decision 2026-11-25: no Gmail for now); until then a program that needs a confirmed address cannot be enrolled
without a human, and enrollment says so instead of waiting.
"""

from __future__ import annotations

from typing import Protocol


class Mailbox(Protocol):
    def wait(self, alias: str, sender_domain: str, since: float, timeout: float) -> str | None: ...


class NoMailbox:
    """No mailbox is configured: never a link."""

    def wait(self, alias: str, sender_domain: str, since: float, timeout: float) -> str | None:
        return None


def default() -> Mailbox:
    return NoMailbox()
