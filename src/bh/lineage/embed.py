"""Room for embeddings, not wired: memory search is SQLite FTS5 (bh.lineage.store), nothing leaves the host.

An implementation would have to run locally (no API, no third party). None exists; nothing calls this.
"""

from __future__ import annotations

from typing import Protocol

ENABLED = False


class Embedder(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]:
        """One vector per text, same order."""
        ...
