"""Lineage: every hunting session is a numbered agent that leaves typed items to its successors.

Host side only (mounted in no container). The memory lives in board.sqlite (bh.lineage.store): one canonical key per
attempt (bh.lineage.key), full-text search with SQLite FTS5, facts dated and superseded rather than erased,
deduplication at write time, a readable Markdown export (bh.lineage.export). No embeddings, no vector store, no
external API: nothing of a program leaves the machine. Provenance labels come from the host (gate, judge, receipts
it checked), never from the agent's text.
"""
