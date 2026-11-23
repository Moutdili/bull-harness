"""Shared board: facts (title/summary/evidence), intents, findings, human todos, runs."""

from bh.board.db import Board, default_board_path

__all__ = ["Board", "default_board_path"]
