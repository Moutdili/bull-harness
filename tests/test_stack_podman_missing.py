from bh import stack


def test_container_running_is_false_without_podman(monkeypatch):
    """Found by running the suite in the audit container: without podman, /api/status raised instead of saying down."""

    def missing(*a, **k):
        raise FileNotFoundError("podman")

    monkeypatch.setattr(stack.subprocess, "run", missing)
    assert stack.container_running("bh-gate") is False
