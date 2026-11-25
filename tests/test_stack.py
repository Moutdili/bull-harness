"""Which container the host's operations aim at (no podman: subprocess is replaced)."""

import subprocess

import pytest

from bh import stack


def _record(monkeypatch):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(stack.subprocess, "run", fake_run)
    return calls


def _target(argv):
    return argv[argv.index("--user") + 2]


def test_agent_sh_defaults_to_the_agent_and_takes_another_container(monkeypatch):
    calls = _record(monkeypatch)
    stack.agent_sh("true")
    stack.agent_sh("true", container=stack.JUDGE_CTR)
    assert [_target(a) for a in calls] == [stack.AGENT, stack.JUDGE_CTR]


def test_prepare_judge_runs_in_the_judge_container_as_root(monkeypatch):
    calls = _record(monkeypatch)
    stack.prepare_judge("/tmp/bh-home-1-F2", "/work/p/.verify/F2")
    (argv,) = calls
    assert _target(argv) == stack.JUDGE_CTR and argv[argv.index("--user") + 1] == "root"
    assert argv[-2:] == ["/tmp/bh-home-1-F2", "/work/p/.verify/F2"]


def test_kill_follows_the_work_dir_to_its_container(monkeypatch):
    calls = _record(monkeypatch)
    stack.kill_agent("p")
    stack.kill_agent("p", bh_dir="/work/p/.verify/F2")
    assert [_target(a) for a in calls] == [stack.AGENT, stack.JUDGE_CTR]
    assert calls[1][-2] == "/work/p/.verify/F2/" + stack.c.AGENT_PID


def test_push_file_names_its_container(monkeypatch):
    calls = _record(monkeypatch)
    stack.push_file("/work/p/.verify/F2/proof.json", "{}", user=stack.JUDGE, container=stack.JUDGE_CTR)
    assert _target(calls[0]) == stack.JUDGE_CTR


def test_container_of():
    assert stack.container_of(None) == stack.AGENT
    assert stack.container_of("/work/p/.bh") == stack.AGENT
    assert stack.container_of("/work/p/.verify/F9") == stack.JUDGE_CTR
    assert stack.container_of("/work/p/.verifyx/F9") == stack.AGENT


def test_in_container_swaps_exactly_the_agent():
    cmd = ["podman", "exec", "-i", "--user", "judge", "-e", "BH_DIR=/work/bh-agent", stack.AGENT, "sh", "-c", "x"]
    out = stack.in_container(cmd, stack.JUDGE_CTR)
    assert out[7] == stack.JUDGE_CTR and out[6] == "BH_DIR=/work/bh-agent" and stack.AGENT not in out
    with pytest.raises(ValueError):
        stack.in_container(["sh", "-c", stack.AGENT], stack.JUDGE_CTR)
    with pytest.raises(ValueError):
        stack.in_container(["podman", "exec", stack.AGENT, stack.AGENT], stack.JUDGE_CTR)
