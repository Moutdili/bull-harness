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


# ------------------------------------------------------------------ B5: the kill loop, run by sh with fake tools
_FAKES = r"""
pgrep() { case "$*" in "-u root -x runuser") echo 100 ;; "-P 100") echo 101 ;; "-u hunter") cat "$STATE" ;; esac; }
ps() { echo S; }
id() { return 0; }
sleep() { :; }
kill() { echo "$@" >> "$KILLED"; [ -n "$RESPAWN" ] || echo 101 > "$STATE"; }
users="hunter"
"""


def _kill_loop(tmp_path, respawn: bool):
    state, killed = tmp_path / "state", tmp_path / "killed"
    state.write_text("101\n102\n103\n")
    env = {"STATE": str(state), "KILLED": str(killed), "RESPAWN": "1" if respawn else "", "PATH": "/usr/bin:/bin"}
    r = subprocess.run(["sh", "-c", _FAKES + stack._KILL_USERS], capture_output=True, text=True, env=env, timeout=30)
    return r, killed.read_text().splitlines() if killed.exists() else []


def test_kill_repeats_until_no_process_is_left_and_spares_the_keep_alive(tmp_path):
    r, killed = _kill_loop(tmp_path, respawn=False)
    assert r.returncode == 0, r.stderr
    assert killed == ["-KILL 102 103"]  # 101 is the keep-alive (child of root's runuser)


def test_kill_fails_when_a_process_keeps_coming_back(tmp_path):
    r, killed = _kill_loop(tmp_path, respawn=True)
    assert r.returncode == 1 and "survive" in r.stderr
    assert len(killed) == 50  # bounded: it gives up instead of looping forever


def test_reset_scripts_never_follow_links_and_empty_tmp():
    for script in (stack._RESET_SCRIPT, stack._SCRUB_SCRIPT, stack._JUDGE_SCRIPT):
        assert stack._KILL_USERS in script
        assert "chown -h" in script and "chown hunter" not in script and "chown judge" not in script
    assert "find /tmp /var/tmp /dev/shm -mindepth 1 -user hunter" in stack._RESET_SCRIPT
    assert 'mkdir -m 700 -- "$1"' in stack._RESET_SCRIPT  # never through a planted link (no -p)


def test_scrub_failure_stops_the_segment(monkeypatch):
    monkeypatch.setattr(
        stack.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", "processes survive")
    )
    with pytest.raises(SystemExit, match="cannot scrub"):
        stack.scrub_agent_user("/tmp/bh-home-1")
