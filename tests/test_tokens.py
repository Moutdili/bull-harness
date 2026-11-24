"""Token economy watch: command miner parsing and pricing (aliases dropped, issue 017)."""

import json

from bh.tokens import miner


def test_prefixes_are_literal_and_skip_builtins():
    got = miner.prefixes('cd /tmp; bh-note fact "x y" -s z | head -c 300 && export A=1; curl http://h/x')
    assert "bh-note fact" in got and "head -c 300" in got
    assert not any(p.startswith(("cd", "export")) for p in got)  # an executable cannot change the shell
    assert "bh-note fact x y" not in got  # quoted, variable text stops the prefix
    assert "curl" in got and not any("://" in p for p in got)


def test_net_saving_prices_the_legend():
    assert miner.net_saving(tokens=8, uses=5, symbol=1) > 0
    assert miner.net_saving(tokens=3, uses=0.2, symbol=2) < 0  # rare and short: the legend costs more
    assert miner.net_saving(tokens=8, uses=5, symbol=2) < miner.net_saving(tokens=8, uses=5, symbol=1)


def test_select_prices_overlapping_prefixes_on_their_margin():
    cands = [miner.Candidate("bh-note", 80, 3), miner.Candidate("bh-note frontier", 30, 5)]
    chosen = miner.select(cands, runs=4, symbol_costs=[1, 1])
    assert [x.prefix for x in chosen] == ["bh-note", "bh-note frontier"]
    # with an alias for bh-note, `<a> frontier` already saves 2 of the 5 tokens: the second alias is priced on 2
    assert chosen[1].net < miner.net_saving(5, 30 / 4, 1)
    few = [miner.Candidate("bh-note", 20, 3), miner.Candidate("bh-note frontier", 18, 5)]
    chosen = miner.select(few, runs=2, symbol_costs=[1, 1])
    assert chosen[0].prefix == "bh-note frontier"
    assert all(x.prefix != "bh-note" for x in chosen[1:]) or chosen[1].uses == (20 - 18) / 2


def test_mine_from_run_logs(tmp_path):
    ev = {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Bash", "input": {}}]}}
    for i in range(3):
        lines = []
        for _ in range(6):
            ev["message"]["content"][0]["input"] = {"command": "bh-note frontier | head -c 400"}
            lines.append(json.dumps(ev))
        (tmp_path / f"{i:05d}-p.jsonl").write_text("\n".join(lines))
    chosen, runs = miner.mine(runs_dir=tmp_path, measure=lambda items: {p: 2 + 2 * p.count(" ") for p in items})
    assert runs == 3
    assert {x.prefix for x in chosen} >= {"bh-note frontier", "head -c 400"}


def test_prefixes_ignore_heredoc_bodies_and_quoted_separators():
    cmd = (
        "cd /w; cat > poc.sh <<'E'\n#!/bin/sh\ncurl -s x; echo\nE\nchmod +x poc.sh\n"
        'bh-note fact "a; b | c\nno new findings" -k handoff; bh-note fact "x" -s "F1-F5,F11 filed"'
    )
    got = miner.prefixes(cmd)
    assert "chmod +x poc.sh" in got and got.count("bh-note fact") == 2
    assert not {"E", "no", "b", "c", "curl", "echo", "F1-F5,F11"} & set(got)


def test_prefixes_skip_shell_functions():
    got = miner.prefixes("b(){ printf %s \"$1\" | base64 -w0; }\nH=$(b 'x'); P=$(b 'y')\ncurl -s x")
    assert "b" not in got and "base64 -w0" in got and "curl -s" in got


def test_prefixes_inside_loops_and_conditions():
    got = miner.prefixes("for i in 1 2; do curl -s x; done; if grep -q a f; then echo ok; fi")
    assert {"curl -s", "grep -q", "echo ok"} <= set(got)
    assert not any(p.startswith(("for", "i ", "in")) for p in got)
