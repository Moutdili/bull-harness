from types import SimpleNamespace

from bh.browser_service import watch


def test_a_challenge_is_pushed_once_and_a_new_one_again():
    pushed = []
    st = {"challenge": {"pending": True, "since": 10.0}, "program": "p", "identity": "user-a"}
    w = watch.ChallengeWatcher(
        status=lambda: st, push=lambda *a: pushed.append(a), running=lambda: True, view=lambda: "http://ui/captcha/"
    )
    w.tick()
    w.tick()
    assert pushed == [("p", "user-a", "http://ui/captcha/")]
    st["challenge"] = {"pending": False}
    w.tick()
    st["challenge"] = {"pending": True, "since": 20.0}
    w.tick()
    assert len(pushed) == 2


def test_the_watcher_never_raises_and_skips_a_stopped_browser():
    def boom():
        raise OSError("down")

    w = watch.ChallengeWatcher(status=boom, push=lambda *a: 1 / 0, running=lambda: True, view=lambda: "")
    w.tick()
    w2 = watch.ChallengeWatcher(status=boom, push=lambda *a: 1 / 0, running=lambda: False, view=lambda: "")
    w2.tick()


def test_only_scopes_with_a_passthrough_host_want_the_browser():
    assert watch.wanted(SimpleNamespace(support_hosts=lambda k: ("challenges.cloudflare.com",)))
    assert not watch.wanted(SimpleNamespace(support_hosts=lambda k: ()))
    assert watch.prepare(SimpleNamespace(support_hosts=lambda k: ()), ["user-a"]) is None
