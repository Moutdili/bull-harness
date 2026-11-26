"""RFC 6238 TOTP, checked against the test vectors of its appendix B, and the shapes a seed is stored in."""

import base64

import pytest

from bh.accounts import totp

# RFC 6238 appendix B: the seeds are the ASCII strings below (20, 32 and 64 bytes), 8 digits, 30 s, T0 = 0.
SEEDS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}
VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


@pytest.mark.parametrize(("t", "sha1", "sha256", "sha512"), VECTORS)
def test_rfc6238_appendix_b(t, sha1, sha256, sha512):
    for algo, want in (("SHA1", sha1), ("SHA256", sha256), ("SHA512", sha512)):
        assert totp.totp(totp.Params(SEEDS[algo], digits=8, algorithm=algo), t) == want


def test_defaults_are_sha1_30s_6_digits():
    p = totp.params(base64.b32encode(SEEDS["SHA1"]).decode())
    assert (p.digits, p.period, p.algorithm) == (6, 30, "SHA1")
    assert totp.totp(p, 59) == "287082"  # the last 6 digits of the 8-digit vector
    assert totp.totp(p, 30) == totp.totp(p, 59) != totp.totp(p, 60)


def test_seed_shapes_and_otpauth_uri():
    b32 = base64.b32encode(SEEDS["SHA256"]).decode().rstrip("=")
    spaced = " ".join(b32[i : i + 4] for i in range(0, len(b32), 4)).lower()
    uri = f"otpauth://totp/Lab:user-a?secret={b32}&algorithm=SHA256&digits=8&period=30&issuer=Lab"
    for doc in (uri, {"secret": spaced, "algorithm": "sha-256", "digits": 8}):
        p = totp.params(doc)
        assert p.key == SEEDS["SHA256"] and p.algorithm == "SHA256" and p.digits == 8
        assert totp.totp(p, 1111111109) == "68084774"
    assert "key" not in repr(p) and b32 not in repr(p)


@pytest.mark.parametrize(
    "doc",
    [
        "not base32 !",
        "",
        {"secret": "JBSWY3DP", "algorithm": "MD5"},
        {"secret": "JBSWY3DP", "digits": 4},
        "otpauth://hotp/x?secret=JBSWY3DP",
        {"no": "secret"},
        42,
    ],
)
def test_bad_seeds_are_refused_without_echo(doc):
    with pytest.raises(totp.TotpError) as exc:
        totp.params(doc)
    if isinstance(doc, str) and doc:
        assert doc not in str(exc.value)


def test_fresh_code_waits_for_the_next_window_near_its_end():
    p = totp.params(base64.b32encode(SEEDS["SHA1"]).decode())
    slept = []
    assert totp.fresh_code(p, at=58.0, sleep=slept.append) == totp.totp(p, 60.2)
    assert slept and 2.0 <= slept[0] <= 2.3
    slept.clear()
    assert totp.fresh_code(p, at=31.0, sleep=slept.append) == totp.totp(p, 31.0) and not slept
