"""Checks of a disclosure against the reference (pqb.py), independent of the app."""

import hashlib

from . import fixtures as fx
from . import pqb
from .bitcoin import hash160, verify
from .pqb_command_sender import Disclosure, WithdrawRequest


def check_disclosure(req: WithdrawRequest, d: Disclosure) -> None:
    seed = fx.seed(req.v)
    cs = fx.commitments(req.v)
    # Round 0: the 20-byte preimages s[j], HASH160(s[j]) = c[j].
    assert len(d.s) == 8
    for j, s in zip(req.round0, d.s):
        assert s == pqb.hors(seed, j)[0]
        assert hash160(s) == cs[j]
    # Round 1: w[j] = SHA256(s[j]), RIPEMD160(w[j]) = c[j].
    assert len(d.w) == 9
    for j, w in zip(req.round1, d.w):
        assert w == pqb.hors(seed, j)[1]
        assert pqb.ripemd160(w) == cs[j]
    # Menu signatures: SHA1(g) is the stage's commitment.
    offsets = (109, 121, 137)
    for stage, (p, g) in enumerate(zip(req.picks, d.menu_sigs)):
        assert g == pqb.menu(seed, stage)[p][1]
        assert hashlib.sha1(g).digest() == cs[offsets[stage] + p]
    # Co-signature: Q's HASH160 is commitment 153; it signs the legacy sighash of T.
    assert d.q == pqb.cosign_key(seed)[1]
    assert hash160(d.q) == cs[153]
    z = pqb.legacy_sighash_all(req.unsigned_tx(), fx.script(req.v))
    verify(d.q, z, d.cosig)
    der = d.cosig[:-1]
    assert pqb.ecdsa_verify(d.q, z, *pqb.der_decode(der))


def binding(req: WithdrawRequest) -> bytes:
    return hashlib.sha256(req.unsigned_tx()).digest()


def digest(req: WithdrawRequest) -> bytes:
    return pqb.disclosure_digest(req.round0, req.round1, req.picks, binding(req))
