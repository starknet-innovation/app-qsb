"""Transactions and expected values for the PQB tests, built from the reference (pqb.py)."""

from functools import lru_cache
from typing import List, Sequence, Tuple

from . import pqb
from .bitcoin import Tx, TxIn, TxOut, address, sha256
from .pqb_command_sender import WithdrawRequest

# Destinations that aren't the vault: a P2TR and a P2WPKH output.
P2TR_DESTINATION = bytes.fromhex("5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
P2WPKH_DESTINATION = bytes.fromhex("0014") + bytes(range(20))

# A valid selection: 8 + 9 ascending indices below 109, disjoint; picks below 12, 16, 16.
ROUND0 = [0, 3, 9, 27, 40, 64, 100, 108]
ROUND1 = [1, 2, 4, 5, 33, 50, 77, 99, 107]
PICKS = [11, 0, 15]


@lru_cache(maxsize=None)
def seed(v: int) -> bytes:
    return pqb.device_seed(v)


@lru_cache(maxsize=None)
def commitments(v: int) -> Tuple[bytes, ...]:
    return tuple(pqb.commitments(seed(v)))


@lru_cache(maxsize=None)
def root(v: int) -> bytes:
    return pqb.root(seed(v), list(commitments(v)))


@lru_cache(maxsize=None)
def script(v: int) -> bytes:
    return pqb.script(seed(v), list(commitments(v)))


def script_hash(v: int) -> bytes:
    return sha256(script(v))


@lru_cache(maxsize=None)
def deposit_script(v: int) -> bytes:
    return pqb.deposit_script(seed(v))


def deposit_pubkey(v: int) -> bytes:
    return pqb.deposit_key(seed(v))[1]


def deposit_address(v: int) -> str:
    return address(deposit_script(v))


def funding(script_pubkey: bytes, value: int, salt: int, vout: int = 0) -> Tx:
    """A transaction from an arbitrary outpoint paying `value` to `script_pubkey` at output `vout`."""
    outputs = [TxOut(1_000 + salt, bytes.fromhex("0014") + bytes([salt]) * 20) for _ in range(vout)]
    outputs.append(TxOut(value, script_pubkey))
    outputs.append(TxOut(2_000, bytes.fromhex("0014") + bytes([salt ^ 0xFF]) * 20))
    return Tx(version=2, inputs=[TxIn(sha256(bytes([salt, vout])), 1, 0xFFFFFFFD)], outputs=outputs)


def sweep(v: int, values: Sequence[int], amount: int, salt: int = 0,
          to: bytes = b"") -> Tuple[Tx, List[bytes]]:
    """A sweep of deposit UTXOs of `values` into vault `v` (or into `to`)."""
    prevs = [funding(deposit_script(v), value, salt + i) for i, value in enumerate(values)]
    tx = Tx(2, [TxIn(p.txid(), 0, 0xFFFFFFFD) for p in prevs], [TxOut(amount, to or script(v))])
    return tx, [p.serialize() for p in prevs]


def refund(v: int, values: Sequence[int], outputs: List[TxOut], salt: int = 0x40) -> Tuple[Tx, List[bytes]]:
    prevs = [funding(deposit_script(v), value, salt + i) for i, value in enumerate(values)]
    tx = Tx(2, [TxIn(p.txid(), 0, 0xFFFFFFFD) for p in prevs], outputs)
    return tx, [p.serialize() for p in prevs]


def withdrawal(v: int, prev: Tx, vout: int, outputs: List[TxOut], round0: Sequence[int] = ROUND0,
               round1: Sequence[int] = ROUND1, picks: Sequence[int] = PICKS, **kw) -> WithdrawRequest:
    return WithdrawRequest(
        v=v, prev_tx=prev.serialize(), vout=vout,
        outputs=b"".join(o.serialize() for o in outputs), n_outputs=len(outputs),
        round0=list(round0), round1=list(round1), picks=list(picks), **kw,
    )
