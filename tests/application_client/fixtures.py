"""Transactions for the tests, built around the device's own wallet key."""

from pathlib import Path
from typing import List, Tuple

from .bitcoin import Tx, TxIn, TxOut, sha256

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

P2WPKH_PATH = "m/84'/0'/0'/0/0"
NESTED_PATH = "m/49'/0'/0'/0/0"

# A destination that isn't the wallet: a P2TR output.
P2TR_DESTINATION = bytes.fromhex("5120") + bytes(range(32))


def fixture(name: str) -> bytes:
    return bytes.fromhex((FIXTURES / name).read_text().strip())


def vault_script() -> bytes:
    """A Config A vault script generated with qsb-app's pipeline (seed 2)."""
    return fixture("vault-seed2.hex")


def strip_witness(raw: bytes) -> bytes:
    """Legacy serialization of a SegWit transaction (marker, flag and witnesses removed)."""
    if raw[4] != 0:
        return raw
    pos = 6

    def varint() -> int:
        nonlocal pos
        first = raw[pos]
        pos += 1
        if first < 0xFD:
            return first
        size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
        value = int.from_bytes(raw[pos:pos + size], "little")
        pos += size
        return value

    def skip(n: int) -> None:
        nonlocal pos
        pos += n

    # Not `pos += varint()`: that adds to the value of `pos` from before the read.
    n_in = varint()
    for _ in range(n_in):
        skip(36)
        skip(varint())
        skip(4)
    for _ in range(varint()):
        skip(8)
        skip(varint())
    body_end = pos
    for _ in range(n_in):
        for _ in range(varint()):
            skip(varint())
    assert pos + 4 == len(raw), "malformed SegWit transaction"
    return raw[:4] + raw[6:body_end] + raw[pos:]


def mainnet_deposit() -> bytes:
    """qsb-app's first mainnet deposit, 1378dd5c…: output 0 is a real vault."""
    return strip_witness(fixture("mainnet-deposit.hex"))


MAINNET_VAULT_FINGERPRINT = "5f7a0bc1bf0fa932d95ad2dd9b60104dbbebb1f7b42ee5f1f2d58c344525290e"


def funding(script: bytes, value: int, salt: int) -> Tx:
    """A transaction from an arbitrary outpoint paying `value` to `script` at output 0."""
    return Tx(
        version=2,
        inputs=[TxIn(sha256(bytes([salt])), 1, 0xFFFFFFFD, b"")],
        outputs=[TxOut(value, script), TxOut(1_000, bytes.fromhex("0014") + bytes([salt]) * 20)],
    )


def deposit(wallet: bytes, values: List[int], amount: int, change: int) -> Tuple[Tx, List[bytes]]:
    """A deposit of `amount` into the vault, spending wallet UTXOs of `values`."""
    prevs = [funding(wallet, v, i) for i, v in enumerate(values)]
    outputs = [TxOut(amount, vault_script())]
    if change:
        outputs.append(TxOut(change, wallet))
    tx = Tx(2, [TxIn(p.txid(), 0) for p in prevs], outputs)
    return tx, [p.serialize() for p in prevs]


def withdrawal(wallet: bytes, helper: int, destination: bytes, amount: int) -> Tuple[Tx, List[bytes], int]:
    """A withdrawal of the mainnet vault (100,000 sats) plus a wallet helper UTXO."""
    helper_prev = funding(wallet, helper, 7)
    vault_prev = mainnet_deposit()
    vault_txid = sha256(sha256(vault_prev))
    tx = Tx(
        version=1,
        inputs=[TxIn(helper_prev.txid(), 0, 0xFFFFFFFE), TxIn(vault_txid, 0, 0x800007A1)],
        outputs=[TxOut(amount, destination)],
        locktime=950_229_240,
    )
    return tx, [helper_prev.serialize(), vault_prev], 100_000
