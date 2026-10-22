"""Reference implementation of QSB-HORS-v1 (the "QSB HORS Ledger App" spec).

Independent of the app: the functional tests compare the device against it,
and `python3 tests/application_client/hors.py` checks SLIP-0021 against its
published test vectors and prints the vectors qsb-core's tests embed.
"""

import hashlib
import hmac
import struct
from typing import List, Sequence

N = 150
SPEC = b"QSB-HORS-v1"
LABEL = b"QSB-HORS"

# Speculos's default seed, which Ragger uses.
SPECULOS_MNEMONIC = (
    "glory promote mansion idle axis finger extra february uncover one trip resource "
    "lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
)


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def bip39_seed(mnemonic: str, passphrase: str = "") -> bytes:
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), ("mnemonic" + passphrase).encode(), 2048)


def slip21_key(seed: bytes, labels: Sequence[bytes]) -> bytes:
    """SLIP-0021: Key(N) = N[32:64], children from N[0:32]."""
    node = hmac.new(b"Symmetric key seed", seed, hashlib.sha512).digest()
    for label in labels:
        node = hmac.new(node[:32], b"\x00" + label, hashlib.sha512).digest()
    return node[32:]


def app_key(mnemonic: str = SPECULOS_MNEMONIC) -> bytes:
    return slip21_key(bip39_seed(mnemonic), [LABEL])


def secret(k: bytes, net: int, v: int, r: int, i: int) -> bytes:
    message = SPEC + b"\x00" + bytes([net]) + struct.pack(">I", v) + bytes([r]) + struct.pack(">H", i)
    return hmac.new(k, message, hashlib.sha256).digest()[:20]


def _hash160(b: bytes) -> bytes:
    from .bitcoin import hash160  # pure Python RIPEMD-160; OpenSSL 3 may lack it

    return hash160(b)


def commitments(k: bytes, net: int, v: int, r: int) -> List[bytes]:
    return [_hash160(secret(k, net, v, r, i)) for i in range(N)]


def root(k: bytes, net: int, v: int) -> bytes:
    return _sha256(b"QSB-HORS-v1/root" + b"".join(commitments(k, net, v, 0) + commitments(k, net, v, 1)))


def reveal_hash(round1: Sequence[int], round2: Sequence[int], binding: bytes) -> bytes:
    indices = b"".join(struct.pack(">H", i) for i in list(round1) + list(round2))
    return _sha256(b"QSB-HORS-v1/reveal" + indices + binding)


def wallet_tag(k: bytes) -> bytes:
    """The reveal guard's tag for the wallet K belongs to (not part of the spec's v1 record)."""
    return hmac.new(k, b"QSB-HORS-v1/guard", hashlib.sha256).digest()[:8]


def fingerprint(r: bytes) -> str:
    h = r[:8].hex()
    return " ".join(h[j:j + 4] for j in range(0, 16, 4))


def _self_test() -> None:
    seed = bip39_seed("all all all all all all all all all all all all")
    assert seed.hex() == (
        "c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f"
        "74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8"
    )
    vectors = {
        (): "dbf12b44133eaab506a740f6565cc117228cbf1dd70635cfa8ddfdc9af734756",
        (b"SLIP-0021",): "1d065e3ac1bbe5c7fad32cf2305f7d709dc070d672044a19e610c77cdf33de0d",
        (b"SLIP-0021", b"Master encryption key"): "ea163130e35bbafdf5ddee97a17b39cef2be4b4f390180d65b54cf05c6a82fde",
        (b"SLIP-0021", b"Authentication key"): "47194e938ab24cc82bfa25f6486ed54bebe79c40ae2a5a32ea6db294d81861a6",
    }
    for labels, key in vectors.items():
        assert slip21_key(seed, labels).hex() == key, labels


if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from application_client import hors  # noqa: E402  (so the relative import resolves)

    hors._self_test()
    print("SLIP-0021 vectors: ok")
    k = bytes(range(32))
    print("K =", k.hex())
    for net, v, r, i in [(0, 0, 0, 0), (0, 0, 1, 149), (0, 7, 0, 3), (1, 0x7FFFFFFF, 1, 42)]:
        s = hors.secret(k, net, v, r, i)
        print(f"secret{(net, v, r, i)} = {s.hex()}  commitment = {hors._hash160(s).hex()}")
    for net, v in [(0, 0), (0, 7)]:
        rt = hors.root(k, net, v)
        print(f"root{(net, v)} = {rt.hex()}  fingerprint = {hors.fingerprint(rt)}")
    print("reveal_hash =", hors.reveal_hash(list(range(8)), list(range(140, 147)), bytes([0xAB]) * 32).hex())
    print("wallet_tag =", hors.wallet_tag(k).hex())
    print("speculos K =", hors.app_key().hex())
