"""Reference implementation of the PQB-v1 profile (BIP "PQB Vault Secret Management").

Independent of the app: the functional tests compare the device against it.
Derivation follows the BIP's reference.py byte for byte; the script comes from
the template in pqb-core/src/template.bin (regenerated, and checked against the
pqb implementation, by tools/pqb_template.py).

Slow, variable-time pure-Python secp256k1: for tests only.
"""

import hashlib
import hmac
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

PROFILE = b"PQB-v1"
TABLE = 109
# (tag, width, r): pqb v1 uses r = 1 for the pinning menu, 0x81 for the round menus.
MENUS = (("pin", 12, 1), ("round0", 16, 0x81), ("round1", 16, 0x81))
PQB_VERSION = "v1"
BIP85_PATH = [83696968, 39, 0, 24]  # then v', all hardened

# Speculos's default seed, which Ragger uses.
SPECULOS_MNEMONIC = (
    "glory promote mansion idle axis finger extra february uncover one trip resource "
    "lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
)

TEMPLATE = (Path(__file__).resolve().parent.parent.parent / "pqb-core" / "src" / "template.bin")
SCRIPT_LEN = 4696
# Script order: (offset of the first push opcode, stride, count, first root index).
LAYOUT = [(6, 0, 1, 153), (34, 21, 12, 109), (306, 31, 109, 0), (3675, 21, 16, 121),
          (4175, 21, 16, 137)]


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ripemd160(b: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", b).digest()
    except ValueError:  # OpenSSL 3 without the legacy provider
        from .bitcoin import _ripemd160
        return _ripemd160(b)


def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))


# ---- secp256k1 ---------------------------------------------------------------
def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def point_mul(k: int, pt=G):
    acc = None
    while k:
        if k & 1:
            acc = point_add(acc, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return acc


def compress(pt) -> bytes:
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def decompress(b: bytes):
    x = int.from_bytes(b[1:], "big")
    pt = lift_x(x, b[0] == 3)
    assert pt is not None
    return pt


def lift_x(x: int, odd: bool):
    if not 0 < x < P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    if (y & 1) != odd:
        y = P - y
    return x, y


def on_curve_x(x: int) -> bool:
    return lift_x(x, False) is not None


def key_from_bytes(b32: bytes) -> int:
    return int.from_bytes(b32, "big") % (N - 1) + 1


def pubkey(d: int) -> bytes:
    return compress(point_mul(d))


def ecdsa_verify(pub: bytes, z: bytes, r: int, s: int) -> bool:
    if not (0 < r < N and 0 < s < N):
        return False
    w = pow(s, N - 2, N)
    u1 = int.from_bytes(z, "big") * w % N
    u2 = r * w % N
    pt = point_add(point_mul(u1), point_mul(u2, decompress(pub)))
    return pt is not None and pt[0] % N == r


def der_decode(sig: bytes) -> Tuple[int, int]:
    assert sig[0] == 0x30 and sig[1] == len(sig) - 2
    assert sig[2] == 0x02
    rl = sig[3]
    r = int.from_bytes(sig[4:4 + rl], "big")
    assert sig[4 + rl] == 0x02
    sl = sig[5 + rl]
    s = int.from_bytes(sig[6 + rl:6 + rl + sl], "big")
    assert 6 + rl + sl == len(sig)
    return r, s


# ---- seed sources ------------------------------------------------------------
def bip39_seed(mnemonic: str, passphrase: str = "") -> bytes:
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), ("mnemonic" + passphrase).encode(), 2048)


def bip85_child(seed64: bytes, index: int) -> bytes:
    """E: BIP 85 entropy at m/83696968'/39'/0'/24'/index'."""
    i = hmac.new(b"Bitcoin seed", seed64, "sha512").digest()
    k, c = int.from_bytes(i[:32], "big"), i[32:]
    for step in BIP85_PATH + [index]:
        d = hmac.new(c, b"\x00" + k.to_bytes(32, "big") + (step + 2**31).to_bytes(4, "big"),
                     "sha512").digest()
        k, c = (int.from_bytes(d[:32], "big") + k) % N, d[32:]
    return hmac.new(b"bip-entropy-from-k", k.to_bytes(32, "big"), "sha512").digest()[:32]


def vault_seed(child: bytes, network: str = "main") -> bytes:
    return hmac.new(child, b"pqb/vault-seed|hybrid|PQB|v1|real|" + network.encode(), "sha256").digest()


def device_seed(v: int, mnemonic: str = SPECULOS_MNEMONIC, passphrase: str = "") -> bytes:
    """S for vault v of a device holding `mnemonic`, on mainnet."""
    return vault_seed(bip85_child(bip39_seed(mnemonic, passphrase), v))


def wallet_id(mnemonic: str = SPECULOS_MNEMONIC, passphrase: str = "") -> bytes:
    """The device's record key for a seed: SHA256("PQB-v1/wallet" || S(v=0))[0..16)."""
    return sha256(PROFILE + b"/wallet" + device_seed(0, mnemonic, passphrase))[:16]


# ---- per-vault secrets -------------------------------------------------------
def secret(seed: bytes, label: bytes) -> bytes:
    assert len(seed) == 32
    return sha256(b"pqb/v1|" + seed + b"|" + label)


def hors(seed: bytes, j: int) -> Tuple[bytes, bytes, bytes]:
    s = secret(seed, b"r2g4-hors-%d" % j)[:20]
    return s, sha256(s), hash160(s)


def der_int(v: int) -> bytes:
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    return b"\x02" + bytes([len(b) + (b[0] >> 7)]) + (b"\x00" if b[0] & 0x80 else b"") + b


def der_sig(r: int, s: int, hashtype: int = 1) -> bytes:
    body = der_int(r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body + bytes([hashtype])


def menu_r(seed: bytes, stage: int) -> int:
    return MENUS[stage][2]


def menu(seed: bytes, stage: int) -> List[Tuple[int, bytes, bytes]]:
    """[(scalar, signature, commitment)] of stage 0 (pin), 1 (round 0), 2 (round 1)."""
    tag, width, _ = MENUS[stage]
    r = menu_r(seed, stage)
    inner = secret(seed, b"r5close-indep-menu-" + tag.encode())
    out = []
    for i in range(width):
        x = (int.from_bytes(sha256(inner + b"|%d" % i), "big") >> 6) | 2**250
        sig = der_sig(r, x)
        out.append((x, sig, hashlib.sha1(sig).digest()))
    return out


def cosign_key(seed: bytes) -> Tuple[int, bytes, bytes]:
    d = key_from_bytes(secret(seed, b"cosig-key"))
    pk = pubkey(d)
    return d, pk, hash160(pk)


def deposit_key(seed: bytes) -> Tuple[int, bytes]:
    d = key_from_bytes(hmac.new(seed, b"pqb/deposit-key/v1", "sha512").digest()[:32])
    return d, pubkey(d)


def deposit_script(seed: bytes) -> bytes:
    return bytes.fromhex("0014") + hash160(deposit_key(seed)[1])


def commitments(seed: bytes) -> List[bytes]:
    out = [hors(seed, j)[2] for j in range(TABLE)]
    for stage in range(3):
        out += [c for _, _, c in menu(seed, stage)]
    return out + [cosign_key(seed)[2]]


def root(seed: bytes, cs: Optional[List[bytes]] = None) -> bytes:
    return sha256(PROFILE + b"/root" + b"".join(cs or commitments(seed)))


def fingerprint(r: bytes) -> str:
    h = r[:8].hex()
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


def script(seed: bytes, cs: Optional[List[bytes]] = None) -> bytes:
    cs = cs or commitments(seed)
    out = bytearray(TEMPLATE.read_bytes())
    assert len(out) == SCRIPT_LEN
    for push, stride, count, first in LAYOUT:
        for i in range(count):
            at = push + i * stride + 1
            out[at:at + 20] = cs[first + i]
    return bytes(out)


def menu_points(seed: bytes, stage: int, variant: int) -> Optional[List[bytes]]:
    """(r^-1 * s_i) * R for each menu scalar, R = lift_x(r + n*(variant>>1), odd=variant&1)."""
    r = menu_r(seed, stage)
    x = r + (N if variant & 2 else 0)
    if x >= P:
        return None
    base = lift_x(x, bool(variant & 1))
    if base is None:
        return None
    rinv = pow(r, N - 2, N)
    return [compress(point_mul(rinv * s % N, base)) for s, _, _ in menu(seed, stage)]


# ---- disclosure --------------------------------------------------------------
def disclosure_digest(round0: Sequence[int], round1: Sequence[int], picks: Sequence[int],
                      binding: bytes) -> bytes:
    return sha256(PROFILE + b"/reveal" + bytes(round0) + bytes(round1) + bytes(picks) + binding)


def legacy_sighash_all(tx_unsigned: bytes, script_code: bytes) -> bytes:
    """SIGHASH_ALL digest of the single input of `tx_unsigned` (its scriptSig empty)."""
    # version (4) || 0x01 || outpoint (36) || 0x00 || rest
    assert tx_unsigned[4] == 1 and tx_unsigned[41] == 0
    n = len(script_code)
    if n < 0xFD:
        size = bytes([n])
    else:
        size = b"\xfd" + n.to_bytes(2, "little")
    pre = tx_unsigned[:41] + size + script_code + tx_unsigned[42:] + (1).to_bytes(4, "little")
    return sha256(sha256(pre))


def response_items(seed: bytes, round0, round1, picks) -> List[bytes]:
    """What the device releases, before the co-signature and Q."""
    items = [hors(seed, j)[0] for j in round0] + [hors(seed, j)[1] for j in round1]
    items += [menu(seed, k)[p][1] for k, p in enumerate(picks)]
    return items


if __name__ == "__main__":
    seed = bytes(range(32))
    assert hors(seed, 0)[2].hex() == "be4e7023ab90e2e09e38891393626562c8feeae3"
    assert root(seed).hex() == "48629f7b1de16b950bbd36124838bc887b0b1c9e6735bf6c8c6b9214a6a3590d"
    print("ok")
