"""Minimal Bitcoin helpers for the functional tests.

Written independently of the app so the tests check its output rather than
repeat its logic: transaction serialization, BIP-143 and BIP-322 digests,
addresses and signature checks.
"""

import hashlib
import struct
from dataclasses import dataclass
from typing import List, Optional

from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))


def _ripemd160(msg: bytes) -> bytes:
    """Pure-Python RIPEMD-160: OpenSSL 3 builds of hashlib may not offer it."""
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def f(j, x, y, z):
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & z)
        if j < 48:
            return (x | ~y) ^ z
        if j < 64:
            return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    kl = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    kr = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    rl = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
          7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
          1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    rr = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    sl = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
          7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
          11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    sr = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    padded = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64) + struct.pack("<Q", 8 * len(msg))
    for off in range(0, len(padded), 64):
        x = struct.unpack("<16I", padded[off:off + 64])
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            t = (rol((al + f(j, bl, cl, dl) + x[rl[j]] + kl[j // 16]) & 0xFFFFFFFF, sl[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = (rol((ar + f(79 - j, br, cr, dr) + x[rr[j]] + kr[j // 16]) & 0xFFFFFFFF, sr[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        t = (h[1] + cl + dr) & 0xFFFFFFFF
        h[1] = (h[2] + dl + er) & 0xFFFFFFFF
        h[2] = (h[3] + el + ar) & 0xFFFFFFFF
        h[3] = (h[4] + al + br) & 0xFFFFFFFF
        h[4] = (h[0] + bl + cr) & 0xFFFFFFFF
        h[0] = t
    return struct.pack("<5I", *h)


def hash160(b: bytes) -> bytes:
    return _ripemd160(sha256(b))


def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


@dataclass
class TxIn:
    txid: bytes  # serialization (internal) byte order
    vout: int
    sequence: int = 0xFFFFFFFE
    script_sig: bytes = b""

    def outpoint(self) -> bytes:
        return self.txid + struct.pack("<I", self.vout)


@dataclass
class TxOut:
    value: int
    script: bytes

    def serialize(self) -> bytes:
        return struct.pack("<Q", self.value) + compact_size(len(self.script)) + self.script


@dataclass
class Tx:
    version: int
    inputs: List[TxIn]
    outputs: List[TxOut]
    locktime: int = 0

    def serialize(self) -> bytes:
        """Legacy serialization: what the txid commits to and the app expects."""
        out = struct.pack("<I", self.version) + compact_size(len(self.inputs))
        for i in self.inputs:
            out += i.outpoint() + compact_size(len(i.script_sig)) + i.script_sig + struct.pack("<I", i.sequence)
        out += compact_size(len(self.outputs)) + b"".join(o.serialize() for o in self.outputs)
        return out + struct.pack("<I", self.locktime)

    def txid(self) -> bytes:
        return sha256d(self.serialize())

    def outputs_bytes(self) -> bytes:
        return b"".join(o.serialize() for o in self.outputs)


def p2wpkh_script(pkh: bytes) -> bytes:
    return b"\x00\x14" + pkh


def p2sh_script(h: bytes) -> bytes:
    return b"\xa9\x14" + h + b"\x87"


def wallet_script(pubkey: bytes, nested: bool) -> bytes:
    witness = p2wpkh_script(hash160(pubkey))
    return p2sh_script(hash160(witness)) if nested else witness


def bip143_sighash(tx: Tx, index: int, pkh: bytes, amount: int) -> bytes:
    hash_prevouts = sha256d(b"".join(i.outpoint() for i in tx.inputs))
    hash_sequence = sha256d(b"".join(struct.pack("<I", i.sequence) for i in tx.inputs))
    hash_outputs = sha256d(tx.outputs_bytes())
    i = tx.inputs[index]
    preimage = (
        struct.pack("<I", tx.version) + hash_prevouts + hash_sequence + i.outpoint()
        + b"\x19\x76\xa9\x14" + pkh + b"\x88\xac"
        + struct.pack("<Q", amount) + struct.pack("<I", i.sequence)
        + hash_outputs + struct.pack("<I", tx.locktime) + struct.pack("<I", 1)
    )
    return sha256d(preimage)


def bip322_sighash(message: bytes, script_pubkey: bytes, pkh: bytes) -> bytes:
    tag = sha256(b"BIP0322-signed-message")
    message_hash = sha256(tag + tag + message)
    to_spend = Tx(0, [TxIn(b"\x00" * 32, 0xFFFFFFFF, 0, b"\x00\x20" + message_hash)], [TxOut(0, script_pubkey)])
    to_sign = Tx(0, [TxIn(to_spend.txid(), 0, 0)], [TxOut(0, b"\x6a")])
    return bip143_sighash(to_sign, 0, pkh, 0)


HALF_N = SECP256k1.order // 2


def verify(pubkey: bytes, digest: bytes, signature: bytes) -> None:
    """Check `signature` (DER || 0x01) is a valid low-S SIGHASH_ALL signature of `digest`."""
    assert signature[-1] == 0x01, "SIGHASH_ALL"
    der = signature[:-1]
    r, s = sigdecode_der(der, SECP256k1.order)
    assert s <= HALF_N, "low S"
    key = VerifyingKey.from_string(pubkey, curve=SECP256k1)
    assert key.verify_digest(der, digest, sigdecode=sigdecode_der)


_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def segwit_address(version: int, program: bytes) -> str:
    data, acc, bits = [version], 0, 0
    for b in program:
        acc, bits = (acc << 8) | b, bits + 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    const = 1 if version == 0 else 0x2BC830A3
    hrp = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    chk = _polymod(hrp + data + [0] * 6) ^ const
    return "bc1" + "".join(_BECH32[d] for d in data) + "".join(_BECH32[(chk >> 5 * (5 - i)) & 31] for i in range(6))


def base58check(version: int, payload: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    data = bytes([version]) + payload
    data += sha256d(data)[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def address(script: bytes) -> Optional[str]:
    if len(script) == 22 and script[:2] == b"\x00\x14":
        return segwit_address(0, script[2:])
    if len(script) == 34 and script[:2] == b"\x00\x20":
        return segwit_address(0, script[2:])
    if len(script) == 34 and script[:2] == b"\x51\x20":
        return segwit_address(1, script[2:])
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[22] == 0x87:
        return base58check(5, script[2:22])
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac":
        return base58check(0, script[3:23])
    return None
