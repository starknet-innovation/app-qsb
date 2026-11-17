"""An in-process stand-in for the PQB Ledger app, for the device tests.

It speaks the app's APDU protocol (docs/apdu.md of the app) for one seed, from pqb's own build of
that seed: it holds the secrets a real device would, and releases them the way the app does
(one disclosure per vault, recorded before anything leaves, exact retries only). The protocol
parsing in pqb.device is exercised byte for byte; what is NOT exercised is the app's own
derivation, which test_device.py checks against a real app on Speculos when $PQB_SPECULOS is set.

It derives nothing itself: everything comes from pqb's `Lock.build` at the given seeds.
"""
import hashlib
import struct

import coincurve

from pqb import _research  # noqa: F401
from pqb.configs import get
from pqb.lock import Lock
from pqb_ledger.adapter import _root_order
from test_framework.messages import CTransaction, from_hex
from test_framework.script import CScript, LegacySignatureHash, SIGHASH_ALL

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 2 ** 256 - 2 ** 32 - 977


def lift_x(x, odd):
    if not 0 < x < P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    return coincurve.PublicKey(bytes([3 if odd else 2]) + x.to_bytes(32, 'big'))


class FakeDevice:
    """`exchange(apdu) -> data || sw` for vault seeds {v: seed}."""

    def __init__(self, seeds, approve=True):
        self.locks = {v: Lock.build(get(), s) for v, s in seeds.items()}
        self.approve = approve
        self.authorized = None
        self.records = {}         # v -> digest of the recorded disclosure
        self.session = None
        self.chunks = None
        self.log = []

    def exchange(self, apdu):
        cla, ins, p1, p2, n = apdu[:5]
        data = apdu[5:5 + n]
        self.log.append((ins, p1))
        try:
            return self._handle(ins, p1, data) + b'\x90\x00'
        except _Sw as e:
            return struct.pack('>H', e.sw)

    def _lock(self, data):
        v = struct.unpack('>I', data[:4])[0]
        if v not in self.locks:
            raise _Sw(0x6A80)
        return v, self.locks[v]

    def _handle(self, ins, p1, data):
        if ins == 0x03:
            return bytes([0, 2, 0]) + b'PQB-v1'
        if ins == 0x04:
            return b'PQB'
        if ins == 0x10:
            _, lock = self._lock(data)
            start, count = data[4], data[5]
            return b''.join(_root_order(lock._res)[start:start + count])
        if ins == 0x11:
            _, lock = self._lock(data)
            root = hashlib.sha256(b'PQB-v1/root' + b''.join(_root_order(lock._res))).digest()
            return root + hashlib.sha256(lock.script).digest() + bytes([1, 0])
        if ins == 0x12:
            _, lock = self._lock(data)
            off = struct.unpack('>H', data[4:6])[0]
            if off >= len(lock.script):
                raise _Sw(0x6A80)
            return lock.script[off:off + 250]
        if ins == 0x42:
            return self._menu(p1, data)
        if ins == 0x40:
            return self._withdraw(p1, data)
        if ins == 0x41:
            if self.chunks is None:
                raise _Sw(0x6A91)
            out = self.chunks[p1]
            if p1 == 4:
                self.chunks = None
            return out
        raise _Sw(0x6D00)

    def _menu(self, p1, data):
        v, lock = self._lock(data)
        if p1 == 0:
            if not self.approve:
                raise _Sw(0x6985)
            self.authorized = v
            return b''
        if self.authorized != v:
            raise _Sw(0x6A97)
        stage = data[4]
        menu = lock._res['menu'] if stage == 0 else lock._res['rmenu'][stage - 1]
        if p1 == 2:
            return menu['r'].to_bytes(32, 'big')
        variant, start, count = data[5], data[6], data[7]
        base = lift_x(menu['r'] + (N if variant & 2 else 0), bool(variant & 1))
        if base is None:
            raise _Sw(0x6A80)
        rinv = pow(menu['r'], N - 2, N)
        return b''.join(base.multiply((rinv * s % N).to_bytes(32, 'big')).format(True)
                        for s in menu['s'][start:start + count])

    def _withdraw(self, p1, data):
        if p1 == 0:
            v, lock = self._lock(data)
            self.session = {'v': v, 'lock': lock, 'start': data, 'prev': b'', 'outs': b''}
            return b''
        s = self.session
        if s is None:
            raise _Sw(0xB001)
        if p1 == 1:
            s['prev'] += data
            return b''
        if p1 == 2:
            s['outs'] += data
            return b''
        # REVIEW: rebuild T, check the vault output, record, release.
        st = s['start']
        version, txid, vout, seq, lt = struct.unpack('<I', st[4:8])[0], st[8:40], \
            struct.unpack('<I', st[40:44])[0], struct.unpack('<I', st[44:48])[0], \
            struct.unpack('<I', st[48:52])[0]
        n_out, r0, r1, picks = st[52], list(st[53:61]), list(st[61:70]), list(st[70:73])
        prev = from_hex(CTransaction(), s['prev'].hex())
        if (bytes.fromhex(prev.txid_hex)[::-1] != txid
                or prev.vout[vout].scriptPubKey != s['lock'].script):
            raise _Sw(0xB006)
        t = (struct.pack('<I', version) + b'\x01' + txid + struct.pack('<I', vout) + b'\x00'
             + struct.pack('<I', seq) + bytes([n_out]) + s['outs'] + struct.pack('<I', lt))
        b = hashlib.sha256(t).digest()
        digest = hashlib.sha256(b'PQB-v1/reveal' + bytes(r0 + r1 + picks) + b).digest()
        if s['v'] in self.records and self.records[s['v']] != digest:
            raise _Sw(0x6A90)
        if not self.approve:
            raise _Sw(0x6985)
        self.records[s['v']] = digest
        res = s['lock']._res
        tx = from_hex(CTransaction(), t.hex())
        z = LegacySignatureHash(CScript(s['lock'].script), tx, 0, SIGHASH_ALL)[0]
        key = coincurve.PrivateKey(res['cosig']['d'].to_bytes(32, 'big'))
        cosig = key.sign(z, hasher=None) + b'\x01'
        menus = (res['menu'], res['rmenu'][0], res['rmenu'][1])
        g = b''.join(bytes([len(m['sigs'][p])]) + m['sigs'][p] for m, p in zip(menus, picks))
        w = [res['wit'][1][j] for j in r1]
        self.chunks = [b''.join(res['wit'][0][j] for j in r0), b''.join(w[:5]), b''.join(w[5:]),
                       g, bytes([len(cosig)]) + cosig + res['cosig']['pk']]
        self.session = None
        return b''


class _Sw(Exception):
    def __init__(self, sw):
        self.sw = sw
