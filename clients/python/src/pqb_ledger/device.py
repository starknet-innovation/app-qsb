"""The PQB Ledger app's APDU protocol (docs/apdu.md), for pqb.

The app derives every vault from the device's own seed (BIP 85, then the BIP "PQB Wallet Secret
Management" profile `PQB-v1`, which is pqb's construction `v1`), so the secrets never exist on
this machine. pqb gets from it only:

  * public data: the 154 commitments, the locking script, the deposit address, each menu stage's
    `r`, and (after the user approves on the device) the solver's menu points;
  * one disclosure per vault, after the user approves the withdrawal on the device: the 8 + 9
    selected table preimages, the 3 picked menu signatures, the co-signature and its public key.

The device records each disclosure before releasing it and refuses a second, different one, so
pqb's own journal is no longer the only guard against a second witness. The adapter module turns
these into pqb objects.

Transport: anything with `exchange(apdu: bytes) -> bytes` returning the response data followed by
the two status bytes. `SpeculosTransport` talks to Speculos's REST API; `LedgercommTransport` to
a real device over USB, through the optional `ledgercomm` package.
"""
import hashlib
import json
import struct
import urllib.request

from pqb.errors import PqbError

CLA = 0xE0
PROFILE = b'PQB-v1'
TABLE = 109
COMMITMENTS = 154
MENU_WIDTHS = (12, 16, 16)
CHUNK = 255

INS_VERSION, INS_NAME = 0x03, 0x04
INS_COMMITMENTS, INS_VAULT, INS_SCRIPT, INS_DEPOSIT, INS_STATE = 0x10, 0x11, 0x12, 0x13, 0x14
INS_ALLOCATE, INS_RETIRE = 0x20, 0x21
INS_SIGN_DEPOSIT, INS_WITHDRAW, INS_REVEAL_READ, INS_MENU_POINTS = 0x30, 0x40, 0x41, 0x42

STATUS = {
    0x9000: 'OK', 0x6985: 'rejected on the device', 0x6A80: 'invalid data',
    0x6A86: 'wrong P1/P2', 0x6A87: 'wrong data length',
    0x6A90: 'conflict: a different disclosure or funding is recorded for this vault',
    0x6A91: 'no approved disclosure', 0x6A93: 'device state unreadable',
    0x6A94: "the vault's state does not allow this",
    0x6A95: 'no trustworthy history for this seed on the device',
    0x6A96: 'no room for another record on the device',
    0x6A97: 'menu points not authorized for this vault',
    0x6D00: 'unknown instruction (is the PQB app open?)', 0x6E00: 'wrong CLA',
    0xB001: 'command out of order', 0xB003: 'transaction could not be parsed',
    0xB004: 'previous transaction does not match the outpoint',
    0xB005: "an input does not spend the vault's deposit address",
    0xB006: "not this vault's locking script", 0xB007: 'unsupported transaction layout',
    0xB008: 'output the device cannot show', 0xB009: 'bad amount or non-positive fee',
    0xB00B: 'signing failed', 0xB00C: 'key derivation failed',
}

VAULT_STATUS = {0: 'not-allocated', 1: 'allocated', 2: 'exposed', 3: 'retired', 4: 'unknown',
                5: 'reserved', 6: 'no-history'}


class DeviceError(PqbError):
    def __init__(self, sw, what=''):
        self.sw = sw
        super().__init__('%sdevice refused (0x%04X): %s'
                         % (what + ': ' if what else '', sw, STATUS.get(sw, 'unknown status')))


# ---------------------------------------------------------------------------------- transports
class SpeculosTransport:
    """Speculos's REST API (`speculos --api-port N`)."""

    def __init__(self, url='http://127.0.0.1:5000', timeout=600):
        self.url = url.rstrip('/')
        self.timeout = timeout

    def exchange(self, apdu):
        req = urllib.request.Request(self.url + '/apdu', data=json.dumps({'data': apdu.hex()})
                                     .encode(), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return bytes.fromhex(json.load(r)['data'])


class LedgercommTransport:
    """A Ledger over USB HID, through `pip install ledgercomm[hid]`."""

    def __init__(self):
        try:
            from ledgercomm import Transport
        except ImportError as e:
            raise PqbError('talking to a Ledger needs `pip install "ledgercomm[hid]"`') from e
        self._t = Transport(interface='hid', debug=False)

    def exchange(self, apdu):
        sw, data = self._t.exchange_raw(apdu)
        return bytes(data) + struct.pack('>H', sw)


# ---------------------------------------------------------------------------------- helpers
def _u32be(v):
    if not 0 <= v < 2 ** 31:
        raise PqbError('a vault index is below 2^31')
    return struct.pack('>I', v)


def _varint(b, pos):
    n = b[pos]
    if n < 0xFD:
        return n, pos + 1
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[n]
    return int.from_bytes(b[pos + 1:pos + 1 + size], 'little'), pos + 1 + size


def strip_witness(raw):
    """The legacy serialization of a transaction (marker, flag and witnesses removed)."""
    raw = bytes(raw)
    if len(raw) < 6 or raw[4] != 0 or raw[5] != 1:
        return raw
    pos = 6
    n_in, pos = _varint(raw, pos)
    for _ in range(n_in):
        pos += 36
        n, pos = _varint(raw, pos)
        pos += n + 4
    n_out, pos = _varint(raw, pos)
    for _ in range(n_out):
        pos += 8
        n, pos = _varint(raw, pos)
        pos += n
    body_end = pos
    for _ in range(n_in):
        items, pos = _varint(raw, pos)
        for _ in range(items):
            n, pos = _varint(raw, pos)
            pos += n
    if pos + 4 != len(raw):
        raise PqbError('malformed segwit transaction')
    return raw[:4] + raw[6:body_end] + raw[pos:]


def parse_tx(raw):
    """(version, [(txid internal, vout, scriptSig, sequence)], outputs bytes, n_out, locktime) of a
    legacy-serialized transaction."""
    raw = strip_witness(raw)
    version = struct.unpack('<I', raw[:4])[0]
    pos = 4
    n_in, pos = _varint(raw, pos)
    ins = []
    for _ in range(n_in):
        txid, vout = raw[pos:pos + 32], struct.unpack('<I', raw[pos + 32:pos + 36])[0]
        pos += 36
        n, pos = _varint(raw, pos)
        script_sig = raw[pos:pos + n]
        pos += n
        ins.append((txid, vout, script_sig, struct.unpack('<I', raw[pos:pos + 4])[0]))
        pos += 4
    n_out, out_start = _varint(raw, pos)
    pos = out_start
    for _ in range(n_out):
        pos += 8
        n, pos = _varint(raw, pos)
        pos += n
    return version, ins, raw[out_start:pos], n_out, struct.unpack('<I', raw[pos:pos + 4])[0]


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Disclosure:
    """What the device released for one withdrawal."""

    def __init__(self, round0, round1, menu_sigs, cosig, pubkey, binding, digest):
        self.round0 = round0          # 8 x 20-byte preimages s[j]
        self.round1 = round1          # 9 x 32-byte preimages w[j] = SHA256(s[j])
        self.menu_sigs = menu_sigs    # 3 x DER || 0x01, stages 0, 1, 2
        self.cosig = cosig            # DER || 0x01
        self.pubkey = pubkey          # Q, 33 bytes
        self.binding = binding        # B = SHA256(T)
        self.digest = digest          # D = SHA256("PQB-v1/reveal" || I || B)


def disclosure_digest(round0, round1, picks, binding):
    return hashlib.sha256(PROFILE + b'/reveal' + bytes(round0) + bytes(round1) + bytes(picks)
                          + binding).digest()


# ---------------------------------------------------------------------------------- the app
class PqbDevice:
    """The PQB Ledger app's commands. Every response is checked for shape here; its meaning
    (commitments against the script, a disclosure against the commitments) is checked by the
    callers in lock.py and spend.py."""

    def __init__(self, transport):
        self.transport = transport

    def _send(self, ins, p1=0, data=b'', what=''):
        if len(data) > 255:
            raise PqbError('APDU payload over 255 bytes')
        resp = self.transport.exchange(bytes([CLA, ins, p1, 0, len(data)]) + bytes(data))
        if len(resp) < 2:
            raise PqbError('short response from the device')
        sw = int.from_bytes(resp[-2:], 'big')
        if sw != 0x9000:
            raise DeviceError(sw, what)
        return resp[:-2]

    def _stream(self, ins, p1, data, what):
        for i in range(0, len(data), CHUNK):
            self._send(ins, p1, data[i:i + CHUNK], what)

    # --- public data -----------------------------------------------------------------------
    def version(self):
        r = self._send(INS_VERSION)
        return '%d.%d.%d' % tuple(r[:3]), r[3:].decode()

    def app_name(self):
        return self._send(INS_NAME).decode()

    def check_app(self):
        name, (_, profile) = self.app_name(), self.version()
        if name != 'PQB' or profile != PROFILE.decode():
            raise PqbError('the device runs %r with profile %r, not the PQB app (%s)'
                           % (name, profile, PROFILE.decode()))

    def commitments(self, v):
        """The 154 commitments in root order: c[0..109], m_pin, m_round0, m_round1, q."""
        out = []
        for start in range(0, COMMITMENTS, 12):
            count = min(12, COMMITMENTS - start)
            r = self._send(INS_COMMITMENTS, 0, _u32be(v) + bytes([start, count]), 'commitments')
            if len(r) != 20 * count:
                raise PqbError('unexpected GET_COMMITMENTS response')
            out += [r[20 * k:20 * k + 20] for k in range(count)]
        return out

    def vault(self, v, display=False):
        r = self._send(INS_VAULT, int(display), _u32be(v), 'vault')
        if len(r) != 66:
            raise PqbError('unexpected GET_VAULT response')
        return {'root': r[:32], 'script_sha256': r[32:64],
                'status': VAULT_STATUS.get(r[64], 'status-%d' % r[64]), 'funded': bool(r[65])}

    def script(self, v):
        """The vault's locking script, 250 bytes per read."""
        out = b''
        while True:
            try:
                r = self._send(INS_SCRIPT, 0, _u32be(v) + struct.pack('>H', len(out)), 'script')
            except DeviceError as e:
                # A script whose length is a multiple of 250 ends with an out-of-range read.
                if e.sw == 0x6A80 and out and len(out) % 250 == 0:
                    return out
                raise
            out += r
            if len(r) < 250:
                return out

    def deposit(self, v, display=False):
        r = self._send(INS_DEPOSIT, int(display), _u32be(v), 'deposit address')
        n = r[33]
        return {'pubkey': r[:33], 'address': r[34:34 + n].decode()}

    def state(self):
        r = self._send(INS_STATE, 0, b'', 'state')
        return {'wallet_id': r[:16], 'namespace': {0: 'none', 1: 'fresh', 2: 'unknown'}[r[16]],
                'next_v': struct.unpack('>I', r[17:21])[0], 'records': r[21], 'capacity': r[22]}

    def allocate(self):
        """Reserve the next vault index on the device (the user approves there)."""
        r = self._send(INS_ALLOCATE, 0, b'', 'allocate')
        return {'v': struct.unpack('>I', r[:4])[0], 'root': r[4:36], 'script_sha256': r[36:68]}

    # --- solver data -----------------------------------------------------------------------
    def authorize_menu_points(self, v):
        """Ask the user to approve exporting vault v's menu points (and stage r's)."""
        self._send(INS_MENU_POINTS, 0, _u32be(v), 'menu points authorization')

    def menu_r(self, v, stage):
        r = self._send(INS_MENU_POINTS, 2, _u32be(v) + bytes([stage]), 'menu r')
        if len(r) != 32:
            raise PqbError('unexpected MENU_POINTS response')
        return int.from_bytes(r, 'big')

    def menu_points(self, v, stage, variant):
        """(r^-1 * x[i]) * R for every menu scalar of `stage`, R the recovery point `variant`
        (add_n << 1 | odd). None when that R does not exist. Compressed points."""
        out, width = [], MENU_WIDTHS[stage]
        for start in range(0, width, 7):
            count = min(7, width - start)
            try:
                r = self._send(INS_MENU_POINTS, 1,
                               _u32be(v) + bytes([stage, variant, start, count]), 'menu points')
            except DeviceError as e:
                if e.sw == 0x6A80 and start == 0:
                    return None
                raise
            if len(r) != 33 * count:
                raise PqbError('unexpected MENU_POINTS response')
            out += [r[33 * k:33 * k + 33] for k in range(count)]
        return out

    # --- deposit key -----------------------------------------------------------------------
    def sign_deposit(self, v, tx, prev_txs, sweep=True):
        """Signatures (DER || 0x01) for every input of `tx` (unsigned, spending vault v's deposit
        address), in order. `prev_txs` maps a txid (hex, display order) to its raw transaction.
        A sweep has one output, the vault's script; the device records the funding."""
        version, ins, outputs, n_out, locktime = parse_tx(tx)
        what = 'sweep' if sweep else 'refund'
        self._send(INS_SIGN_DEPOSIT, 0, bytes([1 if sweep else 2]) + _u32be(v)
                   + struct.pack('<II', version, locktime) + bytes([len(ins), n_out]), what)
        for txid, vout, _, seq in ins:
            prev = strip_witness(prev_txs[txid[::-1].hex()])
            self._send(INS_SIGN_DEPOSIT, 1, txid + struct.pack('<II', vout, seq), what)
            self._stream(INS_SIGN_DEPOSIT, 2, prev, what)
        self._stream(INS_SIGN_DEPOSIT, 3, outputs, what)
        self._send(INS_SIGN_DEPOSIT, 4, b'', what)
        return [self._send(INS_SIGN_DEPOSIT, 5, bytes([i]), what) for i in range(len(ins))]

    # --- the one disclosure ----------------------------------------------------------------
    def withdraw(self, v, tx, prev_tx, round0, round1, picks):
        """Disclose vault v's secrets for the withdrawal `tx` (one input, the vault output; its
        scriptSig empty). The user reviews the destinations and fee on the device first."""
        version, ins, outputs, n_out, locktime = parse_tx(tx)
        if len(ins) != 1 or ins[0][2]:
            raise PqbError('a PQB withdrawal has one input, with an empty scriptSig')
        txid, vout, _, seq = ins[0]
        if len(round0) != 8 or len(round1) != 9 or len(picks) != 3:
            raise PqbError('a disclosure is 8 + 9 table indices and 3 menu picks')
        self._send(INS_WITHDRAW, 0, _u32be(v) + struct.pack('<I', version) + txid
                   + struct.pack('<III', vout, seq, locktime) + bytes([n_out]) + bytes(round0)
                   + bytes(round1) + bytes(picks), 'withdraw')
        self._stream(INS_WITHDRAW, 1, strip_witness(prev_tx), 'withdraw')
        self._stream(INS_WITHDRAW, 2, outputs, 'withdraw')
        self._send(INS_WITHDRAW, 3, b'', 'withdraw')
        chunks = [self._send(INS_REVEAL_READ, c, b'', 'reveal') for c in range(5)]
        if len(chunks[0]) != 160 or len(chunks[1]) != 160 or len(chunks[2]) != 128:
            raise PqbError('unexpected REVEAL_READ response')
        s = [chunks[0][20 * k:20 * k + 20] for k in range(8)]
        w = [chunks[1][32 * k:32 * k + 32] for k in range(5)]
        w += [chunks[2][32 * k:32 * k + 32] for k in range(4)]
        g, pos = [], 0
        for _ in range(3):
            n = chunks[3][pos]
            g.append(chunks[3][pos + 1:pos + 1 + n])
            pos += 1 + n
        n = chunks[4][0]
        cosig, q = chunks[4][1:1 + n], chunks[4][1 + n:]
        if pos != len(chunks[3]) or len(q) != 33:
            raise PqbError('unexpected REVEAL_READ response')
        t = bytes(strip_witness(tx))
        binding = hashlib.sha256(t).digest()
        return Disclosure(s, w, g, cosig, q, binding,
                          disclosure_digest(round0, round1, picks, binding))
