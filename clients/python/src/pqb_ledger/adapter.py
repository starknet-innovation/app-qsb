"""pqb vaults whose secrets the PQB Ledger app holds.

pqb builds a vault from its 32-byte seed. The app keeps that seed on the device, so these functions
build the same pqb objects from what the device exports, without changing pqb:

  * `lock_from_device`: the vault's `Lock`. Only the 154 commitments (and so the script) depend on
    the seed; every puzzle, ladder and dummy-signature value is the same in every vault of pqb's
    construction `v1`. So the structure comes from building `v1` once at a fixed, public
    placeholder seed, and the device's commitments replace the placeholder's. The result must
    equal, byte for byte, the script the device reports, whose SHA-256 and root it vouches for.
  * `solver_stages`: `pqb.grind.stages_from_lock`, with each menu stage's `r` and points from the
    device (exported after the user approves on it) instead of computed from secret scalars.
  * `assemble_spend`: `pqb.spend.Spend.assemble`, with the secrets of the device's one disclosure
    (approved on the device), each checked against the script's commitments first.

These reach into pqb internals (`Lock._res`, `Stage` fields, the vendored assembler's
`cosig_sign`), which pqb does not promise to keep. `check_pqb` pins the construction they were
written for and refuses any other, and the tests compare every result with pqb's own seed path.
"""
import copy
import hashlib

import coincurve
from pqb import _research  # noqa: F401  (puts pqb's vendored modules on sys.path)
from pqb import grind
from pqb.configs import get as get_config
from pqb.errors import NotVerified, PqbError, VaultError
from pqb.lock import Lock
from pqb.spend import Spend

from .device import PqbDevice  # noqa: F401  (re-exported for callers)

#: The pqb construction the app derives (BIP profile PQB-v1), and the upstream commit this adapter
#: was checked against.
PQB_VERSION = 'v1'
PQB_COMMIT = 'bb2ddcad5b43ca5c603b3c4054c334cde7e19c47'

#: A public placeholder seed: the shared structure comes from a build at it. Never funded.
STRUCTURE_SEED = hashlib.sha256(b'pqb/device-lock-structure').digest()
#: SHA-256 of pqb v1's script at STRUCTURE_SEED, at PQB_COMMIT. Any change to the construction
#: changes it.
STRUCTURE_SHA256 = '0c2a575aed25088d452d88483de9e06e410ac79a73cd48c0a4f2b5d5c67711cd'

HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0

_checked = {}


def _shell(config):
    if config.version not in _checked:
        if config.version != PQB_VERSION:
            raise VaultError('the PQB Ledger app derives construction %s, not %s'
                             % (PQB_VERSION, config.version))
        shell = Lock.build(config, STRUCTURE_SEED)
        if hashlib.sha256(shell.script).hexdigest() != STRUCTURE_SHA256:
            raise PqbError('this pqb builds construction %s differently from commit %s, which '
                           'pqb_ledger was checked against: refusing to use it'
                           % (PQB_VERSION, PQB_COMMIT[:7]))
        _checked[config.version] = shell
    return _checked[config.version]


def check_pqb(config=None):
    """Raise unless the installed pqb builds construction v1 exactly as PQB_COMMIT does."""
    _shell(config or get_config(None, PQB_VERSION))


def _root_order(res):
    """A build's 154 commitments in root order: c[0..109], m_pin, m_round0, m_round1, q."""
    return (list(res['comm'][0]) + list(res['menu']['comm']) + list(res['rmenu'][0]['comm'])
            + list(res['rmenu'][1]['comm']) + [res['cosig']['h160']])


def _swap(script, old, new):
    """`script` with each 20-byte push of a commitment in `old` replaced by its `new` one."""
    out = bytearray(script)
    for a, b in zip(old, new):
        at = script.find(b'\x14' + a)
        if at < 0 or script.find(b'\x14' + a, at + 1) >= 0:
            raise VaultError('commitment not found exactly once in the script')
        out[at + 1:at + 21] = b
    return bytes(out)


class DeviceLock(Lock):
    """A pqb `Lock` whose secrets stay on the device. It holds none: no seed, no preimage, no
    menu scalar, no co-signing key."""

    def __init__(self, config, res, device, index):
        super().__init__(config, None, res)
        self.device = device
        self.device_index = index

    held_by_device = True

    @property
    def seed_fingerprint(self):
        return 'DEVICE-HELD'

    def assert_fundable(self, network):
        # The app binds every vault seed to mainnet: funding (and later disclosing) the same index
        # anywhere else would spend that mainnet vault's one disclosure.
        if network != 'main':
            raise VaultError('a device-held vault is a mainnet vault; refusing to fund it on %r'
                             % network)

    def save(self, directory):
        raise VaultError('a device-held vault has no seed to save; rebuild it with '
                         'lock_from_device')


def lock_from_device(device, index, config=None):
    """The `Lock` of vault `index` on the device, checked against the script, script hash and root
    the device reports."""
    config = config or get_config(None, PQB_VERSION)
    shell = _shell(config)
    device.check_app()
    cs = [bytes(c) for c in device.commitments(index)]
    info = device.vault(index)
    script = bytes(device.script(index))
    if len(cs) != 154 or len(set(cs)) != 154:
        raise VaultError('the device returned %d commitments, %d distinct; expected 154'
                         % (len(cs), len(set(cs))))
    old = _root_order(shell._res)
    if script != _swap(shell.script, old, cs):
        raise VaultError('the script the device reports is not construction %s with its own '
                         'commitments' % config.version)
    if hashlib.sha256(script).digest() != info['script_sha256']:
        raise VaultError("the device's script does not hash to the script hash it reports")
    if hashlib.sha256(b'PQB-v1/root' + b''.join(cs)).digest() != info['root']:
        raise VaultError("the device's commitments do not hash to the root it reports")

    res = copy.deepcopy(shell._res)
    res['script'] = script
    res['comm'] = [cs[:109], cs[:109]]
    res['menu']['comm'] = cs[109:121]
    res['rmenu'][0]['comm'] = cs[121:137]
    res['rmenu'][1]['comm'] = cs[137:153]
    res['cosig']['h160'] = cs[153]
    # The placeholder's secrets go: only a disclosure fills the ones a spend needs.
    res['wit'] = [[None] * 109, [None] * 109]
    for m in (res['menu'], res['rmenu'][0], res['rmenu'][1]):
        m['s'] = [None] * len(m['s'])
        m['sigs'] = [None] * len(m['sigs'])
    res['cosig']['d'] = None
    res['cosig']['pk'] = None
    res['params']['seed'] = None
    man = res['manifest']
    man['params']['seed'] = None
    man['script_hex'] = script.hex()
    man['cosig']['pubkey_hash160'] = cs[153].hex()
    man['tables']['commitments'] = [c.hex() for c in cs[:109]]
    man['tables']['menu_commitments'] = [c.hex() for c in cs[109:121]]
    swap = dict(zip(old, cs))
    for e in man['emissions']:
        d = bytes.fromhex(e.get('data') or '')
        if d in swap:
            e['data'] = swap[d].hex()
            e['enc'] = e['enc'].replace(d.hex(), swap[d].hex())
    return DeviceLock(config, res, device, index)


def solver_stages(lock, menu_point_budget=None):
    """`pqb.grind.stages_from_lock` for a device-held lock: the stages of the shared structure,
    with each menu stage's `r` and points from the device. Call `lock.device.authorize_menu_points`
    first (the user approves on the device)."""
    stages = grind.stages_from_lock(_shell(lock.config), menu_point_budget=menu_point_budget)
    dev, v = lock.device, lock.device_index
    for i, st in enumerate(stages):
        if not st.menu_r:
            continue
        if dev.menu_r(v, i) != st.menu_r['r']:
            raise grind.GrindError('the device reports a different r for stage %d' % i)
        budget = st.menu_r['disclosed']
        for var in st.menu_points:
            got = dev.menu_points(v, i, (2 if var['add_n'] else 0) | int(var['odd']))
            if got is None:
                raise grind.GrindError('the device has no recovery point %r for stage %d'
                                       % ((var['add_n'], var['odd']), i))
            var['points'] = [coincurve.PublicKey(c).format(False).hex() for c in got[:budget]]
        st.menu_r['variants'] = st.menu_points
    return stages


def _der_rs(sig):
    """(r, s) of a strict-DER ECDSA signature followed by its hashtype byte."""
    der = sig[:-1]
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2 or der[2] != 0x02:
        raise NotVerified('malformed DER signature from the device')
    rl = der[3]
    if der[4 + rl] != 0x02:
        raise NotVerified('malformed DER signature from the device')
    sl = der[5 + rl]
    if 6 + rl + sl != len(der):
        raise NotVerified('malformed DER signature from the device')
    return int.from_bytes(der[4:4 + rl], 'big'), int.from_bytes(der[6 + rl:6 + rl + sl], 'big')


def _filled(lock, selection, picks, d):
    """A copy of the lock's build with the disclosed secrets filled in, each checked against the
    commitment the script holds, and the co-signer that hands the device's signature to the
    assembler once it verifies over the assembler's own sighash."""

    def h160(b):
        return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

    res = copy.deepcopy(lock._res)
    rows = [list(selection[0]), list(selection[1])]
    if [len(rows[0]), len(rows[1])] != [len(d.round0), len(d.round1)]:
        raise NotVerified('the disclosure has the wrong number of preimages')
    for j, s in zip(rows[0], d.round0):
        if len(s) != 20 or h160(s) != res['comm'][0][j]:
            raise NotVerified('round-0 preimage %d does not open its commitment' % j)
        res['wit'][0][j] = s
    for j, w in zip(rows[1], d.round1):
        if len(w) != 32 or hashlib.new('ripemd160', w).digest() != res['comm'][1][j]:
            raise NotVerified('round-1 preimage %d does not open its commitment' % j)
        res['wit'][1][j] = w
    for menu, p, g in zip((res['menu'], res['rmenu'][0], res['rmenu'][1]), picks, d.menu_sigs):
        if g[-1:] != b'\x01' or hashlib.sha1(g).digest() != menu['comm'][p]:
            raise NotVerified('menu signature %d does not open its commitment' % p)
        r, s = _der_rs(g)
        if r != menu['r']:
            raise NotVerified('menu signature %d has the wrong r' % p)
        menu['sigs'][p], menu['s'][p] = g, s
    if len(d.pubkey) != 33 or h160(d.pubkey) != res['cosig']['h160']:
        raise NotVerified('the co-signing key is not the one the script commits to')
    res['cosig']['pk'] = d.pubkey

    def cosign(_d, z):
        sig = d.cosig
        if sig[-1:] != b'\x01' or _der_rs(sig)[1] > HALF_N:
            raise NotVerified('the co-signature is not low-S SIGHASH_ALL')
        key = coincurve.PublicKey(d.pubkey)
        if not key.verify(sig[:-1], z.to_bytes(32, 'big'), hasher=None):
            raise NotVerified('the co-signature does not sign this transaction')
        return sig
    return res, cosign


def unsigned_tx(funding, outputs, locktime=0, version=2, sequence=0xFFFFFFFF, pin_nonce=None):
    """The withdrawal `T` exactly as `Spend.assemble` builds it, before its scriptSig."""
    from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
    if pin_nonce is not None:
        locktime, sequence = grind.pin_fields(pin_nonce)
    tx = CTransaction()
    tx.version = version
    tx.nLockTime = locktime
    tx.vin.append(CTxIn(COutPoint(int(funding['txid'], 16), funding['vout']), b'', sequence))
    for amount, spk in outputs:
        tx.vout.append(CTxOut(int(amount), bytes(spk)))
    return tx.serialize_without_witness()


def assemble_spend(lock, funding, outputs, funding_tx, selection=None, menu_pick=None, **kw):
    """`Spend.assemble` for a device-held lock. The device shows the destinations and fee and
    discloses after the user approves; `funding_tx` (raw, hex or bytes) is the transaction that
    created the vault output, which the device checks against the outpoint and its own script.

    `selection`, `menu_pick` and the remaining keywords (`pin_nonce`, `hash_pick`, `puzzle_keys`,
    `locktime`, `sequence`, `version`, `oracle`) are `Spend.assemble`'s."""
    import l1run
    if kw.get('n_in', 0) != 0:
        raise VaultError('a device-held vault is spent by a one-input transaction')
    selection = selection or l1run.default_subsets(lock._res['params'])
    menu_pick = dict(menu_pick or {})
    picks = [menu_pick.get('pin', 0), menu_pick.get(0, 0), menu_pick.get(1, 0)]
    t = unsigned_tx(funding, outputs, **{k: kw[k] for k in
                                         ('locktime', 'version', 'sequence', 'pin_nonce')
                                         if k in kw})
    raw = bytes.fromhex(funding_tx) if isinstance(funding_tx, str) else bytes(funding_tx)
    disclosure = lock.device.withdraw(lock.device_index, t, raw, list(selection[0]),
                                      list(selection[1]), picks)
    res, cosign = _filled(lock, selection, picks, disclosure)
    filled = DeviceLock(lock.config, res, lock.device, lock.device_index)

    prev = l1run.cosig_sign
    l1run.cosig_sign = cosign
    try:
        sp = Spend.assemble(filled, funding, outputs, selection=selection, menu_pick=menu_pick,
                            **kw)
    finally:
        l1run.cosig_sign = prev
    # The transaction pqb built must be the one the device approved.
    signed = copy.deepcopy(sp.tx)
    signed.vin[0].scriptSig = b''
    if signed.serialize_without_witness() != t:
        raise NotVerified('pqb built a different transaction from the one the device approved')
    return sp
