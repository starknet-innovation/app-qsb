"""pqb vaults held by the PQB Ledger app (pqb_ledger).

A device-held vault must be indistinguishable from the same vault built from its seed: the same
script, the same solver packets, and, given the same grind result, the same scriptSig. These tests
hold the device path to that against FakeDevice (the app's protocol over pqb's own secrets), and,
with $PQB_SPECULOS set to a Speculos API URL running the app, against the real app.
"""
import hashlib
import os
import unittest

from pqb import _research  # noqa: F401
from pqb import bip85, grind
from pqb.configs import get
from pqb.errors import NotVerified, PqbError, PublicSeed, VaultError
from pqb.lock import Lock
from pqb.spend import Spend
from pqb_ledger import adapter
from pqb_ledger import (DeviceError, PqbDevice, SpeculosTransport, assemble_spend, check_pqb,
                        lock_from_device, solver_stages)
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut

from fake_device import FakeDevice

SEED = bytes(range(32))
DEST = [(90_000, bytes.fromhex('0014' + '42' * 20)), (5_000, bytes.fromhex('5120' + '17' * 32))]


def funding_tx(script, amount=100_000):
    tx = CTransaction()
    tx.version = 2
    tx.vin = [CTxIn(COutPoint(int('5a' * 32, 16), 3), b'', 0xfffffffd)]
    tx.vout = [CTxOut(1_000, bytes.fromhex('0014' + '01' * 20)), CTxOut(amount, script)]
    return tx


def device(**kw):
    return PqbDevice(FakeDevice({7: SEED}, **kw))


class TestPinnedPqb(unittest.TestCase):
    def test_the_installed_pqb_is_the_checked_one(self):
        check_pqb()

    def test_another_construction_is_refused(self):
        saved = dict(adapter._checked)
        adapter._checked.clear()
        real = adapter.STRUCTURE_SHA256
        adapter.STRUCTURE_SHA256 = '00' * 32
        try:
            with self.assertRaises(PqbError):
                check_pqb()
        finally:
            adapter.STRUCTURE_SHA256 = real
            adapter._checked.update(saved)


class TestLockFromDevice(unittest.TestCase):
    def test_the_same_lock_as_the_seed_builds(self):
        local = Lock.build(get(), SEED)
        held = lock_from_device(device(), 7)
        self.assertEqual(held.script, local.script)
        self.assertEqual(held.sha256, local.sha256)
        self.assertEqual(held.cosig_hash160, local.cosig_hash160)
        self.assertTrue(held.held_by_device)
        self.assertEqual(held.seed_fingerprint, 'DEVICE-HELD')
        with self.assertRaises(VaultError):
            held.save('/nonexistent')
        # Nothing secret on this side.
        res = held._res
        self.assertIsNone(res['cosig']['d'])
        self.assertTrue(all(w is None for row in res['wit'] for w in row))
        self.assertTrue(all(s is None for m in [res['menu']] + res['rmenu'] for s in m['s']))
        self.assertIsNone(held.seed)
        self.assertNotIn(SEED.hex(), repr(res['manifest']))

    def test_a_script_the_device_did_not_vouch_for_is_refused(self):
        dev = device()
        real = dev.transport.locks[7]
        dev.transport.locks[7] = Lock.build(get(), bytes(32))      # commitments of another seed
        good_vault = dev.vault

        def lying_vault(v, display=False):          # ...vouched for with the real script's hash
            out = good_vault(v, display)
            out['script_sha256'] = hashlib.sha256(real.script).digest()
            return out
        dev.vault = lying_vault
        with self.assertRaises(VaultError):
            lock_from_device(dev, 7)

    def test_only_on_mainnet(self):
        held = lock_from_device(device(), 7)
        held.assert_fundable('main')
        for net in ('regtest', 'testnet4', 'signet'):
            with self.assertRaises(VaultError):
                held.assert_fundable(net)
        with self.assertRaises(PublicSeed):
            Lock.reproduce().assert_fundable('main')


class TestSolverExport(unittest.TestCase):
    def test_same_packets_from_the_devices_points(self):
        dev = device()
        held = lock_from_device(dev, 7)
        with self.assertRaises(DeviceError) as e:
            solver_stages(held)
        self.assertEqual(e.exception.sw, 0x6A97)          # not authorized yet
        dev.authorize_menu_points(7)
        want = grind.stages_from_lock(Lock.build(get(), SEED))
        got = solver_stages(held)
        self.assertEqual([s.menu_r for s in got], [s.menu_r for s in want])
        self.assertEqual([s.menu_points for s in got], [s.menu_points for s in want])
        for budget in (1, 5):
            self.assertEqual(
                [s.menu_points for s in solver_stages(held, menu_point_budget=budget)],
                [s.menu_points for s in grind.stages_from_lock(Lock.build(get(), SEED),
                                                               menu_point_budget=budget)])


class TestDisclosure(unittest.TestCase):
    SEL = [[1, 4, 9, 16, 25, 36, 49, 64], [0, 2, 3, 5, 7, 11, 13, 17, 19]]
    PICK = {'pin': 11, 0: 0, 1: 15}

    def assemble(self, lock, ftx, funding_tx=None):
        funding = {'txid': ftx.txid_hex, 'vout': 1, 'amount': 100_000}
        if funding_tx is None:
            return Spend.assemble(lock, funding, DEST, selection=self.SEL, menu_pick=self.PICK,
                                  pin_nonce=123456789)
        return assemble_spend(lock, funding, DEST, funding_tx, selection=self.SEL,
                              menu_pick=self.PICK, pin_nonce=123456789)

    def test_same_scriptsig_as_the_seed_builds(self):
        local = Lock.build(get(), SEED)
        ftx = funding_tx(local.script)
        want = self.assemble(local, ftx)
        dev = device()
        got = self.assemble(lock_from_device(dev, 7), ftx, funding_tx=ftx.serialize())
        self.assertEqual(got.raw_hex, want.raw_hex)
        self.assertEqual(got.revealed_secrets, want.revealed_secrets)
        # One disclosure: the exact same request again is a retry, anything else a conflict.
        again = self.assemble(lock_from_device(dev, 7), ftx, funding_tx=ftx.serialize())
        self.assertEqual(again.raw_hex, want.raw_hex)
        funding = {'txid': ftx.txid_hex, 'vout': 1, 'amount': 100_000}
        with self.assertRaises(DeviceError) as e:
            assemble_spend(lock_from_device(dev, 7), funding, DEST, ftx.serialize(),
                           selection=self.SEL, menu_pick=dict(self.PICK, pin=10),
                           pin_nonce=123456789)
        self.assertEqual(e.exception.sw, 0x6A90)

    def test_rejected_on_the_device(self):
        local = Lock.build(get(), SEED)
        ftx = funding_tx(local.script)
        with self.assertRaises(DeviceError) as e:
            self.assemble(lock_from_device(device(approve=False), 7), ftx,
                          funding_tx=ftx.serialize())
        self.assertEqual(e.exception.sw, 0x6985)

    def test_pqbs_own_assembler_has_no_secrets_to_use(self):
        # Without the adapter, pqb's assembler meets an empty lock and cannot spend it.
        held = lock_from_device(device(), 7)
        with self.assertRaises(Exception):
            self.assemble(held, funding_tx(held.script))

    def test_every_released_item_is_checked(self):
        local = Lock.build(get(), SEED)
        ftx = funding_tx(local.script)

        def tamper(chunk, at):
            dev = device()
            fake = dev.transport
            orig = fake._withdraw

            def withdraw(p1, data):
                out = orig(p1, data)
                if p1 == 3:
                    c = bytearray(fake.chunks[chunk])
                    c[at] ^= 1
                    fake.chunks[chunk] = bytes(c)
                return out
            fake._withdraw = withdraw
            return dev
        # round-0 preimage, round-1 preimage, a menu signature's s, the co-signature, Q.
        for chunk, at in [(0, 3), (1, 40), (2, 100), (3, 60), (4, 20), (4, 80)]:
            with self.subTest(chunk=chunk, at=at):
                with self.assertRaises(NotVerified):
                    self.assemble(lock_from_device(tamper(chunk, at), 7), ftx,
                                  funding_tx=ftx.serialize())


SPECULOS = os.environ.get('PQB_SPECULOS')
SPECULOS_MNEMONIC = ('glory promote mansion idle axis finger extra february uncover one trip '
                     'resource lawn turtle enact monster seven myth punch hobby comfort wild '
                     'raise skin')


@unittest.skipUnless(SPECULOS, 'set PQB_SPECULOS to a Speculos API URL running the PQB app')
class TestRealApp(unittest.TestCase):
    """Read-only checks against the real app: its derivation is pqb's."""

    def test_the_apps_vaults_are_pqb_vaults(self):
        dev = PqbDevice(SpeculosTransport(SPECULOS))
        root = bip85.root_from_text(SPECULOS_MNEMONIC, passphrase='')
        for v in (0, 5):
            entropy, _, _ = bip85.child(root, v)
            seed = bip85.vault_seed(entropy, 'PQB', True, 'main', version='v1')
            self.assertEqual(lock_from_device(dev, v).script, Lock.build(get(), seed).script)
