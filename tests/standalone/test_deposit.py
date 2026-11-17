"""The deposit address, and SIGN_DEPOSIT: sweeps into a vault and refunds.

Signatures are checked against BIP-143 digests computed here, independently of
the app, with the deposit key from the reference.
"""

import pytest
from application_client import fixtures as fx
from application_client.bitcoin import TxOut, bip143_sighash, hash160, verify
from application_client.flows import allocate, refused, sign_sweep
from application_client.pqb_command_sender import Errors, Kind, PqbCommandSender, Status
from ragger.error import ExceptionRAPDU


def check_signatures(v, tx, values, sigs):
    pubkey = fx.deposit_pubkey(v)
    for i, sig in enumerate(sigs):
        verify(pubkey, bip143_sighash(tx, i, hash160(pubkey), values[i]), sig)


def test_deposit_address_display(backend, device, navigator, scenario_navigator, test_name):
    client = PqbCommandSender(backend)
    # Not shown as a place to pay before the vault is allocated.
    refused(Errors.SW_VAULT_STATE, client.send, 0x13, 1, b"\x00\x00\x00\x00")
    allocate(backend, device, navigator, first=True)
    refused(Errors.SW_VAULT_STATE, client.send, 0x13, 1, b"\x00\x00\x00\x01")
    with client.get_deposit_address_display(0):
        scenario_navigator.address_review_approve(test_name=test_name)
    pubkey, address = client.unpack_deposit_address(client.get_async_response().data)
    assert pubkey == fx.deposit_pubkey(0)
    assert address == fx.deposit_address(0)
    backend.wait_for_home_screen()


def test_deposit_address_reject(backend, device, navigator, scenario_navigator, test_name):
    client = PqbCommandSender(backend)
    allocate(backend, device, navigator, first=True)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_deposit_address_display(0):
            scenario_navigator.address_review_reject(test_name=test_name)
    assert e.value.status == Errors.SW_DENY
    backend.wait_for_home_screen()


def test_sweep(backend, device, navigator, scenario_navigator, test_name):
    client = PqbCommandSender(backend)
    allocate(backend, device, navigator, first=True)
    values = [60_000, 45_000]
    tx, prevs = fx.sweep(0, values, 100_000)
    sigs = sign_sweep(backend, scenario_navigator, 0, tx, prevs, test_name=test_name)
    check_signatures(0, tx, values, sigs)
    # The funding is recorded.
    vault = client.get_vault(0)
    assert (vault.status, vault.funded) == (Status.ALLOCATED, True)
    record = client.get_record(0)
    assert (record.state, record.flags) == (1, 0x01)
    assert (record.funding_txid, record.funding_vout, record.funding_value) == (tx.txid(), 0, 100_000)
    assert record.sweep_input == tx.inputs[0].outpoint()
    assert record.raw[167:] == bytes(251 - 167)
    # A funded vault's deposit address is no longer shown as a place to pay.
    refused(Errors.SW_VAULT_STATE, client.send, 0x13, 1, b"\x00\x00\x00\x00")

    # The same sweep again: signed again.
    sigs = sign_sweep(backend, scenario_navigator, 0, tx, prevs)
    check_signatures(0, tx, values, sigs)
    # A replacement spending the recorded sweep's input: at most one confirms.
    bump, bump_prevs = fx.sweep(0, values, 99_000)
    sigs = sign_sweep(backend, scenario_navigator, 0, bump, bump_prevs)
    check_signatures(0, bump, values, sigs)
    assert client.get_record(0).funding_txid == bump.txid()
    # An unrelated sweep would fund the vault twice: refused before any screen.
    other, other_prevs = fx.sweep(0, [30_000], 29_000, salt=0x20)
    client.stream_deposit(Kind.SWEEP, 0, other, other_prevs)
    refused(Errors.SW_CONFLICT, client.deposit_review_sync)
    assert client.get_record(0).funding_txid == bump.txid()


def test_sweep_eight_inputs(backend, device, navigator, scenario_navigator):
    allocate(backend, device, navigator, first=True)
    values = [20_000 + i for i in range(8)]
    tx, prevs = fx.sweep(0, values, 150_000)
    check_signatures(0, tx, values, sign_sweep(backend, scenario_navigator, 0, tx, prevs))


def test_sweep_reject(backend, device, navigator, scenario_navigator, test_name):
    client = PqbCommandSender(backend)
    allocate(backend, device, navigator, first=True)
    tx, prevs = fx.sweep(0, [60_000], 50_000)
    client.stream_deposit(Kind.SWEEP, 0, tx, prevs)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.deposit_review():
            scenario_navigator.review_reject(test_name=test_name)
    assert e.value.status == Errors.SW_DENY
    backend.wait_for_home_screen()
    refused(Errors.SW_BAD_STATE, client.deposit_sign, 0)
    assert not client.get_vault(0).funded


def test_refund_with_change(backend, scenario_navigator, test_name):
    """A refund needs no allocation: payments to the deposit address can always be recovered."""
    values = [60_000, 5_000]
    tx, prevs = fx.refund(3, values, [TxOut(50_000, fx.P2TR_DESTINATION), TxOut(9_000, fx.deposit_script(3))])
    sigs = sign_sweep(backend, scenario_navigator, 3, tx, prevs, kind=Kind.REFUND, test_name=test_name)
    check_signatures(3, tx, values, sigs)
    assert PqbCommandSender(backend).get_vault(3).status == Status.NO_HISTORY


def test_sweep_refusals(backend, device, navigator):
    client = PqbCommandSender(backend)

    def at_review(kind, v, tx, prevs, status):
        client.stream_deposit(kind, v, tx, prevs)
        refused(status, client.deposit_review_sync)

    # Before allocation, a sweep has no vault to fund.
    tx, prevs = fx.sweep(0, [60_000], 50_000)
    at_review(Kind.SWEEP, 0, tx, prevs, Errors.SW_VAULT_STATE)
    allocate(backend, device, navigator, first=True)
    # Not this vault's script: a P2TR output, another vault's script.
    tx, prevs = fx.sweep(0, [60_000], 50_000, to=fx.P2TR_DESTINATION)
    at_review(Kind.SWEEP, 0, tx, prevs, Errors.SW_NOT_VAULT)
    tx, prevs = fx.sweep(0, [60_000], 50_000, to=fx.script(1))
    at_review(Kind.SWEEP, 0, tx, prevs, Errors.SW_NOT_VAULT)
    # Vault 1 isn't allocated.
    tx, prevs = fx.sweep(1, [60_000], 50_000)
    at_review(Kind.SWEEP, 1, tx, prevs, Errors.SW_VAULT_STATE)
    # More out than in.
    tx, prevs = fx.sweep(0, [60_000], 60_000)
    at_review(Kind.SWEEP, 0, tx, prevs, Errors.SW_BAD_AMOUNT)
    # An input that isn't the deposit address: vault 1's.
    foreign, foreign_prevs = fx.sweep(1, [60_000], 50_000, to=fx.script(0))
    refused(Errors.SW_NOT_OWN_INPUT, client.stream_deposit, Kind.SWEEP, 0, foreign, foreign_prevs)
    # A previous transaction that doesn't hash to the outpoint's txid.
    tx, prevs = fx.sweep(0, [60_000], 50_000)
    wrong = fx.funding(fx.deposit_script(0), 60_001, 0).serialize()
    refused(Errors.SW_TXID_MISMATCH, client.stream_deposit, Kind.SWEEP, 0, tx, [wrong])
    # A refund to a vault script, or only back to the deposit address.
    tx, prevs = fx.refund(0, [60_000], [TxOut(50_000, fx.script(0))])
    at_review(Kind.REFUND, 0, tx, prevs, Errors.SW_UNSUPPORTED_OUTPUT)
    tx, prevs = fx.refund(0, [60_000], [TxOut(50_000, fx.deposit_script(0))])
    at_review(Kind.REFUND, 0, tx, prevs, Errors.SW_BAD_LAYOUT)
    tx, prevs = fx.refund(0, [60_000], [TxOut(50_000, bytes.fromhex("6a0100"))])
    at_review(Kind.REFUND, 0, tx, prevs, Errors.SW_UNSUPPORTED_OUTPUT)
    # Nothing was recorded.
    assert not client.get_vault(0).funded
