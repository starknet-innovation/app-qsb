"""WITHDRAW and REVEAL_READ: one recorded disclosure per vault.

Every released item is checked against the reference: the table preimages and
menu signatures against the vault's commitments, the co-signature against Q
over the legacy SIGHASH_ALL digest of the withdrawal, with the vault script.
"""

import dataclasses

import pytest
from application_client import fixtures as fx
from application_client.bitcoin import TxOut
from application_client.flows import (
    allocate,
    allocate_and_fund,
    dismiss,
    hold_review,
    refused,
    withdraw,
    withdraw_refused,
)
from application_client.pqb_command_sender import Errors, Ins, PqbCommandSender, Status, idx
from application_client.verify import binding, check_disclosure, digest
from ragger.error import ExceptionRAPDU

OUTPUTS = [TxOut(95_000, fx.P2TR_DESTINATION)]


def check_record(record, req, state, flags, funding_txid, value, sweep_input=bytes(36)):
    assert (record.layout, record.v, record.state, record.flags) == (1, req.v, state, flags)
    assert (record.root, record.script_hash) == (fx.root(req.v), fx.script_hash(req.v))
    assert (record.funding_txid, record.funding_vout, record.funding_value) == (funding_txid, req.vout, value)
    assert record.sweep_input == sweep_input
    assert (record.round0, record.round1, record.picks) == (req.round0, req.round1, req.picks)
    assert record.binding == binding(req)
    assert record.digest == digest(req)


def test_withdraw(backend, device, navigator, scenario_navigator, test_name, default_screenshot_path):
    client = PqbCommandSender(backend)
    sweep = allocate_and_fund(backend, device, navigator, scenario_navigator)
    req = fx.withdrawal(0, sweep, 0, OUTPUTS, locktime=900_000, sequence=0xFFFFFFFE)
    disclosure = withdraw(backend, device, navigator, req, (test_name, default_screenshot_path))
    check_disclosure(req, disclosure)
    # Chunk 4 ends the approval.
    refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 0)
    vault = client.get_vault(0)
    assert (vault.status, vault.funded) == (Status.EXPOSED, True)
    # The record a host builds its recovery manifest from.
    state = client.get_state()
    assert (state.namespace, state.next_v, state.records) == (1, 1, 1)
    check_record(client.get_record(0), req, 2, 0x03, sweep.txid(), 100_000, sweep.inputs[0].outpoint())


def test_withdraw_retry_and_conflicts(backend, device, navigator, scenario_navigator, test_name,
                                      default_screenshot_path):
    client = PqbCommandSender(backend)
    sweep = allocate_and_fund(backend, device, navigator, scenario_navigator)
    outputs = [TxOut(60_000, fx.P2TR_DESTINATION), TxOut(39_000, fx.P2WPKH_DESTINATION)]
    req = fx.withdrawal(0, sweep, 0, outputs)
    first = withdraw(backend, device, navigator, req)
    check_disclosure(req, first)
    # The exact request again, in a new session: approved again, the same release.
    again = withdraw(backend, device, navigator, req, (f"{test_name}/1_retry", default_screenshot_path))
    assert again == first
    # Anything different: the conflict page, then 0x6A90.
    picks = dataclasses.replace(req, picks=[0, 0, 15])
    withdraw_refused(backend, device, navigator, picks, Errors.SW_CONFLICT,
                     (f"{test_name}/2_conflict", default_screenshot_path))
    round0 = dataclasses.replace(req, round0=[0, 3, 9, 27, 40, 64, 100, 106])
    round1 = dataclasses.replace(req, round1=[1, 2, 4, 5, 33, 50, 77, 99, 108],
                                 round0=[0, 3, 9, 27, 40, 64, 100, 107])
    fee = fx.withdrawal(0, sweep, 0, [TxOut(60_000, fx.P2TR_DESTINATION), TxOut(38_000, fx.P2WPKH_DESTINATION)])
    locktime = dataclasses.replace(req, locktime=1)
    for other in (round0, round1, fee, locktime):
        withdraw_refused(backend, device, navigator, other, Errors.SW_CONFLICT)
    refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 0)
    assert client.get_vault(0).status == Status.EXPOSED
    # The recorded disclosure is unchanged, and still retried.
    assert withdraw(backend, device, navigator, req) == first


def test_withdraw_reject(backend, device, navigator, scenario_navigator, test_name, default_screenshot_path):
    client = PqbCommandSender(backend)
    sweep = allocate_and_fund(backend, device, navigator, scenario_navigator)
    req = fx.withdrawal(0, sweep, 0, OUTPUTS)
    client.stream_withdraw(req)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.withdraw_review():
            hold_review(device, navigator, False, (test_name, default_screenshot_path))
    assert e.value.status == Errors.SW_DENY
    backend.wait_for_home_screen()
    refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 0)
    # Nothing was recorded: a different disclosure is a first disclosure.
    assert client.get_vault(0).status == Status.ALLOCATED
    assert client.get_record(0).flags == 0x01
    other = dataclasses.replace(req, picks=[1, 2, 3])
    check_disclosure(other, withdraw(backend, device, navigator, other))
    assert client.get_vault(0).status == Status.EXPOSED


def test_withdraw_unfunded_vault(backend, device, navigator):
    """An allocated vault funded by another wallet: the funding is learned from the withdrawal."""
    client = PqbCommandSender(backend)
    allocate(backend, device, navigator, first=True)
    prev = fx.funding(fx.script(0), 80_000, 0x31, vout=2)
    req = fx.withdrawal(0, prev, 2, [TxOut(79_000, fx.P2WPKH_DESTINATION)], version=1)
    check_disclosure(req, withdraw(backend, device, navigator, req))
    check_record(client.get_record(0), req, 2, 0x03, prev.txid(), 80_000)


ROUND0, ROUND1, PICKS = fx.ROUND0, fx.ROUND1, fx.PICKS


@pytest.mark.parametrize(
    "round0, round1, picks",
    [
        (ROUND0[::-1], ROUND1, PICKS),  # not ascending
        (ROUND0, [1, 2, 4, 5, 33, 50, 77, 107, 99], PICKS),
        ([0, 3, 3, 27, 40, 64, 100, 108], ROUND1, PICKS),  # repeated
        ([0, 3, 9, 27, 40, 64, 100, 109], ROUND1, PICKS),  # out of range
        (ROUND0, [1, 2, 4, 5, 33, 50, 77, 99, 109], PICKS),
        ([1, 3, 9, 27, 40, 64, 100, 108], ROUND1, PICKS),  # in both rounds
        (ROUND0, ROUND1, [12, 0, 0]),  # picks out of range
        (ROUND0, ROUND1, [0, 16, 0]),
        (ROUND0, ROUND1, [0, 0, 16]),
    ],
)
def test_withdraw_start_refusals(backend, round0, round1, picks):
    client = PqbCommandSender(backend)
    prev = fx.funding(fx.script(0), 80_000, 0x31)
    req = fx.withdrawal(0, prev, 0, OUTPUTS, round0=round0, round1=round1, picks=picks)
    refused(Errors.SW_INVALID_DATA, client.send, Ins.WITHDRAW, 0, req.start())


def test_withdraw_start_other_refusals(backend):
    client = PqbCommandSender(backend)
    prev = fx.funding(fx.script(0), 80_000, 0x31)
    req = fx.withdrawal(0, prev, 0, OUTPUTS)
    refused(Errors.SW_INVALID_DATA, client.send, Ins.WITHDRAW, 0, idx(0x80000000) + req.start()[4:])
    # docs/apdu.md lists 1-4 outputs under 0x6A80; pqb-core answers 0xB007 (bad layout).
    for n in (0, 5):
        start = req.start()
        refused(Errors.SW_BAD_LAYOUT, client.send, Ins.WITHDRAW, 0, start[:52] + bytes([n]) + start[53:])


def test_withdraw_transaction_refusals(backend):
    """Refusals while streaming or at REVIEW, before any record is consulted."""
    client = PqbCommandSender(backend)
    prev = fx.funding(fx.script(0), 80_000, 0x31, vout=1)
    good = fx.withdrawal(0, prev, 1, OUTPUTS[:0] + [TxOut(70_000, fx.P2TR_DESTINATION)])
    # The previous transaction doesn't hash to the outpoint.
    bad_txid = dataclasses.replace(good, prev_txid=bytes(32))
    refused(Errors.SW_TXID_MISMATCH, client.stream_withdraw, bad_txid)
    # Output `vout` isn't vault 0's script: another output, another vault's script.
    refused(Errors.SW_NOT_VAULT, client.stream_withdraw, dataclasses.replace(good, vout=0))
    refused(Errors.SW_NOT_VAULT, client.stream_withdraw, dataclasses.replace(good, v=1))
    # A destination with no address, a zero amount, more out than in, no fee.
    for outputs, status in [
        ([TxOut(70_000, bytes.fromhex("6a0100"))], Errors.SW_UNSUPPORTED_OUTPUT),
        ([TxOut(70_000, fx.P2TR_DESTINATION), TxOut(0, fx.P2WPKH_DESTINATION)], Errors.SW_BAD_AMOUNT),
        ([TxOut(80_001, fx.P2TR_DESTINATION)], Errors.SW_BAD_AMOUNT),
        ([TxOut(80_000, fx.P2TR_DESTINATION)], Errors.SW_BAD_AMOUNT),
    ]:
        client.stream_withdraw(fx.withdrawal(0, prev, 1, outputs))
        refused(status, client.send, Ins.WITHDRAW, 3)
    # REVIEW out of order.
    refused(Errors.SW_BAD_STATE, client.send, Ins.WITHDRAW, 3)


def test_withdraw_not_allocated(backend, device, navigator):
    """In a fresh namespace, a vault this device never allocated discloses nothing."""
    client = PqbCommandSender(backend)
    allocate(backend, device, navigator, first=True)
    prev = fx.funding(fx.script(3), 80_000, 0x33)
    client.stream_withdraw(fx.withdrawal(3, prev, 0, [TxOut(79_000, fx.P2TR_DESTINATION)]))
    refused(Errors.SW_VAULT_STATE, client.send, Ins.WITHDRAW, 3)
    assert client.get_vault(3).status == Status.NOT_ALLOCATED
    assert client.get_state().records == 1


def test_withdraw_emergency(backend, device, navigator, test_name, default_screenshot_path):
    """No history for this seed: the emergency path, outside custody conformance."""
    client = PqbCommandSender(backend)
    prev = fx.funding(fx.script(2), 50_000, 0x22, vout=1)
    req = fx.withdrawal(2, prev, 1, [TxOut(48_000, fx.P2TR_DESTINATION)])
    disclosure = withdraw(backend, device, navigator, req, (test_name, default_screenshot_path))
    check_disclosure(req, disclosure)
    vault = client.get_vault(2)
    assert (vault.status, vault.funded) == (Status.UNKNOWN, True)
    # The namespace is now unknown: never mistaken for a fresh seed.
    state = client.get_state()
    assert (state.namespace, state.records) == (2, 1)
    # Funded, disclosed, emergency.
    check_record(client.get_record(0), req, 4, 0x07, prev.txid(), 50_000)
    # Only the exact disclosure can be retried.
    assert withdraw(backend, device, navigator, req) == disclosure
    withdraw_refused(backend, device, navigator, dataclasses.replace(req, picks=[0, 0, 0]), Errors.SW_CONFLICT)
    # And no allocation on this seed.
    with pytest.raises(ExceptionRAPDU) as e:
        with client.allocate():
            dismiss(device, navigator)
    assert e.value.status == Errors.SW_CONTINUITY
    backend.wait_for_home_screen()


def test_command_ends_the_approval(backend, device, navigator, scenario_navigator):
    client = PqbCommandSender(backend)
    prev = fx.funding(fx.script(4), 50_000, 0x24)
    req = fx.withdrawal(4, prev, 0, [TxOut(48_000, fx.P2TR_DESTINATION)])
    client.stream_withdraw(req)
    with client.withdraw_review():
        hold_review(device, navigator, True)
    backend.wait_for_text_on_screen("Disclosing secrets")
    # Chunks can be read again until chunk 4.
    first = client.reveal_read(0)
    assert client.reveal_read(0) == first
    client.get_app_name()
    backend.wait_for_home_screen()
    refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 1)


def test_approval_expires_after_60_seconds(backend, device, navigator):
    client = PqbCommandSender(backend)
    prev = fx.funding(fx.script(4), 50_000, 0x24)
    req = fx.withdrawal(4, prev, 0, [TxOut(48_000, fx.P2TR_DESTINATION)])
    client.stream_withdraw(req)
    with client.withdraw_review():
        hold_review(device, navigator, True)
    backend.wait_for_text_on_screen("Disclosing secrets")
    # Drive the 100 ms ticker by hand. A few real ticks pass before the pause.
    backend.pause_ticker()
    try:
        for _ in range(500):
            backend.send_tick()
        assert len(client.reveal_read(0)) == 160
        for _ in range(110):
            backend.send_tick()
        refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 1)
    finally:
        backend.resume_ticker()
    backend.wait_for_home_screen()
