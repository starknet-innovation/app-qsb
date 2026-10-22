"""Deposits into and withdrawals from QSB vaults.

Signatures are checked against BIP-143 digests computed here, independently of
the app. The withdrawals spend the vault of qsb-app's first mainnet deposit,
so the device recognises a real vault script.
"""

import pytest
from application_client.bitcoin import TxOut, bip143_sighash, hash160, verify, wallet_script
from application_client.fixtures import (
    NESTED_PATH,
    P2TR_DESTINATION,
    P2WPKH_PATH,
    deposit,
    fixture,
    funding,
    withdrawal,
)
from application_client.qsb_command_sender import Errors, Kind, QsbCommandSender
from ragger.error import ExceptionRAPDU

SIGNING = "Signing transaction"


def wallet(client, path):
    pubkey, _ = client.get_wallet(path)
    return pubkey, wallet_script(pubkey, path == NESTED_PATH)


def sign_all(client, pubkey, tx, amounts, indices):
    for i in indices:
        verify(pubkey, bip143_sighash(tx, i, hash160(pubkey), amounts[i]), client.sign(i))


@pytest.mark.parametrize("path", [P2WPKH_PATH, NESTED_PATH])
def test_deposit(backend, scenario_navigator, test_name, path):
    client = QsbCommandSender(backend)
    pubkey, script = wallet(client, path)
    values = [60_000, 45_000]
    tx, prevs = deposit(script, values, amount=100_000, change=4_000)
    client.stream_tx(Kind.DEPOSIT, path, tx, prevs)
    with client.review():
        scenario_navigator.review_approve_with_spinner(SIGNING, test_name=f"{test_name}_{path[2:4]}")
    assert client.get_async_response().data == b""
    sign_all(client, pubkey, tx, values, [0])
    # Each input is signed once; the refusal keeps the approved transaction.
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign(0)
    assert e.value.status == Errors.SW_BAD_STATE
    sign_all(client, pubkey, tx, values, [1])
    backend.wait_for_home_screen()


def test_deposit_eight_inputs(backend, scenario_navigator):
    client = QsbCommandSender(backend)
    pubkey, script = wallet(client, P2WPKH_PATH)
    values = [20_000 + i for i in range(8)]
    tx, prevs = deposit(script, values, amount=150_000, change=9_000)
    client.stream_tx(Kind.DEPOSIT, P2WPKH_PATH, tx, prevs)
    with client.review():
        scenario_navigator.review_approve_with_spinner(SIGNING)
    sign_all(client, pubkey, tx, values, range(8))
    backend.wait_for_home_screen()


def test_abandoned_after_approval(backend, scenario_navigator):
    """A command other than SIGN after approval ends the approved transaction."""
    client = QsbCommandSender(backend)
    pubkey, script = wallet(client, P2WPKH_PATH)
    values = [60_000, 45_000]
    tx, prevs = deposit(script, values, amount=100_000, change=4_000)
    client.stream_tx(Kind.DEPOSIT, P2WPKH_PATH, tx, prevs)
    with client.review():
        scenario_navigator.review_approve_with_spinner(SIGNING, do_comparison=False)
    # Asking for an input that isn't signable leaves the transaction approved.
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign(2)
    assert e.value.status == Errors.SW_BAD_STATE
    sign_all(client, pubkey, tx, values, [0])
    assert client.get_version()
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign(1)
    assert e.value.status == Errors.SW_BAD_STATE
    backend.wait_for_home_screen()


def test_deposit_high_fee(backend, scenario_navigator):
    client = QsbCommandSender(backend)
    pubkey, script = wallet(client, P2WPKH_PATH)
    tx, prevs = deposit(script, [30_000], amount=20_000, change=0)
    client.stream_tx(Kind.DEPOSIT, P2WPKH_PATH, tx, prevs)
    with client.review():
        scenario_navigator.review_approve_with_spinner(SIGNING)
    sign_all(client, pubkey, tx, [30_000], [0])
    backend.wait_for_home_screen()


def test_deposit_reject(backend, scenario_navigator):
    client = QsbCommandSender(backend)
    _, script = wallet(client, P2WPKH_PATH)
    tx, prevs = deposit(script, [60_000], amount=50_000, change=9_000)
    client.stream_tx(Kind.DEPOSIT, P2WPKH_PATH, tx, prevs)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.review():
            scenario_navigator.review_reject()
    assert e.value.status == Errors.SW_DENY
    backend.wait_for_home_screen()
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign(0)
    assert e.value.status == Errors.SW_BAD_STATE


def refused(client, kind, tx, prevs, status, at_review=False, path=P2WPKH_PATH):
    with pytest.raises(ExceptionRAPDU) as e:
        client.stream_tx(kind, path, tx, prevs)
        if at_review:
            with client.review():
                pass
    assert e.value.status == status


def test_deposit_refusals(backend):
    client = QsbCommandSender(backend)
    _, script = wallet(client, P2WPKH_PATH)
    tx, prevs = deposit(script, [60_000], amount=50_000, change=9_000)

    # An input that isn't the wallet's.
    _, other = wallet(client, "m/84'/0'/1'/0/0")
    foreign, foreign_prevs = deposit(other, [60_000], amount=50_000, change=9_000)
    refused(client, Kind.DEPOSIT, foreign, foreign_prevs, Errors.SW_NOT_OWN_INPUT)

    # A previous transaction that doesn't hash to the outpoint's txid.
    refused(client, Kind.DEPOSIT, tx, [funding(script, 60_001, 0).serialize()], Errors.SW_TXID_MISMATCH)

    # Output 0 isn't a vault.
    tx.outputs[0] = TxOut(50_000, P2TR_DESTINATION)
    refused(client, Kind.DEPOSIT, tx, prevs, Errors.SW_NOT_VAULT, at_review=True)

    # Change to another address.
    tx, prevs = deposit(script, [60_000], amount=50_000, change=9_000)
    tx.outputs[1] = TxOut(9_000, other)
    refused(client, Kind.DEPOSIT, tx, prevs, Errors.SW_BAD_LAYOUT, at_review=True)

    # More out than in.
    tx, prevs = deposit(script, [60_000], amount=50_000, change=10_000)
    refused(client, Kind.DEPOSIT, tx, prevs, Errors.SW_BAD_AMOUNT, at_review=True)


def test_withdrawal(backend, scenario_navigator):
    client = QsbCommandSender(backend)
    pubkey, script = wallet(client, P2WPKH_PATH)
    tx, prevs, vault_value = withdrawal(script, helper=1_449, destination=P2TR_DESTINATION, amount=92_083)
    client.stream_tx(Kind.WITHDRAWAL, P2WPKH_PATH, tx, prevs)
    with client.review():
        scenario_navigator.review_approve_with_spinner(SIGNING)
    sign_all(client, pubkey, tx, [1_449, vault_value], [0])
    backend.wait_for_home_screen()


def test_withdrawal_nested_to_own_address(backend, scenario_navigator):
    client = QsbCommandSender(backend)
    pubkey, script = wallet(client, NESTED_PATH)
    tx, prevs, vault_value = withdrawal(script, helper=5_000, destination=script, amount=99_000)
    client.stream_tx(Kind.WITHDRAWAL, NESTED_PATH, tx, prevs)
    with client.review():
        scenario_navigator.review_approve_with_spinner(SIGNING)
    # The vault input is not the wallet's to sign.
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign(1)
    assert e.value.status == Errors.SW_BAD_STATE
    sign_all(client, pubkey, tx, [5_000, vault_value], [0])
    backend.wait_for_home_screen()


def test_withdrawal_reject(backend, scenario_navigator):
    client = QsbCommandSender(backend)
    _, script = wallet(client, P2WPKH_PATH)
    tx, prevs, _ = withdrawal(script, helper=1_449, destination=P2TR_DESTINATION, amount=92_083)
    client.stream_tx(Kind.WITHDRAWAL, P2WPKH_PATH, tx, prevs)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.review():
            scenario_navigator.review_reject()
    assert e.value.status == Errors.SW_DENY


def test_withdrawal_refusals(backend):
    client = QsbCommandSender(backend)
    _, script = wallet(client, P2WPKH_PATH)

    # Input 1 must spend a vault: here it spends another wallet output.
    tx, prevs, _ = withdrawal(script, helper=1_449, destination=P2TR_DESTINATION, amount=92_083)
    other = funding(script, 100_000, 9)
    tx.inputs[1].txid, tx.inputs[1].vout = other.txid(), 0
    refused(client, Kind.WITHDRAWAL, tx, [prevs[0], other.serialize()], Errors.SW_NOT_VAULT)

    # A destination with no address: OP_RETURN.
    tx, prevs, _ = withdrawal(script, helper=1_449, destination=bytes.fromhex("6a0100"), amount=92_083)
    refused(client, Kind.WITHDRAWAL, tx, prevs, Errors.SW_UNSUPPORTED_OUTPUT, at_review=True)

    # Paying out more than vault + helper.
    tx, prevs, _ = withdrawal(script, helper=1_449, destination=P2TR_DESTINATION, amount=101_449)
    refused(client, Kind.WITHDRAWAL, tx, prevs, Errors.SW_BAD_AMOUNT, at_review=True)

    # A previous transaction in its SegWit serialization: the marker reads as zero inputs.
    tx, prevs, _ = withdrawal(script, helper=1_449, destination=P2TR_DESTINATION, amount=92_083)
    refused(client, Kind.WITHDRAWAL, tx, [prevs[0], fixture("mainnet-deposit.hex")], Errors.SW_PARSE)

    # A deposit layout declared as a withdrawal.
    tx, prevs = deposit(script, [60_000], amount=50_000, change=9_000)
    refused(client, Kind.WITHDRAWAL, tx, prevs, Errors.SW_BAD_LAYOUT)
