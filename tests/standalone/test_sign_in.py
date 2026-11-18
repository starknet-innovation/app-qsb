"""SIGN_IN: the QSB sign-in challenge, signed with a vault's deposit key.

Signatures are checked against BIP-322 digests computed here, independently of
the app, with the deposit key from the reference.
"""

import pytest
from application_client import fixtures as fx
from application_client.bitcoin import bip322_sighash, hash160, p2wpkh_script, verify
from application_client.flows import RETIRE, allocate, choose, refused
from application_client.pqb_command_sender import Errors, Ins, PqbCommandSender, Status
from ragger.error import ExceptionRAPDU


def challenge(address: str, origin: str = "https://qsb.example.org") -> bytes:
    """The sign-in message qsb-app's server issues."""
    return (
        "QSB Vault sign-in\n"
        f"Origin: {origin}\n"
        f"Address: {address}\n"
        "Network: bitcoin-mainnet\n"
        "Nonce: 3f2c1e9a-8b7d-4c6e-9f10-2a3b4c5d6e7f\n"
        "Expires: 2026-10-19T16:05:00.000Z\n"
        "This signature authorizes this session only. It does not authorize a Bitcoin transaction."
    ).encode()


def check(v: int, message: bytes, signature: bytes) -> None:
    pubkey = fx.deposit_pubkey(v)
    pkh = hash160(pubkey)
    verify(pubkey, bip322_sighash(message, p2wpkh_script(pkh), pkh), signature)


def test_sign_in(backend, device, navigator, scenario_navigator, test_name):
    client = PqbCommandSender(backend)
    allocate(backend, device, navigator, first=True)
    message = challenge(fx.deposit_address(0))
    with client.sign_in(0, message):
        scenario_navigator.review_approve(test_name=test_name)
    check(0, message, client.get_async_response().data)
    backend.wait_for_home_screen()


def test_sign_in_reject(backend, device, navigator, scenario_navigator, test_name):
    client = PqbCommandSender(backend)
    allocate(backend, device, navigator, first=True)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_in(0, challenge(fx.deposit_address(0))):
            scenario_navigator.review_reject(test_name=test_name)
    assert e.value.status == Errors.SW_DENY
    backend.wait_for_home_screen()


def test_sign_in_retired_vault(backend, device, navigator, scenario_navigator):
    """A retired vault (here dropped, so reserved) still signs in."""
    client = PqbCommandSender(backend)
    allocate(backend, device, navigator, first=True)
    with client.retire(0):
        choose(device, navigator, True, RETIRE)
    backend.wait_for_home_screen()
    assert client.get_vault(0).status == Status.RESERVED
    message = challenge(fx.deposit_address(0))
    with client.sign_in(0, message):
        scenario_navigator.review_approve(do_comparison=False)
    check(0, message, client.get_async_response().data)


def test_sign_in_refused(backend, device, navigator):
    client = PqbCommandSender(backend)
    # In a fresh namespace an index the device never handed out is refused.
    allocate(backend, device, navigator, first=True)
    address = fx.deposit_address(0)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_in(1, challenge(fx.deposit_address(1))):
            pass
    assert e.value.status == Errors.SW_VAULT_STATE
    for message in [
        b"Hello World",
        challenge(fx.deposit_address(1)),  # another vault's address
        challenge(address).replace(b"bitcoin-mainnet", b"bitcoin-testnet"),
        challenge(address, origin="https://qsb.app@evil.example"),
        challenge(address) + b"\n",
    ]:
        with pytest.raises(ExceptionRAPDU) as e:
            with client.sign_in(0, message):
                pass
        assert e.value.status == Errors.SW_INVALID_DATA
    # A continuation without a first chunk.
    refused(Errors.SW_BAD_STATE, client.send, Ins.SIGN_IN, 0x80, b"x")
    refused(Errors.SW_WRONG_P1P2, client.send, Ins.SIGN_IN, 0x01, b"")


def test_sign_in_no_history(backend, scenario_navigator):
    """Before any allocation the seed has no history here: any vault may sign in."""
    client = PqbCommandSender(backend)
    message = challenge(fx.deposit_address(3))
    with client.sign_in(3, message):
        scenario_navigator.review_approve(do_comparison=False)
    check(3, message, client.get_async_response().data)
