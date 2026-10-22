import pytest
from application_client.bitcoin import bip322_sighash, hash160, verify, wallet_script
from application_client.fixtures import NESTED_PATH, P2WPKH_PATH
from application_client.qsb_command_sender import Errors, QsbCommandSender
from ragger.error import ExceptionRAPDU


def challenge(address: str, origin: str = "https://qsb.example.org") -> bytes:
    """The sign-in message qsb-app's server issues (server/app.ts)."""
    return (
        "QSB Vault sign-in\n"
        f"Origin: {origin}\n"
        f"Address: {address}\n"
        "Network: bitcoin-mainnet\n"
        "Nonce: 3f2c1e9a-8b7d-4c6e-9f10-2a3b4c5d6e7f\n"
        "Expires: 2026-10-19T16:05:00.000Z\n"
        "This signature authorizes this session only. It does not authorize a Bitcoin transaction."
    ).encode()


@pytest.mark.parametrize("path", [P2WPKH_PATH, NESTED_PATH])
def test_sign_in(backend, scenario_navigator, test_name, path):
    client = QsbCommandSender(backend)
    pubkey, address = client.get_wallet(path)
    message = challenge(address)
    with client.sign_in(path, message):
        scenario_navigator.review_approve(test_name=f"{test_name}_{path[2:4]}")
    signature = client.get_async_response().data
    script = wallet_script(pubkey, path == NESTED_PATH)
    verify(pubkey, bip322_sighash(message, script, hash160(pubkey)), signature)


def test_sign_in_reject(backend, scenario_navigator):
    client = QsbCommandSender(backend)
    _, address = client.get_wallet(P2WPKH_PATH)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_in(P2WPKH_PATH, challenge(address)):
            scenario_navigator.review_reject()
    assert e.value.status == Errors.SW_DENY


@pytest.mark.parametrize(
    "message",
    [
        b"Hello World",
        challenge("bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"),  # another address
        challenge("{address}").replace(b"bitcoin-mainnet", b"bitcoin-testnet"),
        challenge("{address}") + b"\n",
    ],
)
def test_sign_in_refuses_other_messages(backend, message):
    client = QsbCommandSender(backend)
    _, address = client.get_wallet(P2WPKH_PATH)
    message = message.replace(b"{address}", address.encode())
    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_in(P2WPKH_PATH, message):
            pass
    assert e.value.status == Errors.SW_BAD_MESSAGE
