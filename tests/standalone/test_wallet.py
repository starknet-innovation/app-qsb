import pytest
from application_client.bitcoin import address, wallet_script
from application_client.fixtures import NESTED_PATH, P2WPKH_PATH
from application_client.qsb_command_sender import Errors, Ins, QsbCommandSender
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU


@pytest.mark.parametrize(
    "path, nested",
    [(P2WPKH_PATH, False), ("m/84'/0'/7'/1/49999", False), (NESTED_PATH, True), ("m/49'/0'/100'/0/3", True)],
)
def test_wallet_address(backend, path, nested):
    pubkey, addr = QsbCommandSender(backend).get_wallet(path)
    assert pubkey[0] in (2, 3)
    assert addr == address(wallet_script(pubkey, nested))
    assert addr.startswith("3" if nested else "bc1q")


@pytest.mark.parametrize(
    "path",
    [
        "m/44'/0'/0'/0/0",  # legacy purpose
        "m/86'/0'/0'/0/0",  # taproot purpose
        "m/84'/1'/0'/0/0",  # testnet coin type
        "m/84'/0'/0/0/0",  # unhardened account
        "m/84'/0'/101'/0/0",
        "m/84'/0'/0'/2/0",
        "m/84'/0'/0'/0/50001",
        "m/84'/0'/0'/0",
        "m/84'/0'/0'/0/0/0",
    ],
)
def test_wallet_refuses_other_paths(backend, path):
    with pytest.raises(ExceptionRAPDU) as e:
        QsbCommandSender(backend).get_wallet(path)
    assert e.value.status == Errors.SW_BAD_PATH


def test_wallet_trailing_bytes(backend):
    with pytest.raises(ExceptionRAPDU) as e:
        QsbCommandSender(backend).send(Ins.GET_WALLET_ADDRESS, 0, pack_derivation_path(P2WPKH_PATH) + b"\x00")
    assert e.value.status == Errors.SW_WRONG_DATA_LENGTH


def test_wallet_address_confirm(backend, scenario_navigator):
    client = QsbCommandSender(backend)
    with client.get_wallet_with_confirmation(P2WPKH_PATH):
        scenario_navigator.address_review_approve()
    pubkey, addr = client.unpack_wallet(client.get_async_response().data)
    assert addr == address(wallet_script(pubkey, False))


def test_wallet_address_reject(backend, scenario_navigator):
    client = QsbCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_wallet_with_confirmation(NESTED_PATH):
            scenario_navigator.address_review_reject()
    assert e.value.status == Errors.SW_DENY
