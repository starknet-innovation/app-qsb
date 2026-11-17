from pathlib import Path

import pytest
from application_client.pqb_command_sender import CLA, Errors, Ins, PqbCommandSender
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib

CARGO_TOML = Path(__file__).resolve().parents[2] / "app" / "Cargo.toml"


def test_version(backend):
    version = tomllib.loads(CARGO_TOML.read_text())["package"]["version"]
    numbers, profile = PqbCommandSender(backend).get_version()
    assert numbers == tuple(int(x) for x in version.split("."))
    assert profile == "PQB-v1"


def test_app_name(backend):
    assert PqbCommandSender(backend).get_app_name() == "PQB"


def test_app_mainmenu(device, navigator, test_name, default_screenshot_path):
    if device.is_nano:
        instructions = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK]
    else:
        instructions = [NavInsID.USE_CASE_HOME_SETTINGS, NavInsID.USE_CASE_SUB_SETTINGS_EXIT]
    navigator.navigate_and_compare(
        default_screenshot_path, test_name, instructions, screen_change_before_first_instruction=False
    )


@pytest.mark.parametrize(
    "cla, ins, p1, status",
    [
        (CLA + 1, Ins.GET_VERSION, 0, Errors.SW_CLA_NOT_SUPPORTED),
        (CLA, 0x02, 0, Errors.SW_INS_NOT_SUPPORTED),
        (CLA, 0x06, 0, Errors.SW_INS_NOT_SUPPORTED),
        (CLA, 0x50, 0, Errors.SW_INS_NOT_SUPPORTED),
        (CLA, Ins.GET_VERSION, 1, Errors.SW_WRONG_P1P2),
        (CLA, Ins.GET_APP_NAME, 1, Errors.SW_WRONG_P1P2),
        (CLA, Ins.GET_COMMITMENTS, 1, Errors.SW_WRONG_P1P2),
        (CLA, Ins.GET_VAULT, 2, Errors.SW_WRONG_P1P2),
        (CLA, Ins.GET_SCRIPT, 1, Errors.SW_WRONG_P1P2),
        (CLA, Ins.GET_DEPOSIT_ADDRESS, 2, Errors.SW_WRONG_P1P2),
        (CLA, Ins.GET_STATE, 2, Errors.SW_WRONG_P1P2),
        (CLA, Ins.ALLOCATE, 1, Errors.SW_WRONG_P1P2),
        (CLA, Ins.RETIRE, 1, Errors.SW_WRONG_P1P2),
        (CLA, Ins.SIGN_DEPOSIT, 6, Errors.SW_WRONG_P1P2),
        (CLA, Ins.WITHDRAW, 4, Errors.SW_WRONG_P1P2),
        (CLA, Ins.REVEAL_READ, 5, Errors.SW_WRONG_P1P2),
        (CLA, Ins.MENU_POINTS, 3, Errors.SW_WRONG_P1P2),
    ],
)
def test_bad_apdus(backend, cla, ins, p1, status):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=cla, ins=ins, p1=p1, p2=0)
    assert e.value.status == status


def test_bad_p2(backend):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=Ins.GET_VERSION, p1=0, p2=1)
    assert e.value.status == Errors.SW_WRONG_P1P2


def test_steps_out_of_order(backend):
    client = PqbCommandSender(backend)
    for step, data in [(1, b"\x00" * 40), (2, b"\x00" * 8), (3, b"\x00" * 8), (4, b""), (5, b"\x00")]:
        with pytest.raises(ExceptionRAPDU) as e:
            client.send(Ins.SIGN_DEPOSIT, step, data)
        assert e.value.status == Errors.SW_BAD_STATE
    for step, data in [(1, b"\x00" * 8), (2, b"\x00" * 8), (3, b"")]:
        with pytest.raises(ExceptionRAPDU) as e:
            client.send(Ins.WITHDRAW, step, data)
        assert e.value.status == Errors.SW_BAD_STATE
