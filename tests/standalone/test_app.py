from pathlib import Path

import pytest
from application_client.qsb_command_sender import CLA, Errors, Ins, QsbCommandSender
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib

CARGO_TOML = Path(__file__).resolve().parents[2] / "app" / "Cargo.toml"


def test_version(backend):
    version = tomllib.loads(CARGO_TOML.read_text())["package"]["version"]
    assert QsbCommandSender(backend).get_version() == tuple(int(x) for x in version.split("."))


def test_app_name(backend):
    assert QsbCommandSender(backend).get_app_name() == "QSB"


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
        (CLA, Ins.GET_VERSION, 1, Errors.SW_WRONG_P1P2),
        (CLA, Ins.SIGN_TX, 6, Errors.SW_WRONG_P1P2),
        (CLA, Ins.SIGN_IN, 1, Errors.SW_WRONG_P1P2),
    ],
)
def test_bad_apdus(backend, cla, ins, p1, status):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=cla, ins=ins, p1=p1, p2=0)
    assert e.value.status == status


def test_steps_out_of_order(backend):
    client = QsbCommandSender(backend)
    for step in (1, 2, 3, 4, 5):
        with pytest.raises(ExceptionRAPDU) as e:
            client.send(Ins.SIGN_TX, step, b"\x00" * 8 if step != 5 else b"\x00")
        assert e.value.status in (Errors.SW_BAD_STATE, Errors.SW_WRONG_DATA_LENGTH)
    with pytest.raises(ExceptionRAPDU) as e:
        client.send(Ins.SIGN_IN, 0x80, b"more")
    assert e.value.status == Errors.SW_BAD_STATE
