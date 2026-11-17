"""MENU_POINTS: the solver's points, after the user authorizes their export."""

import pytest
from application_client import fixtures as fx
from application_client import pqb
from application_client.flows import EXPORT, choose, refused
from application_client.pqb_command_sender import Errors, PqbCommandSender
from ragger.error import ExceptionRAPDU


def authorize(backend, device, navigator, v, compare=None):
    client = PqbCommandSender(backend)
    with client.authorize_menu_points(v):
        choose(device, navigator, True, EXPORT, compare)
    assert client.get_async_response().data == b""
    backend.wait_for_home_screen()


def test_menu_points(backend, device, navigator, test_name, default_screenshot_path):
    client = PqbCommandSender(backend)
    v = 0
    authorize(backend, device, navigator, v, (test_name, default_screenshot_path))
    for stage in range(3):
        for variant in range(4):
            expected = pqb.menu_points(fx.seed(v), stage, variant)
            if expected is None:
                refused(Errors.SW_INVALID_DATA, client.menu_points, v, stage, variant, 0, 1)
            else:
                assert client.all_menu_points(v, stage, variant) == expected
    # Stage 0's R never has x-coordinate r + n: variants 2 and 3 don't exist.
    assert pqb.menu_points(fx.seed(v), 0, 2) is None
    refused(Errors.SW_INVALID_DATA, client.menu_points, v, 0, 2, 0, 1)
    refused(Errors.SW_INVALID_DATA, client.menu_points, v, 0, 3, 5, 7)
    # Each stage's r: seed-derived for stage 0, 0x81 for stages 1 and 2.
    for stage in range(3):
        assert client.menu_r(v, stage) == pqb.menu_r(fx.seed(v), stage)
    assert client.menu_r(v, 1) == client.menu_r(v, 2) == 0x81
    refused(Errors.SW_INVALID_DATA, client.menu_r, v, 3)
    refused(Errors.SW_WRONG_DATA_LENGTH, client.send, 0x42, 2, bytes(4))
    # Only the authorized vault.
    refused(Errors.SW_NOT_AUTHORIZED, client.menu_points, 1, 1, 0, 0, 1)
    refused(Errors.SW_NOT_AUTHORIZED, client.menu_r, 1, 0)
    # Exporting points changes no vault's state.
    assert client.get_state().records == 0


def test_menu_points_authorization_moves(backend, device, navigator, test_name, default_screenshot_path):
    client = PqbCommandSender(backend)
    authorize(backend, device, navigator, 5)
    assert client.menu_points(5, 1, 1, 9, 7) == pqb.menu_points(fx.seed(5), 1, 1)[9:16]
    # Authorizing another vault ends the first one's authorization.
    authorize(backend, device, navigator, 0x7FFFFFFF)
    refused(Errors.SW_NOT_AUTHORIZED, client.menu_points, 5, 1, 1, 0, 1)
    assert client.menu_points(0x7FFFFFFF, 2, 0, 0, 3) == pqb.menu_points(fx.seed(0x7FFFFFFF), 2, 0)[:3]
    # A cancelled request ends it too.
    with pytest.raises(ExceptionRAPDU) as e:
        with client.authorize_menu_points(5):
            choose(device, navigator, False, EXPORT, (test_name, default_screenshot_path))
    assert e.value.status == Errors.SW_DENY
    backend.wait_for_home_screen()
    refused(Errors.SW_NOT_AUTHORIZED, client.menu_points, 0x7FFFFFFF, 2, 0, 0, 1)
