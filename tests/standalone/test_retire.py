"""RETIRE: a vault that can never disclose again."""

import pytest
from application_client import fixtures as fx
from application_client.bitcoin import TxOut
from application_client.flows import RETIRE, allocate, allocate_and_fund, choose, refused, withdraw
from application_client.pqb_command_sender import Errors, Ins, PqbCommandSender, Status, idx
from application_client.verify import check_disclosure
from ragger.error import ExceptionRAPDU


def test_retire_exposed_vault(backend, device, navigator, scenario_navigator, test_name, default_screenshot_path):
    client = PqbCommandSender(backend)
    sweep = allocate_and_fund(backend, device, navigator, scenario_navigator)
    req = fx.withdrawal(0, sweep, 0, [TxOut(95_000, fx.P2TR_DESTINATION)])
    check_disclosure(req, withdraw(backend, device, navigator, req))
    assert client.get_vault(0).status == Status.EXPOSED
    with client.retire(0):
        choose(device, navigator, True, RETIRE, (test_name, default_screenshot_path))
    assert client.get_async_response().data == b""
    backend.wait_for_home_screen()
    # In a fresh namespace the record is dropped; the index stays reserved.
    vault = client.get_vault(0)
    assert (vault.status, vault.funded) == (Status.RESERVED, False)
    state = client.get_state()
    assert (state.namespace, state.next_v, state.records) == (1, 1, 0)
    # Not even the exact retry.
    client.stream_withdraw(req)
    refused(Errors.SW_VAULT_STATE, client.send, Ins.WITHDRAW, 3)
    refused(Errors.SW_VAULT_STATE, client.send, Ins.RETIRE, 0, idx(0))
    # The next allocation takes the next index.
    v, _, _ = allocate(backend, device, navigator)
    assert v == 1


def test_retire_cancel(backend, device, navigator, test_name, default_screenshot_path):
    client = PqbCommandSender(backend)
    allocate(backend, device, navigator, first=True)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.retire(0):
            choose(device, navigator, False, RETIRE, (test_name, default_screenshot_path))
    assert e.value.status == Errors.SW_DENY
    backend.wait_for_home_screen()
    assert client.get_vault(0).status == Status.ALLOCATED
    assert client.get_state().records == 1
