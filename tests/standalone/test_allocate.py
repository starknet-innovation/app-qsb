"""ALLOCATE, the first-use question, and GET_VAULT on the device."""

import pytest
from application_client import fixtures as fx
from application_client.flows import FIRST_USE, allocate, choose, dismiss, generic_review, refused, sub
from application_client.pqb_command_sender import Errors, PqbCommandSender, Status
from ragger.error import ExceptionRAPDU


def test_allocate(backend, device, navigator, test_name, default_screenshot_path):
    compare = (test_name, default_screenshot_path)
    client = PqbCommandSender(backend)
    # The first allocation asks whether the seed ever held PQB vaults.
    v, root, script_hash = allocate(backend, device, navigator, first=True, compare=compare)
    assert (v, root, script_hash) == (0, fx.root(0), fx.script_hash(0))
    state = client.get_state()
    assert (state.namespace, state.next_v, state.records) == (1, 1, 1)
    vault = client.get_vault(0)
    assert (vault.status, vault.funded) == (Status.ALLOCATED, False)
    assert (vault.root, vault.script_hash) == (fx.root(0), fx.script_hash(0))
    # Above the high-water mark of a fresh namespace: not allocated.
    assert client.get_vault(1).status == Status.NOT_ALLOCATED
    assert client.get_vault(0x7FFFFFFF).status == Status.NOT_ALLOCATED
    # The second allocation goes straight to the review.
    v, root, script_hash = allocate(backend, device, navigator, compare=sub(compare, "3_second"))
    assert (v, root, script_hash) == (1, fx.root(1), fx.script_hash(1))
    assert client.get_vault(1).status == Status.ALLOCATED
    state = client.get_state()
    assert (state.namespace, state.next_v, state.records) == (1, 2, 2)
    # The records, in order.
    for i in range(2):
        record = client.get_record(i)
        assert (record.layout, record.wallet_id, record.v, record.state, record.flags) == (1, state.wallet_id, i, 1, 0)
        assert (record.root, record.script_hash) == (fx.root(i), fx.script_hash(i))
        assert record.raw[87:] == bytes(251 - 87)
    refused(Errors.SW_INVALID_DATA, client.get_record, 2)


def test_get_vault_display(backend, device, navigator, test_name, default_screenshot_path):
    client = PqbCommandSender(backend)
    allocate(backend, device, navigator, first=True)
    with client.get_vault_display(0):
        generic_review(device, navigator, "OK", True, (test_name, default_screenshot_path))
    vault = client.unpack_vault(client.get_async_response().data)
    assert (vault.root, vault.status, vault.funded) == (fx.root(0), Status.ALLOCATED, False)
    backend.wait_for_home_screen()


def test_get_vault_display_back(backend, device, navigator, test_name, default_screenshot_path):
    """A vault the device has no history for: the review warns not to fund it."""
    client = PqbCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_vault_display(7):
            generic_review(device, navigator, "OK", False, (test_name, default_screenshot_path))
    assert e.value.status == Errors.SW_DENY
    backend.wait_for_home_screen()


def test_allocate_reject(backend, device, navigator, test_name, default_screenshot_path):
    client = PqbCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.allocate():
            choose(device, navigator, True, FIRST_USE)
            backend.wait_for_text_on_screen("Create PQB")
            generic_review(device, navigator, "Create", False, (test_name, default_screenshot_path),
                           screen_change_before_first_instruction=False)
    assert e.value.status == Errors.SW_DENY
    backend.wait_for_home_screen()
    # Nothing recorded, not even the namespace: the question comes again.
    state = client.get_state()
    assert (state.namespace, state.next_v, state.records) == (0, 0, 0)
    assert client.get_vault(0).status == Status.NO_HISTORY
    v, _, _ = allocate(backend, device, navigator, first=True)
    assert v == 0


def test_allocate_used_before(backend, device, navigator, test_name, default_screenshot_path):
    compare = (test_name, default_screenshot_path)
    client = PqbCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.allocate():
            choose(device, navigator, False, FIRST_USE, sub(compare, "1_first_use"))
            backend.wait_for_text_on_screen("No safe history")
            dismiss(device, navigator, sub(compare, "2_no_history"), screen_change_before_first_instruction=False)
    assert e.value.status == Errors.SW_CONTINUITY
    backend.wait_for_home_screen()
    # The namespace is recorded unknown: no allocation, ever.
    state = client.get_state()
    assert (state.namespace, state.next_v, state.records) == (2, 0, 0)
    assert client.get_vault(0).status == Status.NO_HISTORY
    with pytest.raises(ExceptionRAPDU) as e:
        with client.allocate():
            dismiss(device, navigator)
    assert e.value.status == Errors.SW_CONTINUITY
    backend.wait_for_home_screen()
    assert client.get_state().namespace == 2
