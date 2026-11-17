"""Screen navigation for the PQB app's reviews, on Nano (buttons) and touch screens.

Each helper takes an optional `(test_name, path)` pair: given one, it compares
the screens it goes through with the golden snapshots.
"""

from typing import Optional, Tuple

import pytest
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID

from . import fixtures as fx
from .bitcoin import Tx
from .pqb_command_sender import Errors, Kind, PqbCommandSender, WithdrawRequest

Compare = Optional[Tuple[str, object]]


def refused(status, fn, *args):
    with pytest.raises(ExceptionRAPDU) as e:
        fn(*args)
    assert e.value.status == status, hex(e.value.status)


def _until(navigator, nav, validation, text, compare: Compare, **waits):
    if compare:
        name, path = compare
        navigator.navigate_until_text_and_compare(nav, validation, text, path, name, **waits)
    else:
        navigator.navigate_until_text(nav, validation, text, **waits)


def _navigate(navigator, instructions, compare: Compare, **waits):
    if compare:
        name, path = compare
        navigator.navigate_and_compare(path, name, instructions, **waits)
    else:
        navigator.navigate(instructions, **waits)


def choose(device, navigator, confirm: bool, texts: Tuple[str, str], compare: Compare = None, **waits):
    """Answer an NBGL choice page (first use, retire, menu points export).

    `texts`: the confirm and reject buttons. Nano pages through the question to the button.
    """
    if device.is_nano:
        text = texts[0] if confirm else texts[1]
        _until(navigator, NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], f"^{text}$", compare,
               screen_change_after_last_instruction=False, **waits)
        return
    instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM if confirm else NavInsID.USE_CASE_CHOICE_REJECT]
    _navigate(navigator, instructions, compare, screen_change_after_last_instruction=False, **waits)


FIRST_USE = ("Yes, first use", "No, used before")
RETIRE = ("Retire", "Cancel")
EXPORT = ("Export", "Cancel")


def dismiss(device, navigator, compare: Compare = None, **waits):
    """Close an NBGL action page (no history, conflict) with its only button."""
    instructions = [NavInsID.BOTH_CLICK] if device.is_nano else [NavInsID.CENTERED_FOOTER_TAP]
    _navigate(navigator, instructions, compare, screen_change_after_last_instruction=False, **waits)


def generic_review(device, navigator, button: str, confirm: bool, compare: Compare = None, **waits):
    """Page through a generic review ending on an info button (Create, OK).

    `confirm` presses the button; otherwise the review is rejected from its last page.
    """
    if device.is_nano:
        nav, validation = NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK]
        text = f"^{button}$" if confirm else "^(Reject|Back)$"
    else:
        nav, text = NavInsID.USE_CASE_REVIEW_TAP, f"^{button}$"
        validation = [NavInsID.USE_CASE_CHOICE_CONFIRM if confirm else NavInsID.USE_CASE_REVIEW_REJECT]
    _until(navigator, nav, validation, text, compare, screen_change_after_last_instruction=False, **waits)


def hold_review(device, navigator, confirm: bool, compare: Compare = None, **waits):
    """The disclosure review: a long press on touch screens, a "Disclose" button on Nano."""
    if device.is_nano:
        nav, validation = NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK]
        text = "^Disclose$" if confirm else "^Reject$"
    else:
        nav, text = NavInsID.USE_CASE_REVIEW_TAP, "^Hold to disclose$"
        validation = [NavInsID.USE_CASE_REVIEW_CONFIRM if confirm else NavInsID.USE_CASE_REVIEW_REJECT]
    _until(navigator, nav, validation, text, compare, screen_change_after_last_instruction=False, **waits)


def sub(compare: Compare, part: str) -> Compare:
    return (f"{compare[0]}/{part}", compare[1]) if compare else None


# --- whole operations ------------------------------------------------------


def allocate(backend, device, navigator, first: bool = False, compare: Compare = None) -> Tuple[int, bytes, bytes]:
    """ALLOCATE, answering the first-use question when `first`, and approve."""
    client = PqbCommandSender(backend)
    with client.allocate():
        if first:
            choose(device, navigator, True, FIRST_USE, sub(compare, "1_first_use"))
            backend.wait_for_text_on_screen("Create PQB")
        generic_review(device, navigator, "Create", True, sub(compare, "2_create") if first else compare,
                       screen_change_before_first_instruction=not first)
    backend.wait_for_home_screen()
    return client.unpack_allocation(client.get_async_response().data)


def sign_sweep(backend, scenario_navigator, v: int, tx: Tx, prevs, kind: Kind = Kind.SWEEP,
               test_name: Optional[str] = None):
    """Stream, approve and sign a deposit-key transaction; returns the signatures."""
    client = PqbCommandSender(backend)
    client.stream_deposit(kind, v, tx, prevs)
    with client.deposit_review():
        scenario_navigator.review_approve_with_spinner(
            "Signing transaction", test_name=test_name, do_comparison=test_name is not None)
    assert client.get_async_response().data == b""
    sigs = [client.deposit_sign(i) for i in range(len(tx.inputs))]
    backend.wait_for_home_screen()
    return sigs


def allocate_and_fund(backend, device, navigator, scenario_navigator, value: int = 100_000) -> Tx:
    """Allocate vault 0 on a fresh device and sweep `value` into it; returns the sweep."""
    v, _, _ = allocate(backend, device, navigator, first=True)
    assert v == 0
    tx, prevs = fx.sweep(0, [value + 1_000], value)
    sign_sweep(backend, scenario_navigator, 0, tx, prevs)
    return tx


def withdraw(backend, device, navigator, req: WithdrawRequest, compare: Compare = None):
    """Stream, approve and read one disclosure."""
    client = PqbCommandSender(backend)
    client.stream_withdraw(req)
    with client.withdraw_review():
        hold_review(device, navigator, True, compare)
    assert client.get_async_response().data == b""
    backend.wait_for_text_on_screen("Disclosing secrets")
    disclosure = client.read_disclosure()
    backend.wait_for_home_screen()
    return disclosure


def withdraw_refused(backend, device, navigator, req: WithdrawRequest, status: int, compare: Compare = None):
    """A WITHDRAW whose REVIEW is refused; the conflict page is dismissed."""
    client = PqbCommandSender(backend)
    client.stream_withdraw(req)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.withdraw_review():
            if status == Errors.SW_CONFLICT:
                dismiss(device, navigator, compare)
    assert e.value.status == status, hex(e.value.status)
    backend.wait_for_home_screen()
