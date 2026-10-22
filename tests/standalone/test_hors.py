"""QSB-HORS-v1: secrets derived on the device, commitments, and the guarded reveal.

Expected values come from tests/application_client/hors.py with Speculos's
default seed, so these tests also check the SLIP-0021 derivation end to end.
"""

import struct

import pytest
from application_client import hors
from application_client.bitcoin import hash160
from application_client.qsb_command_sender import Errors, Ins, QsbCommandSender
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID

K = hors.app_key()
MAINNET, TESTNET = 0x00, 0x01
P2TR = bytes.fromhex("5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
ROUND1 = [9, 3, 140, 0, 1, 2, 4, 5]
ROUND2 = [149, 7, 8, 10, 11, 12, 13]
BINDING = bytes([0xAB]) * 32


def refused(status, fn, *args):
    with pytest.raises(ExceptionRAPDU) as e:
        fn(*args)
    assert e.value.status == status, hex(e.value.status)


def test_hors_version(backend):
    version, spec = QsbCommandSender(backend).hors_version()
    assert spec == "QSB-HORS-v1"
    assert version == QsbCommandSender(backend).get_version()


@pytest.mark.parametrize("v", [0, 7, 0x7FFFFFFF])
def test_commitments_and_root_match_the_reference(backend, v):
    client = QsbCommandSender(backend)
    commitments = client.all_commitments(MAINNET, v)
    assert commitments == [hors.commitments(K, MAINNET, v, 0), hors.commitments(K, MAINNET, v, 1)]
    assert client.get_commitment_root(MAINNET, v) == hors.root(K, MAINNET, v)


def test_hors_refusals(backend):
    client = QsbCommandSender(backend)
    # Test networks are refused by this mainnet build.
    refused(Errors.SW_WRONG_NETWORK, client.get_commitment_root, TESTNET, 0)
    refused(Errors.SW_WRONG_NETWORK, client.get_commitments, TESTNET, 0, 0, 0, 1)
    # Out of range: vault index, round, chunk size, end of round.
    refused(Errors.SW_INVALID_DATA, client.get_commitment_root, MAINNET, 0x80000000)
    refused(Errors.SW_INVALID_DATA, client.get_commitments, MAINNET, 0, 0, 139, 12)
    refused(Errors.SW_INVALID_DATA, client.get_commitments, MAINNET, 0, 0, 0, 13)
    refused(Errors.SW_INVALID_DATA, client.get_commitments, MAINNET, 0, 0, 0, 0)
    refused(Errors.SW_WRONG_P1P2, client.send, Ins.GET_COMMITMENTS, 2, struct.pack(">BIHB", 0, 0, 0, 1))
    refused(Errors.SW_WRONG_P1P2, client.send, Ins.GET_COMMITMENT_ROOT, 2, struct.pack(">BI", 0, 0))
    refused(Errors.SW_WRONG_P1P2, client.send, Ins.REVEAL_READ, 2)
    refused(Errors.SW_INVALID_DATA, client.send, Ins.GET_COMMITMENT_ROOT, 0, b"\x00\x00\x00")
    # No approved reveal to read.
    refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 0)
    refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 1)
    # Commands without data refuse trailing bytes.
    refused(Errors.SW_INVALID_DATA, client.send, Ins.HORS_GET_VERSION, 0, b"\x00")
    refused(Errors.SW_INVALID_DATA, client.send, Ins.REVEAL_READ, 0, b"\x00")


@pytest.mark.parametrize(
    "round1, round2, destination, net, status",
    [
        (ROUND1[:-1] + [150], ROUND2, P2TR, MAINNET, Errors.SW_INVALID_DATA),  # index out of range
        (ROUND1[:-1] + [9], ROUND2, P2TR, MAINNET, Errors.SW_INVALID_DATA),  # repeated in round 1
        (ROUND1, ROUND2[:-1] + [149], P2TR, MAINNET, Errors.SW_INVALID_DATA),  # repeated in round 2
        (ROUND1, ROUND2, bytes.fromhex("6a0100"), MAINNET, Errors.SW_INVALID_DATA),  # no address
        (ROUND1, ROUND2, P2TR, TESTNET, Errors.SW_WRONG_NETWORK),
    ],
)
def test_reveal_prepare_refusals(backend, round1, round2, destination, net, status):
    client = QsbCommandSender(backend)
    payload = client.reveal_payload(net, 3, round1, round2, BINDING, 92_083, destination)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.reveal_prepare(payload):
            pass
    assert e.value.status == status
    refused(Errors.SW_INVALID_DATA, client.send, Ins.REVEAL_PREPARE, 0, payload[:-1])


def expected_preimages(v, round1=ROUND1, round2=ROUND2):
    return [hors.secret(K, MAINNET, v, 0, i) for i in round1] + [hors.secret(K, MAINNET, v, 1, i) for i in round2]


def read_reveal(client, v, round1=ROUND1, round2=ROUND2):
    preimages = client.reveal_read(0) + client.reveal_read(1)
    assert preimages == expected_preimages(v, round1, round2)
    commitments = [hors.commitments(K, MAINNET, v, 0), hors.commitments(K, MAINNET, v, 1)]
    for p, (r, i) in zip(preimages, [(0, i) for i in round1] + [(1, i) for i in round2]):
        assert hash160(p) == commitments[r][i]
    return preimages


# --- Screens ---------------------------------------------------------------
# A reveal review ends on a long press on touch screens, and on a "Reveal"
# button confirmed with both buttons on Nano (NBGL has no long press there).


def approve_reveal(device, navigator, test_name=None, path=None, chained=False):
    """`chained`: the review is already on screen (it followed another page)."""
    if device.is_nano:
        nav, validation, text = NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "^Reveal$"
    else:
        nav, validation, text = NavInsID.USE_CASE_REVIEW_TAP, [NavInsID.USE_CASE_REVIEW_CONFIRM], "^Hold to reveal$"
    waits = dict(screen_change_before_first_instruction=not chained, screen_change_after_last_instruction=False)
    if test_name:
        navigator.navigate_until_text_and_compare(nav, validation, text, path, test_name, **waits)
    else:
        navigator.navigate_until_text(nav, validation, text, **waits)


def reject_reveal(device, navigator, test_name, path):
    if device.is_nano:
        nav, validation, text = NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "^Reject$"
    else:
        nav, validation, text = NavInsID.USE_CASE_REVIEW_TAP, [NavInsID.USE_CASE_REVIEW_REJECT], "^Hold to reveal$"
    navigator.navigate_until_text_and_compare(nav, validation, text, path, test_name)


def choose(device, navigator, confirm, test_name=None, path=None):
    """Answer an NBGL choice page (fingerprint OK/Back, Forget/Cancel)."""
    if device.is_nano:
        instructions = [NavInsID.RIGHT_CLICK] * (1 if confirm else 2) + [NavInsID.BOTH_CLICK]
    else:
        instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM if confirm else NavInsID.USE_CASE_CHOICE_REJECT]
    if test_name:
        navigator.navigate_and_compare(path, test_name, instructions)
    else:
        navigator.navigate(instructions)


def reveal(backend, device, navigator, v, round1=ROUND1, round2=ROUND2, binding=BINDING, **compare):
    """Approve a reveal, read both chunks, and wait for the status to clear."""
    client = QsbCommandSender(backend)
    with client.reveal_prepare(client.reveal_payload(MAINNET, v, round1, round2, binding, 92_083, P2TR)):
        approve_reveal(device, navigator, **compare)
    backend.wait_for_text_on_screen("Revealing secrets")
    preimages = read_reveal(client, v, round1, round2)
    backend.wait_for_home_screen()
    return preimages


def test_reveal(backend, device, navigator, test_name, default_screenshot_path):
    client = QsbCommandSender(backend)
    reveal(backend, device, navigator, 3, test_name=test_name, path=default_screenshot_path)
    # The approval is spent once chunk 1 is read.
    refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 0)


def test_re_reveal(backend, device, navigator, test_name, default_screenshot_path):
    first = reveal(backend, device, navigator, 4)
    # The same indices for the same withdrawal: allowed, as a retry.
    again = reveal(backend, device, navigator, 4, test_name=test_name, path=default_screenshot_path)
    assert again == first


def test_reveal_conflict(backend, device, navigator, test_name, default_screenshot_path):
    client = QsbCommandSender(backend)
    reveal(backend, device, navigator, 5)
    for round1, binding in [(ROUND1[::-1], BINDING), (ROUND1, bytes(32))]:
        payload = client.reveal_payload(MAINNET, 5, round1, ROUND2, binding, 92_083, P2TR)
        with pytest.raises(ExceptionRAPDU) as e:
            with client.reveal_prepare(payload):
                instructions = [NavInsID.BOTH_CLICK] if device.is_nano else [NavInsID.CENTERED_FOOTER_TAP]
                navigator.navigate_and_compare(default_screenshot_path, test_name, instructions)
        assert e.value.status == Errors.SW_REVEAL_CONFLICT
        backend.wait_for_home_screen()
    refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 0)


def test_reveal_reject(backend, device, navigator, test_name, default_screenshot_path):
    client = QsbCommandSender(backend)
    payload = client.reveal_payload(MAINNET, 6, ROUND1, ROUND2, BINDING, 92_083, P2TR)
    with pytest.raises(ExceptionRAPDU) as e:
        with client.reveal_prepare(payload):
            reject_reveal(device, navigator, test_name, default_screenshot_path)
    assert e.value.status == Errors.SW_DENY
    backend.wait_for_home_screen()
    refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 0)
    # Nothing was recorded: a different reveal for the vault is a first reveal.
    reveal(backend, device, navigator, 6, round1=ROUND1[::-1])


def check_fingerprint(device, navigator, confirm, test_name, path):
    """Page through the fingerprint review, then OK or Back."""
    if device.is_nano:
        nav, validation = NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK]
        text = "^OK$" if confirm else "^Back$"
    else:
        nav, text = NavInsID.USE_CASE_REVIEW_TAP, "^OK$"
        validation = [NavInsID.USE_CASE_CHOICE_CONFIRM if confirm else NavInsID.USE_CASE_REVIEW_REJECT]
    navigator.navigate_until_text_and_compare(nav, validation, text, path, test_name)


@pytest.mark.parametrize("confirm", [True, False])
def test_commitment_root_display(backend, device, navigator, test_name, default_screenshot_path, confirm):
    # One snapshot folder per variant: OK and Back end on different pages.
    test_name = f"{test_name}_{'ok' if confirm else 'back'}"
    client = QsbCommandSender(backend)
    if confirm:
        with client.get_commitment_root_with_confirmation(MAINNET, 7):
            check_fingerprint(device, navigator, True, test_name, default_screenshot_path)
        assert client.get_async_response().data == hors.root(K, MAINNET, 7)
    else:
        with pytest.raises(ExceptionRAPDU) as e:
            with client.get_commitment_root_with_confirmation(MAINNET, 7):
                check_fingerprint(device, navigator, False, test_name, default_screenshot_path)
        assert e.value.status == Errors.SW_DENY
    backend.wait_for_home_screen()


def test_reveal_expires_after_60_seconds(backend, device, navigator):
    client = QsbCommandSender(backend)
    with client.reveal_prepare(client.reveal_payload(MAINNET, 8, ROUND1, ROUND2, BINDING, 92_083, P2TR)):
        approve_reveal(device, navigator)
    backend.wait_for_text_on_screen("Revealing secrets")
    # Drive the 100 ms ticker by hand. A few real ticks pass before the pause.
    backend.pause_ticker()
    try:
        for _ in range(500):
            backend.send_tick()
        assert client.reveal_read(0) == expected_preimages(8)[:12]
        for _ in range(110):
            backend.send_tick()
        refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 1)
    finally:
        backend.resume_ticker()
    backend.wait_for_home_screen()


class TestGuardFull:
    """64 vaults recorded, then a 65th: the device asks to forget the oldest."""

    def test_guard_full(self, backend, device, navigator, test_name, default_screenshot_path):
        if device.name != "nanosp":
            pytest.skip("64 approvals: run on one device")
        client = QsbCommandSender(backend)
        for v in range(100, 164):
            # Approved and recorded; the next REVEAL_PREPARE replaces the unread approval.
            with client.reveal_prepare(client.reveal_payload(MAINNET, v, ROUND1, ROUND2, BINDING, 1, P2TR)):
                approve_reveal(device, navigator)
            backend.wait_for_text_on_screen("Revealing secrets")
        # Full: forgetting vault 100 is declined, then accepted.
        payload = client.reveal_payload(MAINNET, 200, ROUND1, ROUND2, BINDING, 92_083, P2TR)
        with pytest.raises(ExceptionRAPDU) as e:
            with client.reveal_prepare(payload):
                choose(device, navigator, False)
        assert e.value.status == Errors.SW_DENY
        backend.wait_for_home_screen()
        with client.reveal_prepare(payload):
            choose(device, navigator, True, test_name, default_screenshot_path)
            approve_reveal(device, navigator, chained=True)
        backend.wait_for_text_on_screen("Revealing secrets")
        read_reveal(client, 200)
        backend.wait_for_home_screen()
        # Vault 100 was forgotten: a different reveal for it is new again (and
        # evicts vault 101). Vault 102 is still guarded.
        conflict = client.reveal_payload(MAINNET, 102, ROUND1[::-1], ROUND2, BINDING, 1, P2TR)
        with pytest.raises(ExceptionRAPDU) as e:
            with client.reveal_prepare(conflict):
                navigator.navigate([NavInsID.BOTH_CLICK])
        assert e.value.status == Errors.SW_REVEAL_CONFLICT
        backend.wait_for_home_screen()
        with client.reveal_prepare(client.reveal_payload(MAINNET, 100, ROUND1[::-1], ROUND2, BINDING, 1, P2TR)):
            choose(device, navigator, True)
            approve_reveal(device, navigator, chained=True)
        backend.wait_for_text_on_screen("Revealing secrets")


def approved(backend, device, navigator, v, round1=ROUND1):
    client = QsbCommandSender(backend)
    with client.reveal_prepare(client.reveal_payload(MAINNET, v, round1, ROUND2, BINDING, 92_083, P2TR)):
        approve_reveal(device, navigator)
    backend.wait_for_text_on_screen("Revealing secrets")
    return client


def test_refused_prepare_ends_the_approval(backend, device, navigator):
    client = approved(backend, device, navigator, 9)
    # A new REVEAL_PREPARE replaces the approval even when it is refused before
    # any screen; the spinner goes too.
    bad = client.reveal_payload(MAINNET, 9, ROUND1[:-1] + [150], ROUND2, BINDING, 92_083, P2TR)
    refused(Errors.SW_INVALID_DATA, client.send, Ins.REVEAL_PREPARE, 0, bad)
    backend.wait_for_home_screen()
    refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 0)


def test_reading_chunk_1_ends_the_approval(backend, device, navigator):
    client = approved(backend, device, navigator, 10)
    assert client.reveal_read(1) == expected_preimages(10)[12:]
    backend.wait_for_home_screen()
    refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, 0)


def test_fingerprint_warns_once_revealed(backend, device, navigator, test_name, default_screenshot_path):
    client = approved(backend, device, navigator, 12)
    assert len(client.reveal_read(0) + client.reveal_read(1)) == 15
    backend.wait_for_home_screen()
    with client.get_commitment_root_with_confirmation(MAINNET, 12):
        check_fingerprint(device, navigator, True, test_name, default_screenshot_path)
    assert client.get_async_response().data == hors.root(K, MAINNET, 12)
    backend.wait_for_home_screen()

