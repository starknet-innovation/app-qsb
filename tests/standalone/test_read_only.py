"""Silent queries: commitments, scripts, vault status, deposit addresses and state.

Expected values come from tests/application_client/pqb.py with Speculos's
default seed, so these tests also check the BIP 85 derivation end to end.
"""

import struct

import pytest
from application_client import fixtures as fx
from application_client import pqb
from application_client.bitcoin import sha256
from application_client.flows import refused
from application_client.pqb_command_sender import Errors, Ins, PqbCommandSender, Status, idx

# Speculos's default seed.
WALLET_ID = bytes.fromhex("76d84aced6d909d41da0557e378886f3")
ROOT_0 = bytes.fromhex("d2cab469997de4f1640caacdb783c9249de3d6bcc05ee449c2a8251ad1ca1229")


def test_reference_values():
    """The reference agrees with the values recorded for Speculos's seed."""
    assert pqb.wallet_id() == WALLET_ID
    assert fx.root(0) == ROOT_0


@pytest.mark.parametrize("v", [0, 5, 0x7FFFFFFF])
def test_vault_matches_the_reference(backend, v):
    client = PqbCommandSender(backend)
    commitments = client.all_commitments(v)
    assert len(commitments) == 154
    assert commitments == list(fx.commitments(v))
    script = client.get_script(v)
    assert len(script) == pqb.SCRIPT_LEN
    assert script == fx.script(v)
    vault = client.get_vault(v)
    assert vault.root == fx.root(v) == pqb.root(fx.seed(v), commitments)
    assert vault.script_hash == sha256(script)
    # A fresh device: no namespace for this seed, so no trustworthy history.
    assert vault.status == Status.NO_HISTORY
    assert not vault.funded
    pubkey, address = client.get_deposit_address(v)
    assert pubkey == fx.deposit_pubkey(v)
    assert address == fx.deposit_address(v)
    assert address.startswith("bc1q")


def test_commitment_and_script_chunks(backend):
    client = PqbCommandSender(backend)
    # Any window of commitments, in root order.
    assert client.get_commitments(0, 150, 4) == list(fx.commitments(0)[150:154])
    assert client.get_commitments(0, 153, 1) == [fx.commitments(0)[153]]
    # The script's last chunk is short; any offset is allowed.
    end = pqb.SCRIPT_LEN
    assert client.get_script_chunk(0, end - 8) == fx.script(0)[end - 8:]
    assert client.get_script_chunk(0, end - 1) == fx.script(0)[end - 1:]
    assert client.get_script_chunk(0, 1) == fx.script(0)[1:251]


def test_state_of_a_fresh_device(backend):
    client = PqbCommandSender(backend)
    state = client.get_state()
    assert state.wallet_id == WALLET_ID
    assert (state.namespace, state.next_v, state.records, state.capacity) == (0, 0, 0, 32)
    refused(Errors.SW_INVALID_DATA, client.get_record, 0)


def test_read_only_refusals(backend):
    client = PqbCommandSender(backend)
    send = client.send
    big = idx(0x80000000)
    # GET_COMMITMENTS: count 1..=12, start + count <= 154, v < 2^31, 6 bytes.
    for start, count in [(0, 0), (0, 13), (143, 12), (154, 1), (153, 2)]:
        refused(Errors.SW_INVALID_DATA, send, Ins.GET_COMMITMENTS, 0, idx(0) + bytes([start, count]))
    refused(Errors.SW_INVALID_DATA, send, Ins.GET_COMMITMENTS, 0, big + bytes([0, 1]))
    refused(Errors.SW_WRONG_DATA_LENGTH, send, Ins.GET_COMMITMENTS, 0, idx(0) + bytes([0]))
    refused(Errors.SW_WRONG_DATA_LENGTH, send, Ins.GET_COMMITMENTS, 0, idx(0) + bytes([0, 1, 0]))
    # GET_VAULT, GET_DEPOSIT_ADDRESS, RETIRE, MENU_POINTS authorize: v (4).
    for ins, p1 in [(Ins.GET_VAULT, 0), (Ins.GET_VAULT, 1), (Ins.GET_DEPOSIT_ADDRESS, 0),
                    (Ins.GET_DEPOSIT_ADDRESS, 1), (Ins.RETIRE, 0), (Ins.MENU_POINTS, 0)]:
        refused(Errors.SW_INVALID_DATA, send, ins, p1, big)
        refused(Errors.SW_WRONG_DATA_LENGTH, send, ins, p1, b"\x00\x00\x00")
        refused(Errors.SW_WRONG_DATA_LENGTH, send, ins, p1, b"\x00\x00\x00\x00\x00")
    # GET_SCRIPT: v (4) || offset (2), offset < 4696.
    refused(Errors.SW_INVALID_DATA, send, Ins.GET_SCRIPT, 0, idx(0) + struct.pack(">H", pqb.SCRIPT_LEN))
    refused(Errors.SW_INVALID_DATA, send, Ins.GET_SCRIPT, 0, big + struct.pack(">H", 0))
    refused(Errors.SW_WRONG_DATA_LENGTH, send, Ins.GET_SCRIPT, 0, idx(0))
    # GET_STATE: no data for the summary, one byte for a record.
    refused(Errors.SW_WRONG_DATA_LENGTH, send, Ins.GET_STATE, 0, b"\x00")
    refused(Errors.SW_WRONG_DATA_LENGTH, send, Ins.GET_STATE, 1, b"")
    refused(Errors.SW_WRONG_DATA_LENGTH, send, Ins.GET_STATE, 1, b"\x00\x00")
    # ALLOCATE takes no data.
    refused(Errors.SW_WRONG_DATA_LENGTH, send, Ins.ALLOCATE, 0, b"\x00")
    # The vault's state refuses these before any screen.
    refused(Errors.SW_VAULT_STATE, send, Ins.GET_DEPOSIT_ADDRESS, 1, idx(0))
    refused(Errors.SW_VAULT_STATE, send, Ins.RETIRE, 0, idx(0))


def test_reveal_read_without_approval(backend):
    client = PqbCommandSender(backend)
    for chunk in range(5):
        refused(Errors.SW_NO_APPROVED_REVEAL, client.reveal_read, chunk)
    refused(Errors.SW_WRONG_DATA_LENGTH, client.send, Ins.REVEAL_READ, 0, b"\x00")


def test_menu_points_without_authorization(backend):
    client = PqbCommandSender(backend)
    for stage, variant in [(0, 0), (1, 1), (2, 3)]:
        refused(Errors.SW_NOT_AUTHORIZED, client.menu_points, 0, stage, variant, 0, 1)
    # Parameters are checked first.
    for stage, variant, start, count in [(3, 0, 0, 1), (0, 4, 0, 1), (0, 0, 0, 0), (0, 0, 0, 8),
                                         (0, 0, 6, 7), (1, 0, 10, 7)]:
        refused(Errors.SW_INVALID_DATA, client.menu_points, 0, stage, variant, start, count)
    refused(Errors.SW_WRONG_DATA_LENGTH, client.send, Ins.MENU_POINTS, 1, idx(0) + bytes([0, 0, 0]))


def test_session_start_refusals(backend):
    client = PqbCommandSender(backend)
    send = client.send
    # SIGN_DEPOSIT START: kind, inputs 1..=8, outputs (sweep 1, refund 1..=2), 15 bytes.
    def start(kind, v=0, n_in=1, n_out=1):
        return bytes([kind]) + idx(v) + struct.pack("<II", 2, 0) + bytes([n_in, n_out])
    refused(Errors.SW_WRONG_DATA_LENGTH, send, Ins.SIGN_DEPOSIT, 0, start(1)[:-1])
    refused(Errors.SW_BAD_LAYOUT, send, Ins.SIGN_DEPOSIT, 0, start(3))
    refused(Errors.SW_BAD_LAYOUT, send, Ins.SIGN_DEPOSIT, 0, start(1, n_in=0))
    refused(Errors.SW_BAD_LAYOUT, send, Ins.SIGN_DEPOSIT, 0, start(1, n_in=9))
    refused(Errors.SW_BAD_LAYOUT, send, Ins.SIGN_DEPOSIT, 0, start(1, n_out=2))
    refused(Errors.SW_BAD_LAYOUT, send, Ins.SIGN_DEPOSIT, 0, start(2, n_out=3))
    refused(Errors.SW_INVALID_DATA, send, Ins.SIGN_DEPOSIT, 0, start(1, v=0x80000000))
    # WITHDRAW START: 73 bytes.
    refused(Errors.SW_WRONG_DATA_LENGTH, send, Ins.WITHDRAW, 0, bytes(72))
    refused(Errors.SW_WRONG_DATA_LENGTH, send, Ins.WITHDRAW, 0, bytes(74))
