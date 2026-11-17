"""APDU client for the PQB app (docs/apdu.md), for the Ragger tests."""

import struct
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional, Sequence, Tuple

from ragger.backend.interface import RAPDU, BackendInterface

from . import pqb
from .bitcoin import Tx, sha256d

CLA = 0xE0
CHUNK = 255


class Ins(IntEnum):
    GET_VERSION = 0x03
    GET_APP_NAME = 0x04
    GET_COMMITMENTS = 0x10
    GET_VAULT = 0x11
    GET_SCRIPT = 0x12
    GET_DEPOSIT_ADDRESS = 0x13
    GET_STATE = 0x14
    ALLOCATE = 0x20
    RETIRE = 0x21
    SIGN_DEPOSIT = 0x30
    WITHDRAW = 0x40
    REVEAL_READ = 0x41
    MENU_POINTS = 0x42


class DepositStep(IntEnum):
    START = 0
    INPUT = 1
    PREVTX = 2
    OUTPUTS = 3
    REVIEW = 4
    SIGN = 5


class WithdrawStep(IntEnum):
    START = 0
    PREVTX = 1
    OUTPUTS = 2
    REVIEW = 3


class Kind(IntEnum):
    SWEEP = 1
    REFUND = 2


class Status(IntEnum):
    """GET_VAULT's status byte."""
    NOT_ALLOCATED = 0
    ALLOCATED = 1
    EXPOSED = 2
    RETIRED = 3
    UNKNOWN = 4
    RESERVED = 5
    NO_HISTORY = 6


class Errors(IntEnum):
    SW_DENY = 0x6985
    SW_INVALID_DATA = 0x6A80
    SW_WRONG_P1P2 = 0x6A86
    SW_WRONG_DATA_LENGTH = 0x6A87
    SW_CONFLICT = 0x6A90
    SW_NO_APPROVED_REVEAL = 0x6A91
    SW_STORE_CORRUPT = 0x6A93
    SW_VAULT_STATE = 0x6A94
    SW_CONTINUITY = 0x6A95
    SW_STORE_FULL = 0x6A96
    SW_NOT_AUTHORIZED = 0x6A97
    SW_INS_NOT_SUPPORTED = 0x6D00
    SW_CLA_NOT_SUPPORTED = 0x6E00
    SW_BAD_STATE = 0xB001
    SW_PARSE = 0xB003
    SW_TXID_MISMATCH = 0xB004
    SW_NOT_OWN_INPUT = 0xB005
    SW_NOT_VAULT = 0xB006
    SW_BAD_LAYOUT = 0xB007
    SW_UNSUPPORTED_OUTPUT = 0xB008
    SW_BAD_AMOUNT = 0xB009
    SW_SIGN_FAIL = 0xB00B
    SW_KEY_DERIVE_FAIL = 0xB00C


def chunks(data: bytes, size: int = CHUNK) -> List[bytes]:
    return [data[i:i + size] for i in range(0, len(data), size)]


def idx(v: int) -> bytes:
    return struct.pack(">I", v)


@dataclass
class Vault:
    root: bytes
    script_hash: bytes
    status: int
    funded: bool


@dataclass
class State:
    wallet_id: bytes
    namespace: int
    next_v: int
    records: int
    capacity: int


@dataclass
class Record:
    """GET_STATE P1=1: one 251-byte record."""
    raw: bytes

    @property
    def layout(self) -> int:
        return self.raw[0]

    @property
    def wallet_id(self) -> bytes:
        return self.raw[1:17]

    @property
    def v(self) -> int:
        return struct.unpack(">I", self.raw[17:21])[0]

    @property
    def state(self) -> int:
        return self.raw[21]

    @property
    def flags(self) -> int:
        return self.raw[22]

    @property
    def root(self) -> bytes:
        return self.raw[23:55]

    @property
    def script_hash(self) -> bytes:
        return self.raw[55:87]

    @property
    def funding_txid(self) -> bytes:
        return self.raw[87:119]

    @property
    def funding_vout(self) -> int:
        return struct.unpack("<I", self.raw[119:123])[0]

    @property
    def funding_value(self) -> int:
        return struct.unpack("<Q", self.raw[123:131])[0]

    @property
    def sweep_input(self) -> bytes:
        return self.raw[131:167]

    @property
    def round0(self) -> List[int]:
        return list(self.raw[167:175])

    @property
    def round1(self) -> List[int]:
        return list(self.raw[175:184])

    @property
    def picks(self) -> List[int]:
        return list(self.raw[184:187])

    @property
    def binding(self) -> bytes:
        return self.raw[187:219]

    @property
    def digest(self) -> bytes:
        return self.raw[219:251]


@dataclass
class Disclosure:
    """What REVEAL_READ returns, chunk by chunk."""
    s: List[bytes]
    w: List[bytes]
    menu_sigs: List[bytes]
    cosig: bytes
    q: bytes


@dataclass
class WithdrawRequest:
    v: int
    prev_tx: bytes  # witness-stripped transaction creating the vault output
    vout: int
    outputs: bytes  # serialized outputs, without their count
    n_outputs: int
    round0: Sequence[int]
    round1: Sequence[int]
    picks: Sequence[int]
    version: int = 2
    sequence: int = 0xFFFFFFFD
    locktime: int = 0
    prev_txid: Optional[bytes] = None

    def start(self) -> bytes:
        txid = self.prev_txid if self.prev_txid is not None else sha256d(self.prev_tx)
        return (
            idx(self.v) + struct.pack("<I", self.version) + txid + struct.pack("<I", self.vout)
            + struct.pack("<II", self.sequence, self.locktime) + bytes([self.n_outputs])
            + bytes(self.round0) + bytes(self.round1) + bytes(self.picks)
        )

    def unsigned_tx(self) -> bytes:
        """T: the withdrawal with an empty scriptSig and no witness."""
        txid = self.prev_txid if self.prev_txid is not None else sha256d(self.prev_tx)
        return (
            struct.pack("<I", self.version) + b"\x01" + txid + struct.pack("<I", self.vout) + b"\x00"
            + struct.pack("<I", self.sequence) + bytes([self.n_outputs]) + self.outputs
            + struct.pack("<I", self.locktime)
        )


class PqbCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    def send(self, ins: int, p1: int = 0, data: bytes = b"") -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=ins, p1=p1, p2=0, data=data)

    @contextmanager
    def send_async(self, ins: int, p1: int = 0, data: bytes = b"") -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA, ins=ins, p1=p1, p2=0, data=data):
            yield

    def get_async_response(self) -> RAPDU:
        response = self.backend.last_async_response
        assert response is not None
        return response

    # --- app ---------------------------------------------------------------

    def get_version(self) -> Tuple[Tuple[int, int, int], str]:
        data = self.send(Ins.GET_VERSION).data
        return (data[0], data[1], data[2]), data[3:].decode("ascii")

    def get_app_name(self) -> str:
        return self.send(Ins.GET_APP_NAME).data.decode("ascii")

    # --- read-only ---------------------------------------------------------

    def get_commitments(self, v: int, start: int, count: int) -> List[bytes]:
        data = self.send(Ins.GET_COMMITMENTS, 0, idx(v) + bytes([start, count])).data
        assert len(data) == 20 * count
        return [data[20 * k:20 * k + 20] for k in range(count)]

    def all_commitments(self, v: int) -> List[bytes]:
        return [c for start in range(0, 154, 12) for c in self.get_commitments(v, start, min(12, 154 - start))]

    @staticmethod
    def unpack_vault(data: bytes) -> Vault:
        assert len(data) == 66
        return Vault(data[:32], data[32:64], data[64], bool(data[65]))

    def get_vault(self, v: int) -> Vault:
        return self.unpack_vault(self.send(Ins.GET_VAULT, 0, idx(v)).data)

    @contextmanager
    def get_vault_display(self, v: int) -> Generator[None, None, None]:
        with self.send_async(Ins.GET_VAULT, 1, idx(v)):
            yield

    def get_script_chunk(self, v: int, offset: int) -> bytes:
        return self.send(Ins.GET_SCRIPT, 0, idx(v) + struct.pack(">H", offset)).data

    def get_script(self, v: int) -> bytes:
        out = b""
        while len(out) < pqb.SCRIPT_LEN:
            out += self.get_script_chunk(v, len(out))
        return out

    @staticmethod
    def unpack_deposit_address(data: bytes) -> Tuple[bytes, str]:
        pubkey, length = data[:33], data[33]
        assert len(data) == 34 + length
        return pubkey, data[34:].decode("ascii")

    def get_deposit_address(self, v: int) -> Tuple[bytes, str]:
        return self.unpack_deposit_address(self.send(Ins.GET_DEPOSIT_ADDRESS, 0, idx(v)).data)

    @contextmanager
    def get_deposit_address_display(self, v: int) -> Generator[None, None, None]:
        with self.send_async(Ins.GET_DEPOSIT_ADDRESS, 1, idx(v)):
            yield

    def get_state(self) -> State:
        data = self.send(Ins.GET_STATE, 0).data
        assert len(data) == 23
        return State(data[:16], data[16], struct.unpack(">I", data[17:21])[0], data[21], data[22])

    def get_record(self, i: int) -> Record:
        data = self.send(Ins.GET_STATE, 1, bytes([i])).data
        assert len(data) == 251
        return Record(data)

    # --- allocation --------------------------------------------------------

    @contextmanager
    def allocate(self) -> Generator[None, None, None]:
        with self.send_async(Ins.ALLOCATE):
            yield

    @staticmethod
    def unpack_allocation(data: bytes) -> Tuple[int, bytes, bytes]:
        assert len(data) == 68
        return struct.unpack(">I", data[:4])[0], data[4:36], data[36:68]

    @contextmanager
    def retire(self, v: int) -> Generator[None, None, None]:
        with self.send_async(Ins.RETIRE, 0, idx(v)):
            yield

    # --- SIGN_DEPOSIT ------------------------------------------------------

    def stream_deposit(self, kind: Kind, v: int, tx: Tx, previous: List[bytes]) -> None:
        """Everything up to REVIEW: header, inputs with their previous transactions, outputs."""
        self.send(
            Ins.SIGN_DEPOSIT, DepositStep.START,
            bytes([kind]) + idx(v) + struct.pack("<II", tx.version, tx.locktime)
            + bytes([len(tx.inputs), len(tx.outputs)]),
        )
        for txin, prev in zip(tx.inputs, previous):
            self.send(Ins.SIGN_DEPOSIT, DepositStep.INPUT, txin.outpoint() + struct.pack("<I", txin.sequence))
            for chunk in chunks(prev):
                self.send(Ins.SIGN_DEPOSIT, DepositStep.PREVTX, chunk)
        for chunk in chunks(tx.outputs_bytes()):
            self.send(Ins.SIGN_DEPOSIT, DepositStep.OUTPUTS, chunk)

    @contextmanager
    def deposit_review(self) -> Generator[None, None, None]:
        with self.send_async(Ins.SIGN_DEPOSIT, DepositStep.REVIEW):
            yield

    def deposit_review_sync(self) -> RAPDU:
        return self.send(Ins.SIGN_DEPOSIT, DepositStep.REVIEW)

    def deposit_sign(self, index: int) -> bytes:
        return self.send(Ins.SIGN_DEPOSIT, DepositStep.SIGN, bytes([index])).data

    # --- WITHDRAW ----------------------------------------------------------

    def stream_withdraw(self, req: WithdrawRequest) -> None:
        self.send(Ins.WITHDRAW, WithdrawStep.START, req.start())
        for chunk in chunks(req.prev_tx):
            self.send(Ins.WITHDRAW, WithdrawStep.PREVTX, chunk)
        for chunk in chunks(req.outputs):
            self.send(Ins.WITHDRAW, WithdrawStep.OUTPUTS, chunk)

    @contextmanager
    def withdraw_review(self) -> Generator[None, None, None]:
        with self.send_async(Ins.WITHDRAW, WithdrawStep.REVIEW):
            yield

    def reveal_read(self, chunk: int) -> bytes:
        return self.send(Ins.REVEAL_READ, chunk).data

    def read_disclosure(self) -> Disclosure:
        c0 = self.reveal_read(0)
        c1 = self.reveal_read(1)
        c2 = self.reveal_read(2)
        c3 = self.reveal_read(3)
        c4 = self.reveal_read(4)
        assert len(c0) == 160 and len(c1) == 160 and len(c2) == 128
        sigs, pos = [], 0
        for _ in range(3):
            n = c3[pos]
            sigs.append(c3[pos + 1:pos + 1 + n])
            pos += 1 + n
        assert pos == len(c3)
        n = c4[0]
        assert len(c4) == 1 + n + 33
        return Disclosure(
            s=[c0[20 * k:20 * k + 20] for k in range(8)],
            w=[c1[32 * k:32 * k + 32] for k in range(5)] + [c2[32 * k:32 * k + 32] for k in range(4)],
            menu_sigs=sigs,
            cosig=c4[1:1 + n],
            q=c4[1 + n:],
        )

    # --- MENU_POINTS -------------------------------------------------------

    @contextmanager
    def authorize_menu_points(self, v: int) -> Generator[None, None, None]:
        with self.send_async(Ins.MENU_POINTS, 0, idx(v)):
            yield

    def menu_points(self, v: int, stage: int, variant: int, start: int, count: int) -> List[bytes]:
        data = self.send(Ins.MENU_POINTS, 1, idx(v) + bytes([stage, variant, start, count])).data
        assert len(data) == 33 * count
        return [data[33 * k:33 * k + 33] for k in range(count)]

    def menu_r(self, v: int, stage: int) -> int:
        data = self.send(Ins.MENU_POINTS, 2, idx(v) + bytes([stage])).data
        assert len(data) == 32
        return int.from_bytes(data, "big")

    def all_menu_points(self, v: int, stage: int, variant: int) -> List[bytes]:
        width = 12 if stage == 0 else 16
        out: List[bytes] = []
        for start in range(0, width, 7):
            out += self.menu_points(v, stage, variant, start, min(7, width - start))
        return out
