"""APDU client for the QSB app (docs/apdu.md), for the Ragger tests."""

import struct
from collections.abc import Generator
from contextlib import contextmanager
from enum import IntEnum
from typing import List, Tuple

from ragger.backend.interface import RAPDU, BackendInterface
from ragger.bip import pack_derivation_path

from .bitcoin import Tx

CLA = 0xE0
CHUNK = 255


class Ins(IntEnum):
    HORS_GET_VERSION = 0x01
    GET_VERSION = 0x03
    GET_APP_NAME = 0x04
    GET_WALLET_ADDRESS = 0x05
    SIGN_TX = 0x06
    SIGN_IN = 0x07
    GET_COMMITMENTS = 0x10
    GET_COMMITMENT_ROOT = 0x11
    REVEAL_PREPARE = 0x20
    REVEAL_READ = 0x21


class Step(IntEnum):
    START = 0
    INPUT = 1
    PREVTX = 2
    OUTPUTS = 3
    REVIEW = 4
    SIGN = 5


class Kind(IntEnum):
    DEPOSIT = 1
    WITHDRAWAL = 2


class Errors(IntEnum):
    SW_DENY = 0x6985
    SW_WRONG_P1P2 = 0x6A86
    SW_WRONG_DATA_LENGTH = 0x6A87
    SW_INS_NOT_SUPPORTED = 0x6D00
    SW_CLA_NOT_SUPPORTED = 0x6E00
    SW_BAD_STATE = 0xB001
    SW_BAD_PATH = 0xB002
    SW_PARSE = 0xB003
    SW_TXID_MISMATCH = 0xB004
    SW_NOT_OWN_INPUT = 0xB005
    SW_NOT_VAULT = 0xB006
    SW_BAD_LAYOUT = 0xB007
    SW_UNSUPPORTED_OUTPUT = 0xB008
    SW_BAD_AMOUNT = 0xB009
    SW_BAD_MESSAGE = 0xB00A
    SW_SIGN_FAIL = 0xB00B
    SW_KEY_DERIVE_FAIL = 0xB00C
    # HORS commands (QSB-HORS-v1 spec)
    SW_INVALID_DATA = 0x6A80
    SW_REVEAL_CONFLICT = 0x6A90
    SW_NO_APPROVED_REVEAL = 0x6A91
    SW_WRONG_NETWORK = 0x6A92


def chunks(data: bytes) -> List[bytes]:
    return [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)]


class QsbCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    def send(self, ins: int, p1: int = 0, data: bytes = b"") -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=ins, p1=p1, p2=0, data=data)

    def get_version(self) -> Tuple[int, int, int]:
        major, minor, patch = self.send(Ins.GET_VERSION).data
        return major, minor, patch

    def get_app_name(self) -> str:
        return self.send(Ins.GET_APP_NAME).data.decode("ascii")

    @staticmethod
    def unpack_wallet(data: bytes) -> Tuple[bytes, str]:
        pubkey, length = data[:33], data[33]
        assert len(data) == 34 + length
        return pubkey, data[34:].decode("ascii")

    def get_wallet(self, path: str) -> Tuple[bytes, str]:
        return self.unpack_wallet(self.send(Ins.GET_WALLET_ADDRESS, 0, pack_derivation_path(path)).data)

    @contextmanager
    def get_wallet_with_confirmation(self, path: str) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA, ins=Ins.GET_WALLET_ADDRESS, p1=1, data=pack_derivation_path(path)):
            yield

    def stream_tx(self, kind: Kind, path: str, tx: Tx, previous: List[bytes]) -> None:
        """Send everything up to REVIEW: header, inputs with their previous transactions, outputs."""
        self.send(
            Ins.SIGN_TX,
            Step.START,
            bytes([kind]) + pack_derivation_path(path)
            + struct.pack("<II", tx.version, tx.locktime) + bytes([len(tx.inputs), len(tx.outputs)]),
        )
        for txin, prev in zip(tx.inputs, previous):
            self.send(Ins.SIGN_TX, Step.INPUT, txin.outpoint() + struct.pack("<I", txin.sequence))
            for chunk in chunks(prev):
                self.send(Ins.SIGN_TX, Step.PREVTX, chunk)
        for chunk in chunks(tx.outputs_bytes()):
            self.send(Ins.SIGN_TX, Step.OUTPUTS, chunk)

    @contextmanager
    def review(self) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA, ins=Ins.SIGN_TX, p1=Step.REVIEW):
            yield

    def sign(self, index: int) -> bytes:
        return self.send(Ins.SIGN_TX, Step.SIGN, bytes([index])).data

    @contextmanager
    def sign_in(self, path: str, message: bytes) -> Generator[None, None, None]:
        header = pack_derivation_path(path) + struct.pack(">H", len(message))
        first = message[:CHUNK - len(header)]
        rest = chunks(message[len(first):])
        if not rest:
            with self.backend.exchange_async(cla=CLA, ins=Ins.SIGN_IN, p1=0x00, data=header + first):
                yield
            return
        self.send(Ins.SIGN_IN, 0x00, header + first)
        for chunk in rest[:-1]:
            self.send(Ins.SIGN_IN, 0x80, chunk)
        with self.backend.exchange_async(cla=CLA, ins=Ins.SIGN_IN, p1=0x80, data=rest[-1]):
            yield

    def get_async_response(self) -> RAPDU:
        response = self.backend.last_async_response
        assert response is not None
        return response

    # --- QSB-HORS-v1 ---------------------------------------------------------

    def hors_version(self) -> Tuple[Tuple[int, int, int], str]:
        data = self.send(Ins.HORS_GET_VERSION).data
        return (data[0], data[1], data[2]), data[3:].decode("ascii")

    def get_commitments(self, net: int, v: int, rnd: int, start: int, count: int) -> List[bytes]:
        data = self.send(Ins.GET_COMMITMENTS, rnd, struct.pack(">BIHB", net, v, start, count)).data
        assert len(data) == 20 * count
        return [data[20 * k:20 * k + 20] for k in range(count)]

    def all_commitments(self, net: int, v: int) -> List[List[bytes]]:
        return [
            [c for start in range(0, 150, 12) for c in self.get_commitments(net, v, rnd, start, min(12, 150 - start))]
            for rnd in (0, 1)
        ]

    def get_commitment_root(self, net: int, v: int) -> bytes:
        return self.send(Ins.GET_COMMITMENT_ROOT, 0, struct.pack(">BI", net, v)).data

    @contextmanager
    def get_commitment_root_with_confirmation(self, net: int, v: int) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA, ins=Ins.GET_COMMITMENT_ROOT, p1=1, data=struct.pack(">BI", net, v)):
            yield

    @staticmethod
    def reveal_payload(net: int, v: int, round1: List[int], round2: List[int], binding: bytes,
                       amount: int, destination: bytes) -> bytes:
        return (
            struct.pack(">BI", net, v)
            + b"".join(struct.pack(">H", i) for i in list(round1) + list(round2))
            + binding + struct.pack(">Q", amount) + bytes([len(destination)]) + destination
        )

    @contextmanager
    def reveal_prepare(self, payload: bytes) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA, ins=Ins.REVEAL_PREPARE, p1=0, data=payload):
            yield

    def reveal_read(self, chunk: int) -> List[bytes]:
        data = self.send(Ins.REVEAL_READ, chunk).data
        return [data[20 * k:20 * k + 20] for k in range(len(data) // 20)]
