import { sha256 } from "@noble/hashes/sha2.js";

/** APDU class and instructions; see docs/apdu.md. */
export const CLA = 0xe0;
export const INS = {
  HORS_GET_VERSION: 0x01,
  GET_VERSION: 0x03,
  GET_APP_NAME: 0x04,
  GET_WALLET_ADDRESS: 0x05,
  SIGN_TX: 0x06,
  SIGN_IN: 0x07,
  GET_COMMITMENTS: 0x10,
  GET_COMMITMENT_ROOT: 0x11,
  REVEAL_PREPARE: 0x20,
  REVEAL_READ: 0x21,
} as const;
const STEP = { START: 0, INPUT: 1, PREVTX: 2, OUTPUTS: 3, REVIEW: 4, SIGN: 5 } as const;
const CHUNK = 255;
const HARDENED = 0x80000000;
const SW_OK = 0x9000;
/** The device was showing a status screen and didn't take the command; safe to resend. */
const SW_NOT_ACCEPTED = 0x6901;
/** The app's limit on a sign-in message (docs/apdu.md). */
export const MESSAGE_MAX = 512;

export type TxKind = "deposit" | "withdrawal";

/** The unsigned transaction fields SIGN_TX needs. Txids are in display order (hex). */
export type UnsignedTx = {
  version: number;
  lockTime: number;
  inputs: { txid: string; vout: number; sequence: number; previousTx: Uint8Array }[];
  outputs: { amount: bigint; script: Uint8Array }[];
};

/** `m/84'/0'/0'/0/0` as `count || element (4, big-endian)…`. */
export function serializePath(path: string): Uint8Array {
  if (!/^m(\/\d+['hH]?)+$/.test(path)) throw new Error(`Invalid BIP-32 path: ${path}`);
  const parts = path.split("/").slice(1);
  const out = new Uint8Array(1 + 4 * parts.length);
  const view = new DataView(out.buffer);
  out[0] = parts.length;
  parts.forEach((part, i) => {
    const hardened = /['hH]$/.test(part);
    const n = Number(hardened ? part.slice(0, -1) : part);
    if (n >= HARDENED) throw new Error(`Invalid path element: ${part}`);
    view.setUint32(1 + 4 * i, hardened ? n + HARDENED : n);
  });
  return out;
}

const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
};
const u32le = (n: number) => {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n >>> 0, true);
  return out;
};
const u64le = (n: bigint) => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n, true);
  return out;
};
export function compactSize(n: number): Uint8Array {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >> 8);
  return concat(Uint8Array.of(0xfe), u32le(n));
}
const fromHex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/**
 * The legacy serialization of a transaction: SegWit marker, flag and witnesses
 * removed. That is what the txid commits to, and what the app hashes.
 */
export function stripWitness(raw: Uint8Array): Uint8Array {
  let pos = 4;
  // Reads a CompactSize and moves `pos` past it. Callers must not write
  // `pos += varint()`: that adds to the value of `pos` from before the read.
  const varint = () => {
    const first = raw[pos++];
    if (first < 0xfd) return first;
    const size = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
    let n = 0;
    for (let i = size - 1; i >= 0; i--) n = n * 256 + raw[pos + i];
    pos += size;
    return n;
  };
  const skip = (n: number) => {
    pos += n;
  };
  if (raw[4] !== 0x00) return raw;
  if (raw[5] !== 0x01) throw new Error("Unknown transaction serialization.");
  pos = 6;
  const bodyStart = pos;
  const inputs = varint();
  for (let i = 0; i < inputs; i++) {
    skip(36);
    skip(varint());
    skip(4);
  }
  const outputs = varint();
  for (let i = 0; i < outputs; i++) {
    skip(8);
    skip(varint());
  }
  const bodyEnd = pos;
  for (let i = 0; i < inputs; i++) {
    const items = varint();
    for (let j = 0; j < items; j++) skip(varint());
  }
  if (pos + 4 !== raw.length) throw new Error("Malformed SegWit transaction.");
  return concat(raw.subarray(0, 4), raw.subarray(bodyStart, bodyEnd), raw.subarray(pos));
}

/** The display-order txid of a legacy-serialized transaction. */
export function txidOf(stripped: Uint8Array): string {
  return toHex(sha256(sha256(stripped)).reverse());
}

/** What the app needs from a transport; any `@ledgerhq/hw-transport` instance fits. */
export interface ApduTransport {
  send(cla: number, ins: number, p1: number, p2: number, data?: Buffer): Promise<Buffer>;
}

/** The device refused a command; `statusWord` is in docs/apdu.md. */
export class QsbStatusError extends Error {
  constructor(readonly statusWord: number) {
    super(`QSB app refused the command: 0x${statusWord.toString(16).padStart(4, "0")}`);
  }
}

const statusOf = (error: unknown): number | undefined =>
  typeof error === "object" && error !== null && "statusCode" in error && typeof error.statusCode === "number"
    ? error.statusCode
    : undefined;

/** Thin wrapper over the app's APDUs. */
export class QsbApp {
  constructor(private readonly transport: ApduTransport) {}

  /**
   * Send one APDU and return its data, throwing QsbStatusError unless the app
   * answered 0x9000 (whether or not the transport checks). A command sent while
   * a status screen is up (about 3 s after an approval or rejection) is refused
   * with 0x6901 without being processed, so it is resent.
   */
  async exchange(ins: number, p1: number, data: Uint8Array = new Uint8Array()): Promise<Uint8Array> {
    for (let attempt = 0; ; attempt++) {
      let response: Buffer;
      try {
        response = await this.transport.send(CLA, ins, p1, 0x00, Buffer.from(data));
      } catch (error) {
        const sw = statusOf(error);
        if (sw === SW_NOT_ACCEPTED && attempt < 20) {
          await new Promise((r) => setTimeout(r, 250));
          continue;
        }
        if (sw !== undefined) throw new QsbStatusError(sw);
        throw error;
      }
      if (response.length < 2) throw new Error("Truncated APDU response.");
      const sw = response.readUInt16BE(response.length - 2);
      if (sw === SW_NOT_ACCEPTED && attempt < 20) {
        await new Promise((r) => setTimeout(r, 250));
        continue;
      }
      if (sw !== SW_OK) throw new QsbStatusError(sw);
      return new Uint8Array(response.subarray(0, response.length - 2));
    }
  }

  async getVersion(): Promise<string> {
    const r = await this.exchange(INS.GET_VERSION, 0);
    if (r.length !== 3) throw new Error("Unexpected GET_VERSION response.");
    return `${r[0]}.${r[1]}.${r[2]}`;
  }

  async getAppName(): Promise<string> {
    return new TextDecoder().decode(await this.exchange(INS.GET_APP_NAME, 0));
  }

  /** The wallet key and address at `path`; with `display`, after the user confirms it on the device. */
  async getWalletAddress(path: string, display = false): Promise<{ publicKey: Uint8Array; address: string }> {
    const r = await this.exchange(INS.GET_WALLET_ADDRESS, display ? 1 : 0, serializePath(path));
    if (r.length < 34 || r.length !== 34 + r[33]) throw new Error("Unexpected GET_WALLET_ADDRESS response.");
    const publicKey = r.subarray(0, 33);
    const address = new TextDecoder().decode(r.subarray(34, 34 + r[33]));
    return { publicKey, address };
  }

  /**
   * Stream `tx` to the app, wait for the user's approval, then collect a
   * signature (DER || SIGHASH_ALL) for each index in `sign`.
   */
  async signTransaction(kind: TxKind, path: string, tx: UnsignedTx, sign: number[]): Promise<Map<number, Uint8Array>> {
    if (tx.inputs.length > 8 || tx.outputs.length > 2) throw new Error("Not a QSB deposit or withdrawal.");
    await this.exchange(
      INS.SIGN_TX,
      STEP.START,
      concat(
        Uint8Array.of(kind === "deposit" ? 1 : 2),
        serializePath(path),
        u32le(tx.version),
        u32le(tx.lockTime),
        Uint8Array.of(tx.inputs.length, tx.outputs.length),
      ),
    );
    for (const input of tx.inputs) {
      const previous = stripWitness(input.previousTx);
      if (txidOf(previous) !== input.txid.toLowerCase())
        throw new Error(`Previous transaction for ${input.txid} has a different txid.`);
      await this.exchange(
        INS.SIGN_TX,
        STEP.INPUT,
        concat(fromHex(input.txid).reverse(), u32le(input.vout), u32le(input.sequence)),
      );
      for (let i = 0; i < previous.length; i += CHUNK)
        await this.exchange(INS.SIGN_TX, STEP.PREVTX, previous.subarray(i, i + CHUNK));
    }
    const outputs = concat(
      ...tx.outputs.flatMap((o) => [u64le(o.amount), compactSize(o.script.length), o.script]),
    );
    for (let i = 0; i < outputs.length; i += CHUNK)
      await this.exchange(INS.SIGN_TX, STEP.OUTPUTS, outputs.subarray(i, i + CHUNK));
    await this.exchange(INS.SIGN_TX, STEP.REVIEW);
    const signatures = new Map<number, Uint8Array>();
    for (const index of sign) {
      const signature = await this.exchange(INS.SIGN_TX, STEP.SIGN, Uint8Array.of(index));
      checkSignature(signature);
      signatures.set(index, signature);
    }
    return signatures;
  }

  /** BIP-322 signature (DER || SIGHASH_ALL) of a QSB sign-in challenge. */
  async signIn(path: string, message: string): Promise<Uint8Array> {
    const bytes = new TextEncoder().encode(message);
    if (bytes.length === 0 || bytes.length > MESSAGE_MAX) throw new Error("Not a QSB sign-in challenge.");
    const header = concat(serializePath(path), Uint8Array.of(bytes.length >> 8, bytes.length & 0xff));
    const first = bytes.subarray(0, CHUNK - header.length);
    let response = await this.exchange(INS.SIGN_IN, 0x00, concat(header, first));
    for (let i = first.length; i < bytes.length; i += CHUNK)
      response = await this.exchange(INS.SIGN_IN, 0x80, bytes.subarray(i, i + CHUNK));
    checkSignature(response);
    return response;
  }
}

/** `DER signature || SIGHASH_ALL`, as the app returns it. */
function checkSignature(sig: Uint8Array) {
  if (sig.length < 9 || sig.length > 73 || sig[0] !== 0x30 || sig[1] !== sig.length - 3 || sig[sig.length - 1] !== 0x01)
    throw new Error("Malformed signature from the device.");
}
