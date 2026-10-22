import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { INS, type QsbApp } from "./app.js";

/**
 * QSB-HORS-v1: vault secrets derived on the device (docs/apdu.md, "HORS
 * secrets"). The device exports commitments and, after the user approves a
 * withdrawal on screen, the 15 preimages it needs. Unrevealed secrets never
 * leave it.
 */

export const NET_MAINNET = 0x00;
export const NET_TEST = 0x01;
const N = 150;
const CHUNK = 12;
const enc = new TextEncoder();

/** A vault: the network byte and the vault index (below 2^31). */
export type HorsVault = { net: number; index: number };

/** What the user approves on the device. Amount and destination are shown as host-reported. */
export type RevealRequest = {
  round1: number[];
  round2: number[];
  /** SHA-256 of the unsigned withdrawal, as the host serialises it. */
  binding: Uint8Array;
  amount: bigint;
  destinationScript: Uint8Array;
};

const hash160 = (b: Uint8Array) => ripemd160(sha256(b));
const u16 = (n: number) => Uint8Array.of(n >> 8, n & 0xff);
const vaultBytes = ({ net, index }: HorsVault) => {
  if (net !== NET_MAINNET && net !== NET_TEST) throw new Error("Unknown network byte.");
  if (!Number.isInteger(index) || index < 0 || index > 0x7fffffff) throw new Error("Vault index out of range.");
  const out = new Uint8Array(5);
  out[0] = net;
  new DataView(out.buffer).setUint32(1, index);
  return out;
};
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** R = SHA256("QSB-HORS-v1/root" ‖ round 0's 150 commitments ‖ round 1's). */
export function commitmentRoot(commitments: [Uint8Array[], Uint8Array[]]): Uint8Array {
  if (commitments.some((round) => round.length !== N || round.some((c) => c.length !== 20)))
    throw new Error("Expected 2 × 150 commitments of 20 bytes.");
  return sha256(concat(enc.encode("QSB-HORS-v1/root"), ...commitments[0], ...commitments[1]));
}

/** The root's first 8 bytes as the device shows them, e.g. "9b25 7b6a cd00 017b". */
export function fingerprint(root: Uint8Array): string {
  const h = Array.from(root.subarray(0, 8), (b) => b.toString(16).padStart(2, "0")).join("");
  return h.match(/..../g)!.join(" ");
}

/**
 * A vault takes one reveal per device, so a malformed request must never reach
 * it: `n` integer indices below 150, distinct.
 */
function checkIndices(indices: number[], n: number, round: string) {
  if (
    indices.length !== n ||
    !indices.every((i) => Number.isInteger(i) && i >= 0 && i < N) ||
    new Set(indices).size !== n
  )
    throw new Error(`${round} needs ${n} distinct indices from 0 to 149.`);
}

export class QsbHors {
  constructor(private readonly app: QsbApp) {}

  /** The app version; throws unless the app implements QSB-HORS-v1. */
  async getVersion(): Promise<{ version: string; spec: string }> {
    const r = await this.app.exchange(INS.HORS_GET_VERSION, 0);
    const spec = new TextDecoder().decode(r.subarray(3));
    if (r.length < 4 || spec !== "QSB-HORS-v1") throw new Error(`Unsupported HORS spec: ${spec}`);
    return { version: `${r[0]}.${r[1]}.${r[2]}`, spec };
  }

  /** All 300 commitments, read 12 at a time (13 chunks per round). */
  async getCommitments(vault: HorsVault): Promise<[Uint8Array[], Uint8Array[]]> {
    const rounds: [Uint8Array[], Uint8Array[]] = [[], []];
    for (const round of [0, 1] as const) {
      for (let start = 0; start < N; start += CHUNK) {
        const count = Math.min(CHUNK, N - start);
        const r = await this.app.exchange(
          INS.GET_COMMITMENTS,
          round,
          concat(vaultBytes(vault), u16(start), Uint8Array.of(count)),
        );
        if (r.length !== 20 * count) throw new Error("Unexpected GET_COMMITMENTS response.");
        for (let k = 0; k < count; k++) rounds[round].push(r.slice(20 * k, 20 * k + 20));
      }
    }
    return rounds;
  }

  /** The device's commitment root; with `display`, after the user checks the fingerprint on screen. */
  async getCommitmentRoot(vault: HorsVault, display = false): Promise<Uint8Array> {
    const r = await this.app.exchange(INS.GET_COMMITMENT_ROOT, display ? 1 : 0, vaultBytes(vault));
    if (r.length !== 32) throw new Error("Unexpected GET_COMMITMENT_ROOT response.");
    return r;
  }

  /** Commitments checked against the device's root: what a new vault's script is built from. */
  async getVerifiedCommitments(vault: HorsVault, display = false): Promise<[Uint8Array[], Uint8Array[]]> {
    const commitments = await this.getCommitments(vault);
    if (!equal(commitmentRoot(commitments), await this.getCommitmentRoot(vault, display)))
      throw new Error("Commitments don't match the device's commitment root.");
    return commitments;
  }

  /**
   * Ask the user to approve a reveal, then read the 15 preimages (round 1's 8,
   * then round 2's 7, in the order given) and check each against its commitment.
   */
  async reveal(
    vault: HorsVault,
    request: RevealRequest,
    commitments: [Uint8Array[], Uint8Array[]],
  ): Promise<Uint8Array[]> {
    const { round1, round2, binding, amount, destinationScript } = request;
    checkIndices(round1, 8, "Round 1");
    checkIndices(round2, 7, "Round 2");
    if (binding.length !== 32 || destinationScript.length > 34) throw new Error("Bad binding or destination.");
    if (amount < 0n || amount > 2_100_000_000_000_000n) throw new Error("Amount out of range.");
    if (commitments.some((round) => round.length !== N)) throw new Error("Expected 2 × 150 commitments.");
    const amountBytes = new Uint8Array(8);
    new DataView(amountBytes.buffer).setBigUint64(0, amount);
    await this.app.exchange(
      INS.REVEAL_PREPARE,
      0,
      concat(
        vaultBytes(vault),
        ...round1.map(u16),
        ...round2.map(u16),
        binding,
        amountBytes,
        Uint8Array.of(destinationScript.length),
        destinationScript,
      ),
    );
    const data = concat(await this.app.exchange(INS.REVEAL_READ, 0), await this.app.exchange(INS.REVEAL_READ, 1));
    if (data.length !== 15 * 20) throw new Error("Unexpected REVEAL_READ response.");
    const wanted = [...round1.map((i) => [0, i] as const), ...round2.map((i) => [1, i] as const)];
    return wanted.map(([round, index], k) => {
      const preimage = data.slice(20 * k, 20 * k + 20);
      if (!equal(hash160(preimage), commitments[round][index]))
        throw new Error(`Preimage for round ${round + 1} index ${index} doesn't match its commitment.`);
      return preimage;
    });
  }
}
