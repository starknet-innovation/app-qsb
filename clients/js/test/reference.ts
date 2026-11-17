/**
 * PQB-v1 derivation (tests/application_client/pqb.py, from the BIP's
 * reference.py), ported for the tests: it plays the device. Public test seeds
 * only; nothing here is constant-time.
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hmac } from "@noble/hashes/hmac.js";
import { ripemd160, sha1 } from "@noble/hashes/legacy.js";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

const enc = new TextEncoder();
const N = secp256k1.Point.CURVE().n;
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) out.set(p, (o += p.length) - p.length);
  return out;
};
const int = (b: Uint8Array) => BigInt("0x" + (Buffer.from(b).toString("hex") || "0"));
const bytes32 = (n: bigint) => Uint8Array.from(Buffer.from(n.toString(16).padStart(64, "0"), "hex"));
const hash160 = (b: Uint8Array) => ripemd160(sha256(b));

export const SPECULOS_MNEMONIC =
  "glory promote mansion idle axis finger extra february uncover one trip resource " +
  "lawn turtle enact monster seven myth punch hobby comfort wild raise skin";
const BIP85_PATH = [83696968, 39, 0, 24];
const MENUS: [string, number, boolean][] = [
  ["pin", 12, false],
  ["round0", 16, true],
  ["round1", 16, true],
];

export const bip39Seed = (mnemonic: string, passphrase = "") =>
  pbkdf2(sha512, enc.encode(mnemonic.normalize("NFKD")), enc.encode(("mnemonic" + passphrase).normalize("NFKD")), { c: 2048, dkLen: 64 });

/** E: BIP 85 entropy at m/83696968'/39'/0'/24'/index'. Hardened steps only, so no point arithmetic. */
export function bip85Child(seed64: Uint8Array, index: number): Uint8Array {
  let i = hmac(sha512, enc.encode("Bitcoin seed"), seed64);
  let k = int(i.subarray(0, 32));
  let c = i.subarray(32);
  for (const step of [...BIP85_PATH, index]) {
    const idx = new Uint8Array(4);
    new DataView(idx.buffer).setUint32(0, step + 2 ** 31);
    i = hmac(sha512, c, concat(Uint8Array.of(0), bytes32(k), idx));
    k = (int(i.subarray(0, 32)) + k) % N;
    c = i.subarray(32);
  }
  return hmac(sha512, enc.encode("bip-entropy-from-k"), bytes32(k)).subarray(0, 32);
}

export const vaultSeed = (child: Uint8Array, network = "main") =>
  hmac(sha256, child, enc.encode("pqb/vault-seed|hybrid|PQB|v1|real|" + network));

export const deviceSeed = (v: number, mnemonic = SPECULOS_MNEMONIC, passphrase = "") =>
  vaultSeed(bip85Child(bip39Seed(mnemonic, passphrase), v));

export const walletId = (mnemonic = SPECULOS_MNEMONIC, passphrase = "") =>
  sha256(concat(enc.encode("PQB-v1/wallet"), deviceSeed(0, mnemonic, passphrase))).subarray(0, 16);

const secret = (seed: Uint8Array, label: string) => sha256(concat(enc.encode("pqb/v1|"), seed, enc.encode("|" + label)));

export function hors(seed: Uint8Array, j: number) {
  const s = secret(seed, `r2g4-hors-${j}`).subarray(0, 20);
  return { s, w: sha256(s), c: hash160(s) };
}


export function menuR(seed: Uint8Array, stage: number): bigint {
  // pqb v1: r = 1 for the pinning menu, 0x81 for the round menus.
  return stage === 0 ? 1n : 0x81n;
}

const derInt = (v: bigint) => {
  const h = v.toString(16);
  let b = Uint8Array.from(Buffer.from(h.length % 2 ? "0" + h : h, "hex"));
  if (b[0] & 0x80) b = concat(Uint8Array.of(0), b);
  return concat(Uint8Array.of(0x02, b.length), b);
};
/** DER(r, s) || 0x01. */
export const derSig = (r: bigint, s: bigint) => {
  const body = concat(derInt(r), derInt(s));
  return concat(Uint8Array.of(0x30, body.length), body, Uint8Array.of(0x01));
};

export function menu(seed: Uint8Array, stage: number) {
  const [tag, width] = MENUS[stage];
  const r = menuR(seed, stage);
  const inner = secret(seed, "r5close-indep-menu-" + tag);
  return Array.from({ length: width }, (_, i) => {
    const x = (int(sha256(concat(inner, enc.encode(`|${i}`)))) >> 6n) | (1n << 250n);
    const sig = derSig(r, x);
    return { x, sig, m: sha1(sig) };
  });
}

export function cosignKey(seed: Uint8Array) {
  const d = (int(secret(seed, "cosig-key")) % (N - 1n)) + 1n;
  const Q = secp256k1.getPublicKey(bytes32(d), true);
  return { d: bytes32(d), Q, q: hash160(Q) };
}

export function depositKey(seed: Uint8Array) {
  const d = (int(hmac(sha512, seed, enc.encode("pqb/deposit-key/v1")).subarray(0, 32)) % (N - 1n)) + 1n;
  return { d: bytes32(d), publicKey: secp256k1.getPublicKey(bytes32(d), true) };
}

export function commitments(seed: Uint8Array): Uint8Array[] {
  const out = Array.from({ length: 109 }, (_, j) => hors(seed, j).c);
  for (let stage = 0; stage < 3; stage++) out.push(...menu(seed, stage).map((e) => e.m));
  out.push(cosignKey(seed).q);
  return out;
}

/** The co-signature over z, as a device makes it: RFC 6979, low S, DER || 0x01. */
export function cosign(seed: Uint8Array, z: Uint8Array): Uint8Array {
  const der = secp256k1.sign(z, cosignKey(seed).d, { prehash: false, lowS: true, format: "der" });
  return concat(der, Uint8Array.of(0x01));
}
