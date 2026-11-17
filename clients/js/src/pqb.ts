import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ripemd160, sha1 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { TEMPLATE_BASE64, TEMPLATE_SHA256 } from "./template.js";
import { concat, equalBytes, fromHex, parseTx, serializeTx, toHex, u32le, type TxOutput } from "./tx.js";

/**
 * PQB-v1 host computations (BIP "PQB Wallet Secret Management"): everything a
 * host can check about a vault without its seed. No device involved.
 */

export const PROFILE = "PQB-v1";
/** Table entries, shared by both rounds. */
export const TABLE = 109;
/** Commitments in the root: c[0..109], m_pin[0..12], m_round0[0..16], m_round1[0..16], q. */
export const COMMITMENTS = 154;
/** Menu widths of stages 0 (pin), 1 (round 0) and 2 (round 1). */
export const MENU_WIDTHS = [12, 16, 16] as const;
/** Root index of each stage's first menu commitment. */
export const MENU_OFFSETS = [109, 121, 137] as const;
/** Root index of q, HASH160 of the co-signing key. */
export const Q_INDEX = 153;
export const ROUND0 = 8;
export const ROUND1 = 9;
export const SCRIPT_LEN = 4696;

const enc = new TextEncoder();
const SIGHASH_ALL = 0x01;

export const hash160 = (b: Uint8Array): Uint8Array => ripemd160(sha256(b));

/** R = SHA256("PQB-v1/root" || the 154 commitments in root order). */
export function commitmentRoot(commitments: Uint8Array[]): Uint8Array {
  if (commitments.length !== COMMITMENTS || commitments.some((c) => c.length !== 20))
    throw new Error(`Expected ${COMMITMENTS} commitments of 20 bytes.`);
  return sha256(concat(enc.encode(`${PROFILE}/root`), ...commitments));
}

/** The root's first eight bytes in four groups, as the device shows them. Not for matching. */
export function fingerprint(root: Uint8Array): string {
  return toHex(root.subarray(0, 8)).match(/..../g)!.join(" ");
}

let templateBytes: Uint8Array | undefined;
/** The PQB-v1 script template, commitments zeroed. */
export function template(): Uint8Array {
  if (!templateBytes) {
    const t = Uint8Array.from(atob(TEMPLATE_BASE64), (c) => c.charCodeAt(0));
    if (t.length !== SCRIPT_LEN || toHex(sha256(t)) !== TEMPLATE_SHA256) throw new Error("Corrupt script template.");
    templateBytes = t;
  }
  return templateBytes.slice();
}

/** In script order: (offset of the first push opcode, stride, count, first root index). */
const LAYOUT: [number, number, number, number][] = [
  [6, 0, 1, 153],
  [34, 21, 12, 109],
  [306, 31, 109, 0],
  [3675, 21, 16, 121],
  [4175, 21, 16, 137],
];
/** [offset of the 20 committed bytes, root index] of each slot. */
const SLOTS: [number, number][] = LAYOUT.flatMap(([push, stride, count, first]) =>
  Array.from({ length: count }, (_, i) => [push + i * stride + 1, first + i] as [number, number]),
);

/** The vault's 4,908-byte locking script: the template with the commitments filled in. */
export function vaultScript(commitments: Uint8Array[]): Uint8Array {
  commitmentRoot(commitments); // checks the shape
  const out = template();
  for (const [at, index] of SLOTS) out.set(commitments[index], at);
  return out;
}

/**
 * The 154 commitments embedded in a PQB-v1 script, in root order. Throws unless
 * the script is the template apart from its commitments.
 */
export function commitmentsFromScript(script: Uint8Array): Uint8Array[] {
  if (script.length !== SCRIPT_LEN) throw new Error("Not a PQB-v1 script: wrong length.");
  const commitments: Uint8Array[] = new Array(COMMITMENTS);
  const masked = script.slice();
  for (const [at, index] of SLOTS) {
    commitments[index] = script.slice(at, at + 20);
    masked.fill(0, at, at + 20);
  }
  if (!equalBytes(masked, template())) throw new Error("Not a PQB-v1 script: template mismatch.");
  return commitments;
}

export const scriptHash = (script: Uint8Array): Uint8Array => sha256(script);

/**
 * Legacy SIGHASH_ALL digest of the only input of `t` (scriptSig empty, no
 * witness), with `scriptCode` as the script code: the co-signature's message z.
 */
export function legacySighashAll(t: Uint8Array, scriptCode: Uint8Array): Uint8Array {
  const tx = parseTx(t);
  if (tx.segwit || tx.inputs.length !== 1 || tx.inputs[0].scriptSig.length !== 0)
    throw new Error("Not a single-input transaction with an empty scriptSig.");
  const withCode = serializeTx({ ...tx, inputs: [{ ...tx.inputs[0], scriptSig: scriptCode }] });
  return sha256(sha256(concat(withCode, u32le(SIGHASH_ALL))));
}

/** What a withdrawal discloses: table indices per round and one menu pick per stage. */
export type DisclosureRequest = { round0: number[]; round1: number[]; picks: [number, number, number] };

/** Throws unless the request satisfies the BIP's cardinality, range, order and disjointness rules. */
export function checkRequest({ round0, round1, picks }: DisclosureRequest): void {
  const ascending = (xs: number[], n: number, name: string) => {
    if (!Array.isArray(xs) || xs.length !== n) throw new Error(`${name} needs exactly ${n} indices.`);
    xs.forEach((x, i) => {
      if (!Number.isInteger(x) || x < 0 || x >= TABLE) throw new Error(`${name} index out of range: ${x}`);
      if (i > 0 && x <= xs[i - 1]) throw new Error(`${name} indices must be strictly ascending.`);
    });
  };
  ascending(round0, ROUND0, "round0");
  ascending(round1, ROUND1, "round1");
  if (round0.some((x) => round1.includes(x))) throw new Error("An index appears in both rounds.");
  if (!Array.isArray(picks) || picks.length !== 3) throw new Error("Need one menu pick per stage.");
  picks.forEach((p, k) => {
    if (!Number.isInteger(p) || p < 0 || p >= MENU_WIDTHS[k]) throw new Error(`Menu pick ${k} out of range: ${p}`);
  });
}

/** D = SHA256("PQB-v1/reveal" || round0 || round1 || p0 || p1 || p2 || B), B = SHA256(T). */
export function disclosureDigest(request: DisclosureRequest, binding: Uint8Array): Uint8Array {
  checkRequest(request);
  if (binding.length !== 32) throw new Error("B must be 32 bytes.");
  return sha256(
    concat(enc.encode(`${PROFILE}/reveal`), Uint8Array.from(request.round0), Uint8Array.from(request.round1), Uint8Array.from(request.picks), binding),
  );
}

/** The withdrawal transaction's fields; `prevTxid` in internal (serialization) order. */
export type Withdrawal = {
  version: number;
  prevTxid: Uint8Array;
  vout: number;
  sequence: number;
  lockTime: number;
  outputs: TxOutput[];
};

/** T: the withdrawal with an empty scriptSig and no witness. */
export function withdrawalTx(w: Withdrawal): Uint8Array {
  if (w.prevTxid.length !== 32) throw new Error("prevTxid must be 32 bytes.");
  return serializeTx({
    version: w.version,
    inputs: [{ txid: w.prevTxid, vout: w.vout, scriptSig: new Uint8Array(), sequence: w.sequence }],
    outputs: w.outputs,
    lockTime: w.lockTime,
  });
}

/** What REVEAL_READ returns, parsed. Spending-sensitive: keep it out of logs. */
export type DisclosureResponse = {
  /** s[j] for each round-0 index (20 bytes each). */
  round0Preimages: Uint8Array[];
  /** w[j] for each round-1 index (32 bytes each). */
  round1Preimages: Uint8Array[];
  /** g[p0], g[p1], g[p2]: DER || 0x01. */
  menuSignatures: [Uint8Array, Uint8Array, Uint8Array];
  /** The co-signature, DER || 0x01. */
  cosignature: Uint8Array;
  /** The co-signing public key, compressed. */
  Q: Uint8Array;
};

/** Parse REVEAL_READ chunks 0..4 into a DisclosureResponse. */
export function parseReveal(chunks: Uint8Array[]): DisclosureResponse {
  if (chunks.length !== 5) throw new Error("Expected 5 REVEAL_READ chunks.");
  const split = (b: Uint8Array, size: number, n: number, what: string) => {
    if (b.length !== size * n) throw new Error(`Unexpected ${what} length.`);
    return Array.from({ length: n }, (_, i) => b.slice(i * size, (i + 1) * size));
  };
  const lengthPrefixed = (b: Uint8Array, n: number, what: string) => {
    const out: Uint8Array[] = [];
    let pos = 0;
    for (let i = 0; i < n; i++) {
      if (pos >= b.length || pos + 1 + b[pos] > b.length) throw new Error(`Truncated ${what}.`);
      out.push(b.slice(pos + 1, pos + 1 + b[pos]));
      pos += 1 + b[pos];
    }
    return { out, rest: b.subarray(pos) };
  };
  const round0Preimages = split(chunks[0], 20, 8, "round-0 chunk");
  const round1Preimages = [...split(chunks[1], 32, 5, "round-1 chunk"), ...split(chunks[2], 32, 4, "round-1 chunk")];
  const menu = lengthPrefixed(chunks[3], 3, "menu signatures");
  if (menu.rest.length !== 0) throw new Error("Trailing bytes after menu signatures.");
  const cos = lengthPrefixed(chunks[4], 1, "co-signature");
  if (cos.rest.length !== 33) throw new Error("Unexpected Q length.");
  return {
    round0Preimages,
    round1Preimages,
    menuSignatures: menu.out as [Uint8Array, Uint8Array, Uint8Array],
    cosignature: cos.out[0],
    Q: cos.rest.slice(),
  };
}

/** BIP 66 strict DER, without the hash type byte. */
export function isStrictDer(sig: Uint8Array): boolean {
  if (sig.length < 8 || sig.length > 72) return false;
  if (sig[0] !== 0x30 || sig[1] !== sig.length - 2) return false;
  const lenR = sig[3];
  if (5 + lenR >= sig.length) return false;
  const lenS = sig[5 + lenR];
  if (lenR + lenS + 6 !== sig.length) return false;
  if (sig[2] !== 0x02 || lenR === 0 || sig[4] & 0x80) return false;
  if (lenR > 1 && sig[4] === 0 && !(sig[5] & 0x80)) return false;
  if (sig[lenR + 4] !== 0x02 || lenS === 0 || sig[lenR + 6] & 0x80) return false;
  if (lenS > 1 && sig[lenR + 6] === 0 && !(sig[lenR + 7] & 0x80)) return false;
  return true;
}

/** The checks verifyDisclosure applies, by name, in the order applied. */
export class DisclosureError extends Error {}

/**
 * Check a disclosure against the vault's commitments (root order) and T:
 * HASH160(s) = c[j], RIPEMD160(w) = c[j], SHA1(g) = m_stage[p], HASH160(Q) = q,
 * and the co-signature is strict DER, low S, SIGHASH_ALL and valid over z with
 * Q, z the legacy sighash of T with the vault script as script code. Throws a
 * DisclosureError naming the first failure.
 */
export function verifyDisclosure(
  commitments: Uint8Array[],
  request: DisclosureRequest,
  t: Uint8Array,
  response: DisclosureResponse,
): void {
  checkRequest(request);
  const script = vaultScript(commitments);
  const fail = (why: string) => {
    throw new DisclosureError(why);
  };
  if (response.round0Preimages.length !== ROUND0 || response.round1Preimages.length !== ROUND1)
    fail("Wrong number of preimages.");
  request.round0.forEach((j, i) => {
    const s = response.round0Preimages[i];
    if (s.length !== 20 || !equalBytes(hash160(s), commitments[j])) fail(`Round-0 preimage for index ${j} doesn't match c[${j}].`);
  });
  request.round1.forEach((j, i) => {
    const w = response.round1Preimages[i];
    if (w.length !== 32 || !equalBytes(ripemd160(w), commitments[j])) fail(`Round-1 preimage for index ${j} doesn't match c[${j}].`);
  });
  request.picks.forEach((p, k) => {
    const g = response.menuSignatures[k];
    if (!g || !equalBytes(sha1(g), commitments[MENU_OFFSETS[k] + p])) fail(`Menu signature of stage ${k} doesn't match m[${p}].`);
  });
  if (response.Q.length !== 33 || !equalBytes(hash160(response.Q), commitments[Q_INDEX])) fail("Q doesn't match q.");
  const sig = response.cosignature;
  if (sig[sig.length - 1] !== SIGHASH_ALL) fail("Co-signature hash type is not SIGHASH_ALL.");
  const der = sig.subarray(0, -1);
  if (!isStrictDer(der)) fail("Co-signature is not strict DER.");
  const z = legacySighashAll(t, script);
  let valid = false;
  try {
    valid = secp256k1.verify(der, z, response.Q, { format: "der", prehash: false, lowS: true });
  } catch {
    valid = false;
  }
  if (!valid) fail("Co-signature does not verify over z with Q (or has a high S).");
}

// ---- device records and the recovery manifest -----------------------------

/** GET_STATE summary. */
export type StateSummary = {
  walletId: Uint8Array;
  /** 0 none, 1 fresh, 2 unknown. */
  namespace: number;
  nextV: number;
  records: number;
  capacity: number;
};

export const RECORD_STATES = { 1: "allocated", 2: "exposed", 3: "retired", 4: "unknown" } as const;
export type RecordState = (typeof RECORD_STATES)[keyof typeof RECORD_STATES];
export const RECORD_FLAGS = { FUNDED: 0x01, DISCLOSED: 0x02, EMERGENCY: 0x04 } as const;
export const RECORD_LEN = 256;

/** One vault record as the device stores it (GET_STATE, P1 = 0x01). */
export type VaultRecord = {
  walletId: Uint8Array;
  v: number;
  state: RecordState;
  flags: number;
  root: Uint8Array;
  scriptHash: Uint8Array;
  /** Present when flags has FUNDED. txid in internal order. */
  funding: { txid: Uint8Array; vout: number; value: bigint } | null;
  /** The recorded sweep's first input (txid internal || vout LE), 36 bytes. */
  sweepInput: Uint8Array;
  /** Present when flags has DISCLOSED. */
  disclosure: (DisclosureRequest & { binding: Uint8Array; digest: Uint8Array }) | null;
};

export function parseRecord(b: Uint8Array): VaultRecord {
  if (b.length !== RECORD_LEN || b[0] !== 0x01) throw new Error("Unexpected record layout.");
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const state = RECORD_STATES[b[21] as keyof typeof RECORD_STATES];
  if (!state) throw new Error(`Unknown record state ${b[21]}.`);
  const flags = b[22];
  const at = (o: number, n: number) => b.slice(o, o + n);
  return {
    walletId: at(1, 16),
    v: view.getUint32(17),
    state,
    flags,
    root: at(23, 32),
    scriptHash: at(55, 32),
    funding: flags & RECORD_FLAGS.FUNDED ? { txid: at(87, 32), vout: view.getUint32(119, true), value: view.getBigUint64(123, true) } : null,
    sweepInput: at(131, 36),
    disclosure:
      flags & RECORD_FLAGS.DISCLOSED
        ? {
            round0: Array.from(at(167, 8)),
            round1: Array.from(at(175, 9)),
            picks: Array.from(at(184, 3)) as [number, number, number],
            binding: at(187, 32),
            digest: at(219, 32),
          }
        : null,
  };
}

export type ManifestFunding = { txid: string; vout: number; value_sat: number };
export type ManifestDisclosure = {
  round0: number[];
  round1: number[];
  menu_picks: number[];
  transaction: string;
  digest: string;
};
export type ManifestVault = {
  v: number;
  root: string;
  script_pubkey: string | null;
  script_hash: string | null;
  funding: ManifestFunding | null;
  state: RecordState;
  disclosure: ManifestDisclosure | null;
};
export type Manifest = {
  format: "pqb-secret-manifest";
  version: 1;
  profile: "PQB-v1";
  seed_source: "bip85" | "raw32";
  network: "main";
  next_v: number;
  vaults: ManifestVault[];
};

/**
 * The BIP's portable recovery manifest for one seed, from GET_STATE, its
 * records, each vault's script (GET_SCRIPT) and, for each disclosure, the
 * transaction T the host kept (the device stores only B = SHA256(T) and D).
 *
 * Every record is checked: script hash and embedded root, T against B and the
 * funding outpoint, D recomputed. An exposed record without its T is an error.
 * `next_v` is raised to cover any recorded index (an emergency disclosure in an
 * unknown namespace can sit above the device's high-water mark).
 */
export function buildManifest(input: {
  state: StateSummary;
  records: VaultRecord[];
  scripts: Map<number, Uint8Array>;
  transactions?: Map<number, Uint8Array>;
}): Manifest {
  const { state, records, scripts } = input;
  const transactions = input.transactions ?? new Map<number, Uint8Array>();
  const vaults: ManifestVault[] = [];
  const seen = new Set<number>();
  for (const r of [...records].sort((a, b) => a.v - b.v)) {
    if (!equalBytes(r.walletId, state.walletId)) throw new Error(`Record for vault ${r.v} belongs to another seed.`);
    if (seen.has(r.v)) throw new Error(`Two records for vault ${r.v}.`);
    seen.add(r.v);
    const script = scripts.get(r.v) ?? null;
    if (script) {
      if (!equalBytes(scriptHash(script), r.scriptHash)) throw new Error(`Script of vault ${r.v} doesn't match its record's hash.`);
      if (!equalBytes(commitmentRoot(commitmentsFromScript(script)), r.root))
        throw new Error(`Script of vault ${r.v} doesn't carry its record's root.`);
    } else if (r.funding || r.disclosure || r.state === "exposed") {
      throw new Error(`Vault ${r.v} needs its script.`);
    }
    const funding = r.funding
      ? { txid: toHex(r.funding.txid.slice().reverse()), vout: r.funding.vout, value_sat: Number(r.funding.value) }
      : null;
    let disclosure: ManifestDisclosure | null = null;
    if (r.disclosure) {
      const t = transactions.get(r.v);
      if (t) {
        if (!equalBytes(sha256(t), r.disclosure.binding)) throw new Error(`T for vault ${r.v} doesn't hash to its recorded B.`);
        if (!equalBytes(disclosureDigest(r.disclosure, r.disclosure.binding), r.disclosure.digest))
          throw new Error(`Recorded D of vault ${r.v} doesn't match its indices and B.`);
        disclosure = {
          round0: r.disclosure.round0,
          round1: r.disclosure.round1,
          menu_picks: [...r.disclosure.picks],
          transaction: toHex(t),
          digest: toHex(r.disclosure.digest),
        };
      } else if (r.state === "exposed") {
        throw new Error(`Vault ${r.v} is exposed: its withdrawal transaction T is required.`);
      }
    }
    vaults.push({
      v: r.v,
      root: toHex(r.root),
      script_pubkey: script ? toHex(script) : null,
      script_hash: script ? toHex(r.scriptHash) : null,
      funding,
      state: r.state,
      disclosure,
    });
  }
  const nextV = Math.max(state.nextV, ...vaults.map((x) => x.v + 1));
  const manifest: Manifest = {
    format: "pqb-secret-manifest",
    version: 1,
    profile: PROFILE,
    seed_source: "bip85",
    network: "main",
    next_v: nextV,
    vaults,
  };
  validateManifest(manifest);
  return manifest;
}

/** JSON.parse that also rejects duplicate member names and non-integral numbers, and requires valid UTF-8. */
export function parseManifestJson(text: string | Uint8Array): unknown {
  const s = typeof text === "string" ? text : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(text);
  let pos = 0;
  const ws = () => {
    while (pos < s.length && " \t\n\r".includes(s[pos])) pos++;
  };
  const err = (why: string): never => {
    throw new Error(`Manifest JSON: ${why} at ${pos}.`);
  };
  const str = (): string => {
    const m = /^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/.exec(s.slice(pos));
    if (!m) return err("bad string");
    pos += m[0].length;
    return JSON.parse(m[0]);
  };
  const value = (): unknown => {
    ws();
    const c = s[pos];
    if (c === "{") {
      pos++;
      const obj: Record<string, unknown> = Object.create(null);
      ws();
      if (s[pos] === "}") return pos++, { ...obj };
      for (;;) {
        ws();
        if (s[pos] !== '"') err("expected a member name");
        const key = str();
        if (Object.prototype.hasOwnProperty.call(obj, key)) err(`duplicate member "${key}"`);
        ws();
        if (s[pos++] !== ":") err("expected ':'");
        obj[key] = value();
        ws();
        if (s[pos] === ",") pos++;
        else if (s[pos] === "}") return pos++, { ...obj };
        else err("expected ',' or '}'");
      }
    }
    if (c === "[") {
      pos++;
      const arr: unknown[] = [];
      ws();
      if (s[pos] === "]") return pos++, arr;
      for (;;) {
        arr.push(value());
        ws();
        if (s[pos] === ",") pos++;
        else if (s[pos] === "]") return pos++, arr;
        else err("expected ',' or ']'");
      }
    }
    if (c === '"') return str();
    for (const [lit, v] of [["true", true], ["false", false], ["null", null]] as const)
      if (s.startsWith(lit, pos)) return (pos += lit.length), v;
    const m = /^-?(?:0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(s.slice(pos));
    if (!m) return err("unexpected token");
    if (m[1] || m[2]) err("non-integral number");
    pos += m[0].length;
    const n = Number(m[0]);
    if (!Number.isSafeInteger(n)) err("integer out of range");
    return n;
  };
  const out = value();
  ws();
  if (pos !== s.length) err("trailing data");
  return out;
}

/**
 * Check a manifest against the BIP's schema and consistency rules, and
 * recompute what can be recomputed without the seed: script hashes, embedded
 * commitments against the root, disclosure digests, and T against the funding
 * outpoint. Recomputing roots from the seed and checking funding on chain are
 * the importer's job. Accepts parsed JSON (see parseManifestJson).
 */
export function validateManifest(m: unknown): asserts m is Manifest {
  const fail = (why: string): never => {
    throw new Error(`Invalid manifest: ${why}.`);
  };
  const isObj = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
  const exactKeys = (o: Record<string, unknown>, keys: string[], what: string) => {
    const got = Object.keys(o).sort();
    if (got.join() !== [...keys].sort().join()) fail(`${what} must have exactly ${keys.join(", ")}`);
  };
  const int = (x: unknown, lo: number, hi: number, what: string) => {
    if (typeof x !== "number" || !Number.isSafeInteger(x) || x < lo || x > hi) fail(`${what} out of range`);
    return x as number;
  };
  const hexOf = (x: unknown, bytes: number | null, what: string) => {
    if (typeof x !== "string" || !/^([0-9a-f]{2})*$/.test(x) || (bytes !== null && x.length !== 2 * bytes))
      fail(`${what} must be lowercase hex${bytes ? ` of ${bytes} bytes` : ""}`);
    return fromHex(x as string);
  };
  if (!isObj(m)) return fail("not an object");
  exactKeys(m, ["format", "version", "profile", "seed_source", "network", "next_v", "vaults"], "the manifest");
  if (m.format !== "pqb-secret-manifest") fail("format");
  if (m.version !== 1) fail("version");
  if (m.profile !== PROFILE) fail("profile");
  if (m.seed_source !== "bip85" && m.seed_source !== "raw32") fail("seed_source");
  if (m.network !== "main") fail("network");
  const nextV = int(m.next_v, 0, 2 ** 31, "next_v");
  if (m.seed_source === "raw32" && nextV !== 1) fail("raw32 requires next_v = 1");
  if (!Array.isArray(m.vaults)) return fail("vaults must be an array");
  if (m.seed_source === "raw32" && m.vaults.length > 1) fail("raw32 holds at most one vault");
  let last = -1;
  for (const r of m.vaults as unknown[]) {
    if (!isObj(r)) return fail("vault record not an object");
    exactKeys(r, ["v", "root", "script_pubkey", "script_hash", "funding", "state", "disclosure"], "a vault record");
    const v = int(r.v, 0, nextV - 1, "v");
    if (v <= last) fail("vaults must be sorted by v without duplicates");
    if (m.seed_source === "raw32" && v !== 0) fail("raw32 vault must have v = 0");
    last = v;
    const root = hexOf(r.root, 32, "root");
    if (!["allocated", "exposed", "retired", "unknown"].includes(r.state as string)) fail(`state of vault ${v}`);
    if ((r.script_pubkey === null) !== (r.script_hash === null)) fail(`script_pubkey and script_hash of vault ${v} must be null together`);
    let script: Uint8Array | null = null;
    if (r.script_pubkey !== null) {
      script = hexOf(r.script_pubkey, null, "script_pubkey");
      if (script.length === 0 || script.length > 10_000) fail(`script of vault ${v} is empty or too long`);
      if (!equalBytes(scriptHash(script), hexOf(r.script_hash, 32, "script_hash"))) fail(`script_hash of vault ${v}`);
      let embedded: Uint8Array[];
      try {
        embedded = commitmentsFromScript(script);
      } catch {
        return fail(`script of vault ${v} is not a PQB-v1 script`);
      }
      if (!equalBytes(commitmentRoot(embedded), root)) fail(`script of vault ${v} doesn't carry its root`);
    }
    let funding: { txid: Uint8Array; vout: number } | null = null;
    if (r.funding !== null) {
      if (!isObj(r.funding)) return fail(`funding of vault ${v}`);
      exactKeys(r.funding, ["txid", "vout", "value_sat"], "funding");
      funding = { txid: hexOf(r.funding.txid, 32, "funding.txid").reverse(), vout: int(r.funding.vout, 0, 0xffffffff, "funding.vout") };
      int(r.funding.value_sat, 0, 2_100_000_000_000_000, "funding.value_sat");
      if (!script) fail(`funding of vault ${v} requires a script`);
    }
    if (r.state === "exposed" && (r.disclosure === null || !funding || !script)) fail(`exposed vault ${v} needs script, funding and disclosure`);
    if (r.state === "allocated" && r.disclosure !== null) fail(`allocated vault ${v} cannot have a disclosure`);
    if (r.disclosure !== null) {
      const d = r.disclosure;
      if (!isObj(d)) return fail(`disclosure of vault ${v}`);
      exactKeys(d, ["round0", "round1", "menu_picks", "transaction", "digest"], "disclosure");
      if (!script || !funding) return fail(`disclosure of vault ${v} requires script and funding`);
      const request = { round0: d.round0, round1: d.round1, picks: d.menu_picks } as DisclosureRequest;
      try {
        checkRequest(request);
      } catch (e) {
        fail(`disclosure of vault ${v}: ${(e as Error).message}`);
      }
      const t = hexOf(d.transaction, null, "transaction");
      let tx;
      try {
        tx = parseTx(t);
      } catch {
        return fail(`transaction of vault ${v} doesn't parse`);
      }
      if (tx.segwit || tx.inputs.length !== 1 || tx.inputs[0].scriptSig.length !== 0)
        fail(`transaction of vault ${v} must have one input, an empty scriptSig and no witness`);
      if (!equalBytes(tx.inputs[0].txid, funding.txid) || tx.inputs[0].vout !== funding.vout)
        fail(`transaction of vault ${v} doesn't spend its funding`);
      if (!equalBytes(disclosureDigest(request, sha256(t)), hexOf(d.digest, 32, "digest"))) fail(`digest of vault ${v}`);
    }
  }
}
