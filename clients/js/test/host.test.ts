/** Host tests of the client: BIP vectors, and a simulated device where one is needed. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  DisclosureError,
  PqbApp,
  PqbStatusError,
  commitmentRoot,
  commitmentsFromScript,
  disclosureDigest,
  fingerprint,
  legacySighashAll,
  parseRecord,
  scriptHash,
  serializeTx,
  parseTx as parseTxOf,
  stripWitness,
  txidOf,
  vaultScript,
  verifyDisclosure,
  withdrawalTx,
  type ApduTransport,
  type DisclosureRequest,
  type DisclosureResponse,
} from "../src/index.js";
import * as ref from "./reference.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));
const vectors = JSON.parse(readFileSync(new URL("./fixtures/vectors.json", import.meta.url), "utf8"));
const SEED = unhex(vectors.seed);
const CS = ref.commitments(SEED);
const ROOT = "48629f7b1de16b950bbd36124838bc887b0b1c9e6735bf6c8c6b9214a6a3590d";
const SCRIPT_HASH = "7543fe1034af70cca89e7c824d729a217c859816b237bc86af73b1c3fdc3d9fb";

// ---- derivation and script -------------------------------------------------

test("the reference port matches the BIP vectors", () => {
  const b = vectors.bip85;
  const child = ref.bip85Child(ref.bip39Seed(b.mnemonic, b.passphrase), b.index);
  assert.equal(hex(child), b.child_entropy);
  for (const net of ["main", "testnet4", "regtest"]) assert.equal(hex(ref.vaultSeed(child, net)), b.vault_seeds[net]);
  for (const h of vectors.hors) {
    const { s, w, c } = ref.hors(SEED, h.j);
    assert.deepEqual([hex(s), hex(w), hex(c)], [h.round0, h.round1, h.commitment]);
  }
  for (const m of vectors.menus) {
    const entries = ref.menu(SEED, m.stage);
    assert.equal(entries.length, m.width);
    assert.equal(ref.menuR(SEED, m.stage).toString(16).padStart(m.r.length, "0"), m.r);
    for (const [e, v] of [[entries[0], m.first], [entries[m.width - 1], m.last]] as const) {
      assert.equal(e.x.toString(16).padStart(64, "0"), v.scalar);
      assert.equal(hex(e.sig), v.signature);
      assert.equal(hex(e.m), v.commitment);
    }
  }
  assert.equal(hex(ref.cosignKey(SEED).Q), vectors.cosign.public_key);
  assert.equal(hex(ref.depositKey(SEED).publicKey), vectors.deposit.public_key);
});

test("commitment root and fingerprint for seed 00..1f", () => {
  const root = commitmentRoot(CS);
  assert.equal(hex(root), ROOT);
  assert.equal(hex(root), vectors.root);
  assert.equal(fingerprint(root), "4862 9f7b 1de1 6b95");
  assert.throws(() => commitmentRoot(CS.slice(1)));
});

test("vault script from the template matches pqb's script for seed 00..1f", () => {
  const script = vaultScript(CS);
  assert.equal(script.length, 4696);
  assert.equal(hex(scriptHash(script)), SCRIPT_HASH);
  const fixture = new URL("../../../tests/fixtures/pqb-script-seed0123.hex", import.meta.url);
  let expected: string | undefined;
  try {
    expected = readFileSync(fixture, "utf8").trim();
  } catch {
    // The repository fixture is optional here; the hash above pins the script.
  }
  if (expected) assert.equal(hex(script), expected);
  assert.deepEqual(commitmentsFromScript(script), CS);
  const tampered = script.slice();
  tampered[0] ^= 1;
  assert.throws(() => commitmentsFromScript(tampered), /template/);
  assert.throws(() => commitmentsFromScript(script.subarray(1)), /length/);
});

test("disclosure digest vector", () => {
  const d = vectors.disclosure;
  const t = unhex(d.transaction);
  assert.equal(hex(sha256(t)), d.binding);
  const request: DisclosureRequest = { round0: d.round0, round1: d.round1, picks: d.menu_picks };
  assert.equal(hex(disclosureDigest(request, sha256(t))), d.digest);
  for (const bad of [
    { round0: [1, 0, 2, 3, 4, 5, 6, 7] },
    { round0: [0, 1, 2, 3, 4, 5, 6] },
    { round0: [0, 1, 2, 3, 4, 5, 6, 100] },
    { round1: [100, 101, 102, 103, 104, 105, 106, 107, 109] },
    { picks: [12, 0, 0] },
    { picks: [0, 16, 0] },
    { picks: [0, 0, 1.5] },
  ])
    assert.throws(() => disclosureDigest({ ...request, ...bad } as DisclosureRequest, sha256(t)));
});

/** z the way pqb.py computes it, by splicing the script code into T's bytes. */
function sighashBySplice(t: Uint8Array, script: Uint8Array): Uint8Array {
  assert.equal(t[4], 1);
  assert.equal(t[41], 0);
  const size = Uint8Array.of(0xfd, script.length & 0xff, script.length >> 8);
  return sha256(sha256(Buffer.concat([t.subarray(0, 41), size, script, t.subarray(42), Uint8Array.of(1, 0, 0, 0)])));
}

test("legacy SIGHASH_ALL of T with the vault script", () => {
  const t = unhex(vectors.disclosure.transaction);
  const script = vaultScript(CS);
  assert.deepEqual(legacySighashAll(t, script), sighashBySplice(t, script));
});

// ---- a simulated device ----------------------------------------------------

const ok = (b: Uint8Array = new Uint8Array()) => Buffer.concat([Buffer.from(b), Buffer.from([0x90, 0x00])]);
const sw = (n: number) => Buffer.from([n >> 8, n & 0xff]);

type Tamper = (r: DisclosureResponse) => void;

/** Answers the read-only and WITHDRAW APDUs for seed 00..1f (every v), approving everything. */
function device(tamper?: Tamper): ApduTransport & { sent: [number, number, string][] } {
  const sent: [number, number, string][] = [];
  const script = vaultScript(CS);
  let start: Buffer | undefined;
  let outputs = Buffer.alloc(0);
  let reveal: Uint8Array[] | undefined;
  return {
    sent,
    async send(_cla, ins, p1, _p2, data = Buffer.alloc(0)) {
      sent.push([ins, p1, data.toString("hex")]);
      switch (ins) {
        case 0x03:
          return ok(Buffer.from([1, 2, 3, ...Buffer.from("PQB-v1")]));
        case 0x10: {
          const [s, n] = [data[4], data[5]];
          if (n < 1 || n > 12 || s + n > 154) return sw(0x6a80);
          return ok(Buffer.concat(CS.slice(s, s + n)));
        }
        case 0x11:
          return ok(Buffer.concat([commitmentRoot(CS), scriptHash(script), Buffer.from([1, 0])]));
        case 0x12: {
          const off = data.readUInt16BE(4);
          return ok(script.subarray(off, off + 250));
        }
        case 0x40:
          if (p1 === 0) {
            start = Buffer.from(data);
            outputs = Buffer.alloc(0);
          } else if (p1 === 2) outputs = Buffer.concat([outputs, data]);
          else if (p1 === 3) {
            const s = start!;
            const t = Buffer.concat([
              s.subarray(4, 8),
              Buffer.from([1]),
              s.subarray(8, 44),
              Buffer.from([0]),
              s.subarray(44, 48),
              s.subarray(52, 53),
              outputs,
              s.subarray(48, 52),
            ]);
            const round0 = Array.from(s.subarray(53, 61));
            const round1 = Array.from(s.subarray(61, 70));
            const picks = Array.from(s.subarray(70, 73));
            const r: DisclosureResponse = {
              round0Preimages: round0.map((j) => ref.hors(SEED, j).s),
              round1Preimages: round1.map((j) => ref.hors(SEED, j).w),
              menuSignatures: picks.map((p, k) => ref.menu(SEED, k)[p].sig) as [Uint8Array, Uint8Array, Uint8Array],
              cosignature: ref.cosign(SEED, sighashBySplice(t, script)),
              Q: ref.cosignKey(SEED).Q,
            };
            tamper?.(r);
            const lp = (b: Uint8Array) => Buffer.concat([Buffer.from([b.length]), b]);
            reveal = [
              Buffer.concat(r.round0Preimages),
              Buffer.concat(r.round1Preimages.slice(0, 5)),
              Buffer.concat(r.round1Preimages.slice(5)),
              Buffer.concat(r.menuSignatures.map(lp)),
              Buffer.concat([lp(r.cosignature), r.Q]),
            ];
          }
          return ok();
        case 0x41:
          return reveal ? ok(reveal[p1]) : sw(0x6a91);
        case 0x42:
          if (p1 === 2) return ok(Uint8Array.from(Buffer.from(ref.menuR(SEED, data[4]).toString(16).padStart(64, "0"), "hex")));
          return p1 === 0 ? ok() : ok(new Uint8Array(33 * data[7]).fill(2));
        default:
          return sw(0x6d00);
      }
    },
  };
}

test("status words map to typed errors, whether or not the transport throws", async () => {
  const replying: ApduTransport = { send: async () => sw(0x6a97) };
  await assert.rejects(new PqbApp(replying).getVersion(), (e) => e instanceof PqbStatusError && e.statusWord === 0x6a97 && e.status === "MENU_POINTS_UNAUTHORIZED");
  const throwing: ApduTransport = {
    async send() {
      throw Object.assign(new Error("denied"), { statusCode: 0x6985 });
    },
  };
  await assert.rejects(new PqbApp(throwing).getVersion(), (e) => e instanceof PqbStatusError && e.status === "REJECTED");
  const odd: ApduTransport = { send: async () => sw(0x6abc) };
  await assert.rejects(new PqbApp(odd).getVersion(), (e) => e instanceof PqbStatusError && e.status === "UNKNOWN");
});

test("a command refused during a status screen (0x6901) is resent", async () => {
  const replies = [sw(0x6901), sw(0x6901), ok(Buffer.from([0, 1, 0, ...Buffer.from("PQB-v1")]))];
  let calls = 0;
  const app = new PqbApp({ send: async () => (calls++, replies.shift()!) });
  assert.deepEqual(await app.getVersion(), { version: "0.1.0", profile: "PQB-v1" });
  assert.equal(calls, 3);
});

test("reads commitments, vault and script in chunks", async () => {
  const d = device();
  const app = new PqbApp(d);
  assert.deepEqual(await app.getVersion(), { version: "1.2.3", profile: "PQB-v1" });
  const cs = await app.getCommitments(5);
  assert.deepEqual(cs, CS);
  assert.equal(d.sent.filter(([ins]) => ins === 0x10).length, 13);
  assert.equal(d.sent.at(-1)![2], "00000005" + "90" + "0a"); // start 144, count 10
  const vault = await app.getVault(5);
  assert.equal(hex(vault.root), ROOT);
  assert.equal(vault.status, "allocated");
  const script = await app.getScript(5);
  assert.equal(hex(scriptHash(script)), SCRIPT_HASH);
  assert.equal(d.sent.filter(([ins]) => ins === 0x12).length, 19);
  const points = await app.getMenuPoints(5, 1, 0);
  assert.equal(points.length, 16);
  assert.deepEqual(
    d.sent.filter(([ins, p1]) => ins === 0x42 && p1 === 1).map(([, , data]) => data.slice(8)),
    ["01000007", "01000707", "01000e02"],
  );
  for (const stage of [0, 1, 2] as const) assert.equal(await app.getMenuR(5, stage), ref.menuR(SEED, stage));
  assert.equal(await app.getMenuR(5, 1), 0x81n);
  await assert.rejects(app.getCommitments(2 ** 31));
});

/** A legacy transaction paying `amount` to `script` at output 0. */
const fundingTx = (script: Uint8Array, amount: bigint) =>
  serializeTx({
    version: 2,
    inputs: [{ txid: new Uint8Array(32).fill(7), vout: 1, scriptSig: new Uint8Array(), sequence: 0xfffffffd }],
    outputs: [{ amount, script }],
    lockTime: 0,
  });

const REQUEST: DisclosureRequest = { round0: [0, 3, 9, 20, 40, 60, 80, 108], round1: [1, 2, 4, 5, 6, 7, 8, 10, 107], picks: [11, 0, 15] };
const withdrawRequest = () => ({
  ...REQUEST,
  prevTx: fundingTx(vaultScript(CS), 100_000n),
  vout: 0,
  version: 2,
  sequence: 0x7ffffffe,
  lockTime: 950_000_000,
  outputs: [
    { amount: 60_000n, script: unhex("0014" + "11".repeat(20)) },
    { amount: 30_000n, script: unhex("5120" + "22".repeat(32)) },
  ],
});

test("withdraw streams the request, reads chunks 0..4 and verifies them", async () => {
  const d = device();
  const r = await new PqbApp(d).withdraw(3, withdrawRequest(), CS);
  const steps = d.sent.map(([ins, p1]) => `${ins.toString(16)}/${p1}`);
  // The previous transaction carries the 4,696-byte script: one PREVTX per 255 bytes.
  assert.equal(steps.filter((x) => x === "40/1").length, Math.ceil(stripWitness(withdrawRequest().prevTx).length / 255));
  assert.deepEqual(
    steps.filter((x, i) => x !== steps[i - 1]),
    ["40/0", "40/1", "40/2", "40/3", "41/0", "41/1", "41/2", "41/3", "41/4"],
  );
  const startData = d.sent[0][2];
  assert.equal(startData.length, 2 * 73);
  assert.equal(startData.slice(0, 8), "00000003");
  assert.equal(r.round0Preimages.length, 8);
  assert.deepEqual(r.round1Preimages[8], ref.hors(SEED, 107).w);
  assert.deepEqual(r.Q, ref.cosignKey(SEED).Q);
  assert.deepEqual(r.binding, sha256(r.transaction));
  assert.deepEqual(r.digest, disclosureDigest(REQUEST, r.binding));
  // T spends the funding output.
  assert.equal(hex(r.transaction.subarray(5, 37).slice().reverse()), txidOf(withdrawRequest().prevTx));
});

test("withdraw refuses a lying device", async () => {
  const flip = (b: Uint8Array) => {
    b[b.length - 2] ^= 1;
  };
  const tampers: [string, Tamper][] = [
    ["round-0 preimage", (r) => flip(r.round0Preimages[3])],
    ["round-1 preimage", (r) => flip(r.round1Preimages[8])],
    ["menu signature 0", (r) => flip(r.menuSignatures[0])],
    ["menu signature 2", (r) => flip(r.menuSignatures[2])],
    ["Q", (r) => (r.Q = ref.cosignKey(new Uint8Array(32)).Q)],
    ["co-signature", (r) => flip(r.cosignature)],
  ];
  for (const [what, tamper] of tampers)
    await assert.rejects(new PqbApp(device(tamper)).withdraw(0, withdrawRequest(), CS), DisclosureError, what);
  // A previous transaction that doesn't pay this vault never reaches the device.
  const d = device();
  await assert.rejects(new PqbApp(d).withdraw(0, { ...withdrawRequest(), prevTx: fundingTx(unhex("51"), 1n) }, CS), /vault's script/);
  await assert.rejects(new PqbApp(d).withdraw(0, { ...withdrawRequest(), round0: [0, 0, 1, 2, 3, 4, 5, 6] }, CS));
  assert.equal(d.sent.length, 0);
});

// ---- disclosure verification, item by item ----------------------------------

function honest(): { t: Uint8Array; response: DisclosureResponse } {
  const req = withdrawRequest();
  const t = withdrawalTx({ ...req, prevTxid: sha256(sha256(stripWitness(req.prevTx))) });
  return {
    t,
    response: {
      round0Preimages: REQUEST.round0.map((j) => ref.hors(SEED, j).s),
      round1Preimages: REQUEST.round1.map((j) => ref.hors(SEED, j).w),
      menuSignatures: REQUEST.picks.map((p, k) => ref.menu(SEED, k)[p].sig) as [Uint8Array, Uint8Array, Uint8Array],
      cosignature: ref.cosign(SEED, legacySighashAll(t, vaultScript(CS))),
      Q: ref.cosignKey(SEED).Q,
    },
  };
}

/** r and s of DER || hashtype. */
function rs(sig: Uint8Array): [bigint, bigint] {
  const lr = sig[3];
  const r = BigInt("0x" + hex(sig.subarray(4, 4 + lr)));
  const s = BigInt("0x" + hex(sig.subarray(6 + lr, 6 + lr + sig[5 + lr])));
  return [r, s];
}

test("verifyDisclosure accepts honest data and rejects each tampered item", () => {
  const { t, response } = honest();
  verifyDisclosure(CS, REQUEST, t, response);
  const n = secp256k1.Point.CURVE().n;
  const [r, s] = rs(response.cosignature);
  const cases: [string, (x: DisclosureResponse) => void, RegExp][] = [
    ["s[j] of another index", (x) => (x.round0Preimages[0] = ref.hors(SEED, 1).s), /Round-0/],
    ["w[j] of another index", (x) => (x.round1Preimages[4] = ref.hors(SEED, 0).w), /Round-1/],
    ["s[j] given as w[j]", (x) => (x.round1Preimages[0] = ref.hors(SEED, REQUEST.round1[0]).s), /Round-1/],
    ["menu signature of another pick", (x) => (x.menuSignatures[1] = ref.menu(SEED, 1)[1].sig), /stage 1/],
    ["Q of another key", (x) => (x.Q = secp256k1.getPublicKey(new Uint8Array(32).fill(1), true)), /Q doesn't match/],
    ["hash type", (x) => (x.cosignature = Uint8Array.from([...x.cosignature.subarray(0, -1), 0x81])), /SIGHASH_ALL/],
    ["high S", (x) => (x.cosignature = ref.derSig(r, n - s)), /verify/],
    [
      "non-strict DER (padded S)",
      (x) => {
        const der = x.cosignature.subarray(0, -1);
        const lr = der[3];
        const sBytes = der.subarray(6 + lr);
        const body = Buffer.concat([der.subarray(2, 4 + lr), Buffer.from([0x02, sBytes.length + 1, 0]), sBytes]);
        x.cosignature = Uint8Array.from([0x30, body.length, ...body, 0x01]);
      },
      /strict DER/,
    ],
    ["signature over another message", (x) => (x.cosignature = ref.cosign(SEED, new Uint8Array(32).fill(9))), /verify/],
    ["signature by another key", (x) => (x.cosignature = ref.cosign(new Uint8Array(32), legacySighashAll(t, vaultScript(CS)))), /verify/],
    ["missing preimage", (x) => x.round1Preimages.pop(), /number of preimages/],
  ];
  for (const [what, tamper, why] of cases) {
    const x = honest().response;
    tamper(x);
    assert.throws(() => verifyDisclosure(CS, REQUEST, t, x), (e) => e instanceof DisclosureError && why.test(e.message), what);
  }
  // A co-signature is bound to T: the same response for a different T fails.
  const other = Uint8Array.from(t);
  other[other.length - 1] ^= 1;
  assert.throws(() => verifyDisclosure(CS, REQUEST, other, response), /verify/);
});

// ---- records -----------------------------------------------------------------

const WALLET = new Uint8Array(16).fill(0xaa);

function recordBytes(o: {
  v: number;
  state: number;
  flags: number;
  funding?: { txid: Uint8Array; vout: number; value: bigint };
  disclosure?: { request: DisclosureRequest; t: Uint8Array };
}): Uint8Array {
  const b = Buffer.alloc(256);
  b[0] = 1;
  b.set(WALLET, 1);
  b.writeUInt32BE(o.v, 17);
  b[21] = o.state;
  b[22] = o.flags;
  b.set(commitmentRoot(CS), 23);
  b.set(scriptHash(vaultScript(CS)), 55);
  if (o.funding) {
    b.set(o.funding.txid, 87);
    b.writeUInt32LE(o.funding.vout, 119);
    b.writeBigUInt64LE(o.funding.value, 123);
  }
  if (o.disclosure) {
    const { request, t } = o.disclosure;
    b.set(request.round0, 167);
    b.set(request.round1, 175);
    b.set(request.picks, 184);
    b.set(sha256(t), 187);
    b.set(disclosureDigest(request, sha256(t)), 219);
  }
  return new Uint8Array(b);
}

function recordInputs() {
  const prev = withdrawRequest().prevTx;
  const txid = sha256(sha256(prev));
  const { t } = honest();
  const records = [
    parseRecord(recordBytes({ v: 4, state: 2, flags: 3, funding: { txid, vout: 0, value: 100_000n }, disclosure: { request: REQUEST, t } })),
    parseRecord(recordBytes({ v: 0, state: 1, flags: 0 })),
    parseRecord(recordBytes({ v: 2, state: 1, flags: 1, funding: { txid, vout: 0, value: 100_000n } })),
  ];
  return { records, t };
}

test("parseRecord reads the device layout", () => {
  const { records, t } = recordInputs();
  const r = records[0];
  assert.equal(r.v, 4);
  assert.equal(r.state, "exposed");
  assert.equal(r.funding!.value, 100_000n);
  assert.deepEqual(r.disclosure!.round1, REQUEST.round1);
  assert.deepEqual(r.disclosure!.picks, REQUEST.picks);
  assert.deepEqual(r.disclosure!.binding, sha256(t));
  assert.equal(records[1].funding, null);
  assert.equal(records[1].disclosure, null);
});

// ---- SIGN_DEPOSIT -----------------------------------------------------------

test("signSweep streams START, INPUT + PREVTX per input, OUTPUTS, REVIEW and one SIGN per input", async () => {
  const deposit = unhex("0014" + hex(ref.depositKey(SEED).publicKey).slice(0, 40));
  // The first previous transaction in SegWit serialization: it is witness-stripped before streaming.
  const legacy = fundingTx(deposit, 70_000n);
  const segwit = Buffer.concat([legacy.subarray(0, 4), Buffer.from([0, 1]), legacy.subarray(4, -4), Buffer.from([1, 1, 0xab]), legacy.subarray(-4)]);
  assert.deepEqual(stripWitness(segwit), legacy);
  const other = serializeTx({ version: 1, inputs: [{ txid: new Uint8Array(32), vout: 0, scriptSig: unhex("00"), sequence: 0 }], outputs: [{ amount: 1n, script: unhex("51") }, { amount: 40_000n, script: deposit }], lockTime: 0 });
  const sweep = serializeTx({
    version: 2,
    inputs: [
      { txid: sha256(sha256(other)), vout: 1, scriptSig: new Uint8Array(), sequence: 0xfffffffd },
      { txid: sha256(sha256(legacy)), vout: 0, scriptSig: new Uint8Array(), sequence: 0xfffffffd },
    ],
    outputs: [{ amount: 109_000n, script: vaultScript(CS) }],
    lockTime: 0,
  });
  const sig = ref.cosign(SEED, new Uint8Array(32).fill(1));
  const sent: [number, number, string][] = [];
  const app = new PqbApp({
    async send(_c, ins, p1, _p2, data = Buffer.alloc(0)) {
      sent.push([ins, p1, data.toString("hex")]);
      return ok(p1 === 5 ? sig : new Uint8Array());
    },
  });
  const sigs = await app.signSweep(9, sweep, [segwit, other]);
  assert.deepEqual(sigs, [sig, sig]);
  assert.ok(sent.every(([ins]) => ins === 0x30));
  assert.equal(sent[0][2], "01" + "00000009" + "02000000" + "00000000" + "0201");
  const steps = sent.map(([, p1]) => p1).filter((p, i, a) => p !== a[i - 1]);
  assert.deepEqual(steps, [0, 1, 2, 1, 2, 3, 4, 5]);
  assert.equal(sent[1][2], hex(sha256(sha256(other))) + "01000000" + "fdffffff");
  assert.equal(sent.filter(([, p1]) => p1 === 2).map(([, , d]) => d).join("").length, 2 * (other.length + legacy.length));
  // A sweep has exactly one output; a missing previous transaction is caught before anything is sent.
  sent.length = 0;
  await assert.rejects(app.signSweep(9, sweep, [other]), /previous transaction/);
  assert.equal(sent.length, 0);
  await assert.rejects(app.signSweep(9, serializeTx({ ...parseTxOf(sweep), outputs: [{ amount: 1n, script: unhex("51") }, { amount: 1n, script: unhex("51") }] }), [other, legacy]), /outputs/);
  assert.equal(sent.length, 0);
});
