/** Host tests of the client, with a mock transport where a device is needed. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as btc from "@scure/btc-signer";
import { base64, hex } from "@scure/base";
import { Verifier } from "bip322-js";
import { LedgerQsbSigner, QsbApp, QsbStatusError, psbtKind, serializePath, stripWitness, txidOf } from "../src/index.js";
import type { ApduTransport } from "../src/index.js";

const fixture = (name: string) =>
  hex.decode(readFileSync(new URL(`../../../tests/fixtures/${name}`, import.meta.url), "utf8").trim());

test("stripWitness recovers each mainnet fixture's txid", () => {
  for (const [name, txid] of [
    ["mainnet-deposit.hex", "1378dd5c26aa027b329e7a0645a4087e9cc9e0e619cf605135f76b5a27ad5750"],
    ["mainnet-deposit-prev.hex", "51f8e1c10970555dc2f762ac3a6c402e625450f12eb7aa67d7ff61a478a5f53e"],
    ["mainnet-withdrawal.hex", "fb46f6092560cbf3b254a8125644e42db3a361b94a2b3bafee4454d84297d13a"],
  ]) {
    const raw = fixture(name);
    const stripped = stripWitness(raw);
    assert.equal(txidOf(stripped), txid, name);
    assert.deepEqual(stripped, btc.Transaction.fromRaw(raw, { allowUnknownOutputs: true }).toBytes(true, false));
    // A legacy serialization passes through unchanged.
    assert.deepEqual(stripWitness(stripped), stripped);
  }
});

test("serializePath", () => {
  assert.equal(hex.encode(serializePath("m/84'/0'/0'/0/7")), "058000005480000000800000000000000000000007");
  for (const bad of ["84'/0'", "m/84'/0'/", "m/1e3", "m/0x10", "m/-1", "m/2147483648", "m//0"])
    assert.throws(() => serializePath(bad), bad);
});

/** A transport answering from a script of `[expected INS, response hex + SW]`. */
function mockTransport(script: [number, string][]): ApduTransport & { sent: number[] } {
  const sent: number[] = [];
  return {
    sent,
    async send(_cla, ins) {
      sent.push(ins);
      const next = script.shift();
      assert.ok(next, "unexpected APDU");
      assert.equal(ins, next[0]);
      return Buffer.from(next[1], "hex");
    },
  };
}

test("status words other than 0x9000 throw, even if the transport doesn't", async () => {
  const app = new QsbApp(mockTransport([[0x03, "b00a"]]));
  await assert.rejects(app.getVersion(), (e) => e instanceof QsbStatusError && e.statusWord === 0xb00a);
  // Ledger transports throw TransportStatusError with a statusCode instead.
  const throwing: ApduTransport = {
    async send() {
      throw Object.assign(new Error("denied"), { statusCode: 0x6985 });
    },
  };
  await assert.rejects(new QsbApp(throwing).getVersion(), (e) => e instanceof QsbStatusError && e.statusWord === 0x6985);
});

test("a command refused during a status screen (0x6901) is resent", async () => {
  const t = mockTransport([
    [0x03, "6901"],
    [0x03, "6901"],
    [0x03, "0001009000"],
  ]);
  assert.equal(await new QsbApp(t).getVersion(), "0.1.0");
  assert.equal(t.sent.length, 3);
});

// BIP-322 reference key L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k and its
// specification signature of "Hello World".
const ADDRESS = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
const PUBKEY = "02c7f12003196442943d8588e01aee840423cc54fc1521526a3b85c2b0cbd58872";
const SPEC_SIG =
  "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";

test("bip322-js (strict, as qsb-app's server uses it) accepts the specification vector", () => {
  assert.ok(Verifier.verifySignature(ADDRESS, "Hello World", SPEC_SIG, true));
});

test("signMessage encodes the device signature as a BIP-322 simple signature", async () => {
  const witness = base64.decode(SPEC_SIG);
  const derWithSighash = witness.subarray(2, 2 + witness[1]);
  const addressHex = Buffer.from(ADDRESS).toString("hex");
  const t = mockTransport([
    [0x05, `${PUBKEY}${(ADDRESS.length).toString(16)}${addressHex}9000`],
    [0x07, `${hex.encode(derWithSighash)}9000`],
  ]);
  const signer = await LedgerQsbSigner.connect(t);
  assert.equal(signer.address, ADDRESS);
  const signature = await signer.signMessage(ADDRESS, "Hello World");
  assert.equal(signature, SPEC_SIG);
  assert.ok(Verifier.verifySignature(ADDRESS, "Hello World", signature, true));
  await assert.rejects(signer.signMessage("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "x"));
});

test("psbtKind tells qsb-app's withdrawal from a deposit", () => {
  const opts = { allowUnknownInputs: true, allowUnknownOutputs: true };
  const withdrawal = btc.Transaction.fromRaw(fixture("mainnet-withdrawal.hex"), opts);
  const unsigned = new btc.Transaction({ ...opts, version: 1 });
  // Outputs first: @scure/btc-signer refuses new outputs once an input is finalized.
  unsigned.addOutput(withdrawal.getOutput(0) as { amount: bigint; script: Uint8Array });
  unsigned.addInput({ txid: withdrawal.getInput(0).txid!, index: 1 });
  unsigned.addInput({ txid: withdrawal.getInput(1).txid!, index: 0, finalScriptSig: withdrawal.getInput(1).finalScriptSig });
  assert.equal(psbtKind(unsigned, [0]), "withdrawal");
  assert.throws(() => psbtKind(unsigned, [0, 1]));
  const deposit = btc.Transaction.fromRaw(fixture("mainnet-deposit.hex"), opts);
  assert.equal(psbtKind(deposit, [0]), "deposit");
  assert.throws(() => psbtKind(deposit, []));
});

// --- QSB-HORS-v1 -----------------------------------------------------------

import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { QsbHors, commitmentRoot, fingerprint } from "../src/index.js";

/** The derivation, written a third time (after qsb-core and the Python reference). */
function secret(k: Uint8Array, net: number, v: number, r: number, i: number): Uint8Array {
  const m = new Uint8Array(20);
  m.set(new TextEncoder().encode("QSB-HORS-v1"));
  m[12] = net;
  new DataView(m.buffer).setUint32(13, v);
  m[17] = r;
  new DataView(m.buffer).setUint16(18, i);
  return hmac(sha256, k, m).slice(0, 20);
}
const K = Uint8Array.from({ length: 32 }, (_, i) => i);
const commitmentsOf = (net: number, v: number): [Uint8Array[], Uint8Array[]] => [
  Array.from({ length: 150 }, (_, i) => ripemd160(sha256(secret(K, net, v, 0, i)))),
  Array.from({ length: 150 }, (_, i) => ripemd160(sha256(secret(K, net, v, 1, i)))),
];

test("commitment root and fingerprint match the reference vectors", () => {
  const root = commitmentRoot(commitmentsOf(0, 0));
  assert.equal(hex.encode(root), "9b257b6acd00017b1488ed9d73d05bc8a5dbdd43c8aa54d1d37c7e807d65c515");
  assert.equal(fingerprint(root), "9b25 7b6a cd00 017b");
});

/** A device holding K, answering the HORS APDUs without screens. */
function horsDevice(tamper = false): ApduTransport & { sent: number[] } {
  const sent: number[] = [];
  let approved: [number, number][] | undefined;
  let vault = { net: 0, v: 0 };
  return {
    sent,
    async send(_cla, ins, p1, _p2, data = Buffer.alloc(0)) {
      sent.push(ins);
      const ok = (b: Uint8Array) => Buffer.concat([Buffer.from(b), Buffer.from([0x90, 0x00])]);
      if (ins === 0x10) {
        const v = data.readUInt32BE(1), start = data.readUInt16BE(5), count = data[7];
        const cs = commitmentsOf(data[0], v)[p1].slice(start, start + count);
        return ok(Buffer.concat(cs));
      }
      if (ins === 0x11) return ok(commitmentRoot(commitmentsOf(data[0], data.readUInt32BE(1))));
      if (ins === 0x20) {
        vault = { net: data[0], v: data.readUInt32BE(1) };
        const idx = (o: number, n: number) => Array.from({ length: n }, (_, k) => data.readUInt16BE(o + 2 * k));
        approved = [...idx(5, 8).map((i) => [0, i] as [number, number]), ...idx(21, 7).map((i) => [1, i] as [number, number])];
        return ok(new Uint8Array());
      }
      if (ins === 0x21 && approved) {
        const part = p1 === 0 ? approved.slice(0, 12) : approved.slice(12);
        const out = part.map(([r, i]) => secret(K, vault.net, vault.v, r, i));
        if (tamper) out[0] = out[0].map((b) => b ^ 1);
        return ok(Buffer.concat(out));
      }
      return Buffer.from([0x6a, 0x91]);
    },
  };
}

test("QsbHors reads commitments, checks the root, and verifies a reveal", async () => {
  const hors = new QsbHors(new QsbApp(horsDevice()));
  const vault = { net: 0, index: 7 };
  const commitments = await hors.getVerifiedCommitments(vault);
  assert.equal(commitments[0].length, 150);
  const request = {
    round1: [9, 3, 140, 0, 1, 2, 4, 5],
    round2: [149, 7, 8, 10, 11, 12, 13],
    binding: new Uint8Array(32).fill(0xab),
    amount: 92_083n,
    destinationScript: hex.decode("5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"),
  };
  const preimages = await hors.reveal(vault, request, commitments);
  assert.equal(preimages.length, 15);
  assert.deepEqual(preimages[0], secret(K, 0, 7, 0, 9));
  assert.deepEqual(preimages[14], secret(K, 0, 7, 1, 13));

  // Requests that would spend the vault's one reveal on the wrong set never reach the device.
  const device = horsDevice();
  const guarded = new QsbHors(new QsbApp(device));
  for (const bad of [
    { round1: [65536 + 9, 3, 140, 0, 1, 2, 4, 5] }, // wraps to 9 in a u16
    { round1: [3.5, 3, 140, 0, 1, 2, 4, 5] },
    { round1: [9, 9, 140, 0, 1, 2, 4, 5] },
    { round1: [9, 3, 150, 0, 1, 2, 4, 5] },
    { round2: [149, 7, 8] },
    { amount: -1n },
  ]) {
    await assert.rejects(guarded.reveal(vault, { ...request, ...bad }, commitments));
  }
  await assert.rejects(guarded.reveal({ net: 2, index: 7 }, request, commitments), /network/);
  assert.equal(device.sent.length, 0, "nothing was sent");

  // A preimage that doesn't hash to its commitment is refused.
  const lying = new QsbHors(new QsbApp(horsDevice(true)));
  await assert.rejects(lying.reveal(vault, request, commitments), /doesn't match its commitment/);
  // Commitments from another vault don't match the device's root.
  const other = new QsbHors(new QsbApp({ ...horsDevice(), async send(c, ins, p1, p2, d) {
    if (ins === 0x11) return Buffer.concat([Buffer.alloc(32), Buffer.from([0x90, 0x00])]);
    return horsDevice().send(c, ins, p1, p2, d);
  } }));
  await assert.rejects(other.getVerifiedCommitments(vault), /don't match/);
});
