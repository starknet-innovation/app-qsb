/**
 * End-to-end tests of LedgerQsbSigner against the app running in Speculos
 * (Nano S+), driving its buttons through the Speculos REST API. Skipped unless
 * SPECULOS_API is set, e.g. SPECULOS_API=http://127.0.0.1:5000.
 *
 * PSBTs are built the way qsb-app builds them (fundingPsbt, helperPsbt): every
 * input carries its previous transaction; the withdrawal's vault input is
 * already finalized. Sign-in signatures are checked with bip322-js in strict
 * mode, as qsb-app's server does.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as speculosModule from "@ledgerhq/hw-transport-node-speculos-http";
import * as btc from "@scure/btc-signer";
import { hex } from "@scure/base";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { Verifier } from "bip322-js";
import { LedgerQsbSigner } from "../src/index.js";

const API = process.env.SPECULOS_API;
// The package is CommonJS: its class is the default export's `default`.
const SpeculosHttpTransport = ((speculosModule as unknown as { default: { default?: unknown } }).default.default ??
  (speculosModule as unknown as { default: unknown }).default) as {
  open(opts: { baseURL?: string; apiPort?: string }): Promise<Parameters<typeof LedgerQsbSigner.connect>[0] & { close(): Promise<void> }>;
};
const opts = { allowUnknownInputs: true, allowUnknownOutputs: true };
const fixture = (name: string) =>
  hex.decode(readFileSync(new URL(`../../../tests/fixtures/${name}`, import.meta.url), "utf8").trim());
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function screen(): Promise<string[]> {
  const r = await fetch(`${API}/events?currentscreenonly=true`);
  const { events } = (await r.json()) as { events: { text: string }[] };
  return events.map((e) => e.text);
}

async function press(button: "left" | "right" | "both") {
  await fetch(`${API}/button/${button}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ action: "press-and-release" }),
  });
}

/**
 * Wait for the review to open, page right until a line matches `pattern`, then
 * press both buttons. Returns the lines seen.
 */
async function approve(pattern: RegExp): Promise<string[]> {
  const seen: string[] = [];
  for (let i = 0; !(await screen()).some((l) => l.startsWith("Review")); i++) {
    if (i === 200) throw new Error("No review appeared.");
    await sleep(100);
  }
  for (let i = 0; i < 60; i++) {
    await sleep(250);
    const lines = await screen();
    seen.push(...lines);
    if (lines.some((l) => pattern.test(l))) {
      await press("both");
      return seen;
    }
    await press("right");
  }
  throw new Error(`Never reached ${pattern}; saw ${seen.join(" | ")}`);
}

/** Wait for the home screen once the status screen has gone. */
async function home() {
  for (let i = 0; i < 40; i++) {
    await sleep(250);
    if ((await screen()).some((l) => l.startsWith("QSB vault deposits"))) return;
  }
  throw new Error("The app did not return home.");
}

async function signer(path: string) {
  // The transport appends `:apiPort` to `baseURL` itself.
  const url = new URL(API!);
  const transport = await SpeculosHttpTransport.open({ baseURL: `${url.protocol}//${url.hostname}`, apiPort: url.port || "5000" });
  return { transport, signer: await LedgerQsbSigner.connect(transport, path) };
}

/** A transaction from an arbitrary outpoint paying `amount` to `script`. */
function previous(script: Uint8Array, amount: bigint, salt: number): Uint8Array {
  return btc.RawTx.encode({
    version: 2,
    segwitFlag: false,
    inputs: [{ txid: new Uint8Array(32).fill(salt), index: 1, finalScriptSig: new Uint8Array(), sequence: 0xfffffffd }],
    outputs: [{ amount, script }],
    witnesses: [],
    lockTime: 0,
  });
}

const txidOf = (raw: Uint8Array) => btc.Transaction.fromRaw(raw, opts).id;

/** Check every partial signature against @scure/btc-signer's BIP-143 digest. */
function verifySigned(psbt: string, publicKey: string, indices: number[], amounts: bigint[]) {
  const tx = btc.Transaction.fromPSBT(Buffer.from(psbt, "base64"), opts);
  const pub = hex.decode(publicKey);
  const scriptCode = btc.p2pkh(pub).script;
  for (const i of indices) {
    const [[key, sig]] = tx.getInput(i).partialSig!;
    assert.deepEqual(key, pub);
    assert.equal(sig[sig.length - 1], btc.SigHash.ALL);
    const digest = tx.preimageWitnessV0(i, scriptCode, btc.SigHash.ALL, amounts[i]);
    assert.ok(secp256k1.verify(sig.subarray(0, -1), digest, pub, { format: "der", prehash: false, lowS: true }));
  }
}

const challenge = (address: string) =>
  [
    "QSB Vault sign-in",
    "Origin: https://qsb.example.org",
    `Address: ${address}`,
    "Network: bitcoin-mainnet",
    "Nonce: 3f2c1e9a-8b7d-4c6e-9f10-2a3b4c5d6e7f",
    "Expires: 2026-10-19T16:05:00.000Z",
    "This signature authorizes this session only. It does not authorize a Bitcoin transaction.",
  ].join("\n");

for (const path of ["m/84'/0'/0'/0/0", "m/49'/0'/0'/0/0"]) {
  test(`sign-in passes bip322-js strict verification (${path})`, { skip: !API }, async () => {
    const { transport, signer: s } = await signer(path);
    const message = challenge(s.address);
    const [signature, seen] = await Promise.all([s.signMessage(s.address, message), approve(/^Sign message$/)]);
    // The Nano wraps long values across lines.
    assert.ok(seen.join("").includes("https://qsb.example.org"));
    assert.ok(Verifier.verifySignature(s.address, message, signature, true));
    await home();
    await transport.close();
  });
}

test("deposit PSBT", { skip: !API }, async () => {
  const { transport, signer: s } = await signer("m/84'/0'/0'/0/0");
  const script = btc.OutScript.encode(btc.Address(btc.NETWORK).decode(s.address));
  const amounts = [70_000n, 40_000n];
  const tx = new btc.Transaction({ ...opts, version: 2 });
  amounts.forEach((amount, i) => {
    const raw = previous(script, amount, i + 1);
    tx.addInput({
      txid: txidOf(raw),
      index: 0,
      sequence: 0xfffffffe,
      nonWitnessUtxo: raw,
      witnessUtxo: { amount, script },
    });
  });
  tx.addOutput({ amount: 100_000n, script: fixture("vault-seed2.hex") });
  tx.addOutput({ amount: 9_000n, script });
  const psbt = Buffer.from(tx.toPSBT()).toString("base64");

  const [signed, seen] = await Promise.all([s.signPsbt(s.address, psbt, [0, 1]), approve(/^Sign transaction$/)]);
  assert.ok(seen.includes("0.001 BTC"));
  verifySigned(signed, s.publicKey, [0, 1], amounts);
  await home();
  await transport.close();
});

test("withdrawal PSBT spending qsb-app's first mainnet vault", { skip: !API }, async () => {
  const { transport, signer: s } = await signer("m/84'/0'/0'/0/0");
  const script = btc.OutScript.encode(btc.Address(btc.NETWORK).decode(s.address));
  // The real deposit (vault at output 0) and the real withdrawal's QSB scriptSig.
  const deposit = btc.Transaction.fromRaw(fixture("mainnet-deposit.hex"), opts);
  // As qsb-app passes it: the raw transaction, witnesses included.
  const depositRaw = fixture("mainnet-deposit.hex");
  const qsbScriptSig = btc.Transaction.fromRaw(fixture("mainnet-withdrawal.hex"), opts).getInput(1).finalScriptSig!;
  const helperRaw = previous(script, 1_449n, 9);

  const tx = new btc.Transaction({ ...opts, version: 1, lockTime: 950_229_240 });
  // Outputs first: @scure/btc-signer refuses new outputs once an input is finalized.
  tx.addOutputAddress("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", 92_083n, btc.NETWORK);
  tx.addInput({
    txid: txidOf(helperRaw),
    index: 0,
    sequence: 0xfffffffe,
    sighashType: btc.SigHash.ALL,
    nonWitnessUtxo: helperRaw,
    witnessUtxo: { amount: 1_449n, script },
  });
  tx.addInput({ txid: deposit.id, index: 0, sequence: 0x800007a1, finalScriptSig: qsbScriptSig, nonWitnessUtxo: depositRaw });
  const psbt = Buffer.from(tx.toPSBT()).toString("base64");

  const [signed, seen] = await Promise.all([s.signPsbt(s.address, psbt, [0]), approve(/^Sign transaction$/)]);
  // Values wrap across pages; keep only lines of lowercase letters and digits
  // (hex fingerprints, bech32 addresses), dropping titles such as "From vault (2/2)".
  const shown = seen.filter((l) => /^[0-9a-z]+$/.test(l)).join("");
  assert.ok(shown.includes("5f7a0bc1bf0fa932d95ad2dd9b60104dbbebb1f7b42ee5f1f2d58c344525290e"), "the mainnet vault fingerprint");
  assert.ok(shown.includes("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), "the destination");
  verifySigned(signed, s.publicKey, [0], [1_449n, 100_000n]);
  await home();
  await transport.close();
});
