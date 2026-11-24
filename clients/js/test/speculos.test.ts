/**
 * End-to-end tests of PqbApp against the app running in Speculos, with
 * Speculos's default seed (test/reference.ts, SPECULOS_MNEMONIC). Skipped unless
 * SPECULOS_API is set, e.g. SPECULOS_API=http://127.0.0.1:5000.
 *
 * Mostly commands that need no button press. ALLOCATE is approved here by
 * pressing buttons through the Speculos REST API (Nano only), to read records
 * back from a real device; the other review flows (SIGN_DEPOSIT, WITHDRAW,
 * MENU_POINTS authorization) are exercised by the Ragger tests.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as speculosModule from "@ledgerhq/hw-transport-node-speculos-http";
import { PqbApp, PqbStatusError, commitmentRoot, scriptHash, vaultScript, type ApduTransport } from "../src/index.js";
import * as ref from "./reference.js";

const API = process.env.SPECULOS_API;
// The package is CommonJS: its class is the default export's `default`.
const SpeculosHttpTransport = ((speculosModule as unknown as { default: { default?: unknown } }).default.default ??
  (speculosModule as unknown as { default: unknown }).default) as {
  open(opts: { baseURL?: string; apiPort?: string }): Promise<ApduTransport & { close(): Promise<void> }>;
};
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const WALLET_ID = "76d84aced6d909d41da0557e378886f3";
const VAULT0_ROOT = "d2cab469997de4f1640caacdb783c9249de3d6bcc05ee449c2a8251ad1ca1229";

async function open() {
  // The transport appends `:apiPort` to `baseURL` itself.
  const url = new URL(API!);
  const transport = await SpeculosHttpTransport.open({ baseURL: `${url.protocol}//${url.hostname}`, apiPort: url.port || "5000" });
  return { transport, app: new PqbApp(transport) };
}

test("the host reference agrees with the expected Speculos values", () => {
  assert.equal(hex(ref.walletId()), WALLET_ID);
  assert.equal(hex(commitmentRoot(ref.commitments(ref.deviceSeed(0)))), VAULT0_ROOT);
});

test("version, name and state", { skip: !API }, async () => {
  const { transport, app } = await open();
  const { version, profile } = await app.getVersion();
  assert.match(version, /^\d+\.\d+\.\d+$/);
  assert.equal(profile, "PQB-v1");
  assert.equal(await app.getAppName(), "PQB");
  const state = await app.getState();
  assert.equal(hex(state.walletId), WALLET_ID);
  assert.ok([0, 1, 2].includes(state.namespace));
  assert.ok(state.records <= state.capacity);
  await transport.close();
});

for (const v of [0, 1]) {
  test(`vault ${v}: root, commitments and script match the host derivation`, { skip: !API }, async () => {
    const { transport, app } = await open();
    const expected = ref.commitments(ref.deviceSeed(v));
    const vault = await app.getVault(v);
    assert.equal(hex(vault.root), hex(commitmentRoot(expected)));
    if (v === 0) assert.equal(hex(vault.root), VAULT0_ROOT);

    const commitments = await app.getCommitments(v);
    assert.deepEqual(commitments.map(hex), expected.map(hex));
    assert.deepEqual(commitmentRoot(commitments), vault.root);

    const script = await app.getScript(v);
    assert.deepEqual(scriptHash(script), vault.scriptHash);
    assert.deepEqual(script, vaultScript(commitments));
    await transport.close();
  });
}

test("deposit key, silently", { skip: !API }, async () => {
  const { transport, app } = await open();
  const { publicKey, address } = await app.getDepositAddress(0);
  assert.equal(hex(publicKey), hex(ref.depositKey(ref.deviceSeed(0)).publicKey));
  assert.match(address, /^bc1q[02-9ac-hj-np-z]{38}$/);
  await transport.close();
});

test("secrets and menu points need an approval", { skip: !API }, async () => {
  const { transport, app } = await open();
  await assert.rejects(app.exchange(0x41, 0), (e) => e instanceof PqbStatusError && e.status === "NO_DISCLOSURE");
  await assert.rejects(app.getMenuPoints(0, 1, 0), (e) => e instanceof PqbStatusError && e.status === "MENU_POINTS_UNAUTHORIZED");
  await assert.rejects(app.getMenuR(0, 0), (e) => e instanceof PqbStatusError && e.status === "MENU_POINTS_UNAUTHORIZED");
  await assert.rejects(app.exchange(0x10, 0, Uint8Array.of(0, 0, 0, 0, 150, 5)), (e) => e instanceof PqbStatusError && e.status === "INVALID_DATA");
  await transport.close();
});

// ---- Driving the Nano screens over the Speculos REST API ---------------------

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The text lines on the current screen. */
async function screen(): Promise<string[]> {
  const r = await fetch(`${API}/events?currentscreenonly=true`);
  const { events } = (await r.json()) as { events: { text: string }[] };
  return events.map((e) => e.text);
}

/** Press a button, then wait (up to 2 s) for the screen to redraw so the next read sees the new page. */
async function press(button: "left" | "right" | "both") {
  const before = JSON.stringify(await screen());
  await fetch(`${API}/button/${button}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ action: "press-and-release" }),
  });
  for (let i = 0; i < 20 && JSON.stringify(await screen()) === before; i++) await sleep(100);
}

/** Wait until a line on screen matches one of `wants`; returns the screen. */
async function waitFor(wants: RegExp[], timeoutMs = 10_000): Promise<string[]> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const lines = await screen();
    if (lines.some((l) => wants.some((w) => w.test(l)))) return lines;
    if (Date.now() > end) throw new Error(`Waited for ${wants.join(" or ")}; screen shows ${JSON.stringify(lines)}.`);
    await sleep(100);
  }
}

/** Page right until a line matches `target`, then press both buttons. */
async function select(target: RegExp, maxPages = 20) {
  for (let i = 0; i < maxPages; i++) {
    if ((await screen()).some((l) => target.test(l))) return press("both");
    await press("right");
  }
  throw new Error(`${target} never showed; screen shows ${JSON.stringify(await screen())}.`);
}

/** Approve ALLOCATE as the Ragger flow does: the first-use choice on a fresh device, then the "Create PQB" review. */
async function approveAllocate() {
  // A fresh seed first asks "First PQB vault on this seed?", with the answers on the next pages.
  const first = await waitFor([/First PQB vault/, /Create PQB/]);
  if (first.some((l) => /First PQB vault/.test(l))) {
    await select(/^Yes, first use$/);
    await waitFor([/Create PQB/]);
  }
  await select(/^Create$/);
}

test("allocate, then read the record back with getRecords", { skip: !API, timeout: 60_000 }, async () => {
  const { transport, app } = await open();
  const before = await app.getState();
  // If the screens are not as expected, close the transport so the pending APDU does not hold the run open.
  const [allocated] = await Promise.all([app.allocate(), approveAllocate().catch(async (e) => (await transport.close(), Promise.reject(e)))]);
  const after = await app.getState();
  assert.equal(after.records, before.records + 1);
  assert.equal(after.nextV, allocated.v + 1);

  const vault = await app.getVault(allocated.v);
  assert.deepEqual(allocated.root, vault.root);
  assert.deepEqual(allocated.scriptHash, vault.scriptHash);

  const records = await app.getRecords();
  assert.equal(records.length, after.records);
  const record = records.find((r) => r.v === allocated.v);
  assert.ok(record, `no record for vault ${allocated.v}`);
  assert.equal(hex(record.walletId), WALLET_ID);
  assert.equal(record.state, "allocated");
  assert.equal(record.flags, 0);
  assert.deepEqual(record.root, vault.root);
  assert.deepEqual(record.scriptHash, vault.scriptHash);
  assert.equal(record.funding, null);
  assert.equal(record.disclosure, null);
  await transport.close();
});
