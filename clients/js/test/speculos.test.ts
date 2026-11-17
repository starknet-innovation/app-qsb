/**
 * End-to-end tests of PqbApp against the app running in Speculos, with
 * Speculos's default seed (test/reference.ts, SPECULOS_MNEMONIC). Skipped unless
 * SPECULOS_API is set, e.g. SPECULOS_API=http://127.0.0.1:5000.
 *
 * Only commands that need no button press are covered here; flows with a
 * review screen (ALLOCATE, SIGN_DEPOSIT, WITHDRAW, MENU_POINTS authorization)
 * are exercised by the Ragger tests, which drive the screens.
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
