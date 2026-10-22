import * as btc from "@scure/btc-signer";
import { base64, hex } from "@scure/base";
import { QsbApp, type ApduTransport, type TxKind, type UnsignedTx } from "./app.js";

const opts = { allowUnknownInputs: true, allowUnknownOutputs: true };

/**
 * A Ledger-backed wallet with the shape of the QSB SDK's `Signer`
 * (qsb-app `sdk/signer.ts`): one P2WPKH (BIP-84 path) or P2SH-P2WPKH (BIP-49
 * path) address that signs in, funds the deposit and provides the withdrawal's
 * helper input. Every signature needs the user's approval on the device.
 */
export class LedgerQsbSigner {
  private constructor(
    private readonly app: QsbApp,
    readonly path: string,
    readonly address: string,
    readonly publicKey: string,
  ) {}

  /**
   * Read the wallet at `path`. With `verifyAddress`, the device shows the address
   * and this resolves only once the user confirms it.
   */
  static async connect(
    transport: ApduTransport,
    path = "m/84'/0'/0'/0/0",
    { verifyAddress = false } = {},
  ): Promise<LedgerQsbSigner> {
    const app = new QsbApp(transport);
    const { publicKey, address } = await app.getWalletAddress(path, verifyAddress);
    return new LedgerQsbSigner(app, path, address, hex.encode(publicKey));
  }

  private own(address: string) {
    if (address !== this.address) throw new Error(`The Ledger wallet holds ${this.address}, not ${address}.`);
  }

  /** BIP-322 "simple" signature (base64) of a QSB sign-in challenge. */
  async signMessage(address: string, message: string): Promise<string> {
    this.own(address);
    const signature = await this.app.signIn(this.path, message);
    const pubkey = hex.decode(this.publicKey);
    const witness = new Uint8Array([2, signature.length, ...signature, pubkey.length, ...pubkey]);
    return base64.encode(witness);
  }

  /**
   * Sign `inputs` of a QSB deposit or withdrawal PSBT (base64) and return it with
   * the signatures added as partial signatures. Never broadcasts.
   */
  async signPsbt(address: string, psbt: string, inputs: number[]): Promise<string> {
    this.own(address);
    const tx = btc.Transaction.fromPSBT(base64.decode(psbt), opts);
    const kind = psbtKind(tx, inputs);
    const unsigned: UnsignedTx = {
      version: tx.version,
      lockTime: tx.lockTime,
      inputs: [],
      outputs: [],
    };
    for (let i = 0; i < tx.inputsLength; i++) {
      const input = tx.getInput(i);
      if (inputs.includes(i) && input.sighashType !== undefined && input.sighashType !== btc.SigHash.ALL)
        throw new Error(`Input ${i} asks for a sighash other than SIGHASH_ALL.`);
      if (!input.txid || input.index === undefined || !input.nonWitnessUtxo)
        throw new Error(`Input ${i} lacks its previous transaction (non_witness_utxo).`);
      unsigned.inputs.push({
        txid: hex.encode(input.txid),
        vout: input.index,
        sequence: input.sequence ?? 0xffffffff,
        previousTx: btc.RawTx.encode(input.nonWitnessUtxo),
      });
    }
    for (let i = 0; i < tx.outputsLength; i++) {
      const output = tx.getOutput(i);
      if (output.amount === undefined || !output.script) throw new Error(`Output ${i} is incomplete.`);
      unsigned.outputs.push({ amount: output.amount, script: output.script });
    }
    const signatures = await this.app.signTransaction(kind, this.path, unsigned, inputs);
    const pubkey = hex.decode(this.publicKey);
    for (const [index, signature] of signatures)
      tx.updateInput(index, { partialSig: [[pubkey, signature]] }, true);
    return base64.encode(tx.toPSBT());
  }
}

/**
 * A withdrawal is qsb-app's two-input, one-output transaction whose input 1 is
 * already finalized with the QSB authorization, signing input 0 only. Anything
 * else is treated as a deposit, signing every input. The device checks either
 * claim against the transaction itself.
 */
export function psbtKind(tx: btc.Transaction, inputs: number[]): TxKind {
  const withdrawal =
    tx.inputsLength === 2 && tx.outputsLength === 1 && !!tx.getInput(1).finalScriptSig?.length;
  if (withdrawal) {
    if (inputs.length !== 1 || inputs[0] !== 0) throw new Error("A QSB withdrawal signs input 0 only.");
    return "withdrawal";
  }
  const all = Array.from({ length: tx.inputsLength }, (_, i) => i);
  if (inputs.length !== all.length || !all.every((i) => inputs.includes(i)))
    throw new Error("A QSB deposit signs every input.");
  return "deposit";
}
