// Regenerates src/template.ts from pqb-core/src/template.bin.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const bin = readFileSync(new URL("../../../pqb-core/src/template.bin", import.meta.url));
if (bin.length !== 4696) throw new Error(`template.bin is ${bin.length} bytes, expected 4696`);
const b64 = bin.toString("base64");
const lines = b64.match(/.{1,100}/g);
const body = lines.map((l, i) => `  "${l}"${i < lines.length - 1 ? " +" : ";"}`).join("\n");
writeFileSync(
  new URL("../src/template.ts", import.meta.url),
  `// Generated from pqb-core/src/template.bin; do not edit by hand.
// Regenerate: npm run gen:template
/** The PQB-v1 locking script with its 154 commitments zeroed (4,908 bytes), base64. */
export const TEMPLATE_BASE64 =
${body}
/** SHA-256 of the template, checked when it is decoded. */
export const TEMPLATE_SHA256 = "${createHash("sha256").update(bin).digest("hex")}";
`,
);
