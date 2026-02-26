import { Command } from "commander";
import { mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { resolve } from "node:path";
import { homedir } from "node:os";
import {
  generateKeypair,
  exportPrivateKeyPem,
  exportPublicKeyPem,
} from "@sanna-ai/core";

export async function runKeygen(options: {
  outputDir?: string;
  label?: string;
}): Promise<void> {
  const outputDir = options.outputDir ?? resolve(homedir(), ".sanna", "keys");
  mkdirSync(outputDir, { recursive: true, mode: 0o700 });

  const keypair = generateKeypair(options.label);
  const keyId = keypair.keyId;

  const privatePath = resolve(outputDir, `${keyId}.key`);
  const publicPath = resolve(outputDir, `${keyId}.pub`);
  const metaPath = resolve(outputDir, `${keyId}.meta.json`);

  writeFileSync(privatePath, exportPrivateKeyPem(keypair.privateKey), "utf-8");
  try { chmodSync(privatePath, 0o600); } catch { /* Windows */ }

  writeFileSync(publicPath, exportPublicKeyPem(keypair.publicKey), "utf-8");

  const meta = {
    key_id: keyId,
    label: options.label ?? null,
    created_at: new Date().toISOString(),
    scheme: "ed25519",
  };
  writeFileSync(metaPath, JSON.stringify(meta, null, 2), "utf-8");

  const shortId = keyId.slice(0, 16);
  if (options.label) {
    console.log(`Generated Ed25519 keypair '${options.label}' (${shortId}...)`);
  } else {
    console.log(`Generated Ed25519 keypair (${shortId}...)`);
  }
  console.log(`  Private key: ${privatePath}`);
  console.log(`  Public key:  ${publicPath}`);
  console.log(`  Metadata:    ${metaPath}`);
  console.log();
  console.log("Usage:");
  console.log(`  sanna sign constitution.yaml --private-key ${privatePath}`);
  console.log(`  sanna verify-constitution constitution.yaml --public-key ${publicPath}`);
  console.log();
  console.log("IMPORTANT: Keep the private key secure. Share only the public key.");
}

export const keygenCommand = new Command("keygen")
  .description("Generate Ed25519 keypair for signing")
  .option("-o, --output-dir <dir>", "Directory for key files (default: ~/.sanna/keys)")
  .option("--label <label>", "Human-friendly label for the keypair")
  .action(async (opts) => {
    await runKeygen({
      outputDir: opts.outputDir,
      label: opts.label,
    });
  });
