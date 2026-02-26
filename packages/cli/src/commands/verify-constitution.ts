import { Command } from "commander";
import {
  loadConstitution,
  verifyConstitutionSignature,
  computeFileContentHash,
  loadPublicKey,
} from "@sanna-ai/core";

export async function runVerifyConstitution(
  file: string,
  options: { publicKey: string },
): Promise<void> {
  let constitution;
  try {
    constitution = loadConstitution(file);
  } catch (e) {
    console.error(`Error: ${e}`);
    process.exitCode = 1;
    return;
  }

  if (!constitution.policy_hash) {
    console.error("FAILED: Constitution is not signed (no policy_hash).");
    process.exitCode = 1;
    return;
  }

  // Verify content hash
  const contentHash = computeFileContentHash(file);
  console.log(`Content hash: ${contentHash.slice(0, 16)}...`);

  // Verify Ed25519 signature
  const publicKey = loadPublicKey(options.publicKey);
  const sig = constitution.provenance.signature;
  if (!sig || !sig.value) {
    console.error("FAILED: Constitution has no Ed25519 signature.");
    process.exitCode = 1;
    return;
  }

  const valid = verifyConstitutionSignature(constitution, publicKey);
  if (!valid) {
    console.error("Signature: FAILED — signature does not match public key.");
    process.exitCode = 1;
    return;
  }

  console.log(`Hash:      VALID (${constitution.policy_hash.slice(0, 16)}...)`);
  console.log(`Signature: VALID (key_id=${sig.key_id}, scheme=${sig.scheme})`);
  console.log(`Agent:     ${constitution.identity.agent_name}`);
  console.log(`Status:    VERIFIED`);
}

export const verifyConstitutionCommand = new Command("verify-constitution")
  .description("Verify a constitution's integrity and signature")
  .argument("<file>", "Path to constitution YAML file")
  .requiredOption("--public-key <path>", "Path to Ed25519 public key")
  .action(async (file, opts) => {
    await runVerifyConstitution(file, opts);
  });
