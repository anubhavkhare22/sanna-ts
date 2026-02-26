import { Command } from "commander";
import { readFileSync } from "node:fs";
import { verifyReceipt, loadPublicKey } from "@sanna-ai/core";

export async function runVerify(
  file: string,
  options: { publicKey?: string },
): Promise<void> {
  let receipt: Record<string, unknown>;
  try {
    receipt = JSON.parse(readFileSync(file, "utf-8")) as Record<string, unknown>;
  } catch (e) {
    console.error(`Error: Invalid JSON in receipt: ${e}`);
    process.exitCode = 1;
    return;
  }

  const publicKey = options.publicKey ? loadPublicKey(options.publicKey) : undefined;
  const result = verifyReceipt(receipt, publicKey);

  console.log("=".repeat(50));
  console.log("SANNA RECEIPT VERIFICATION");
  console.log("=".repeat(50));
  console.log();
  console.log(`  Status:      ${result.valid ? "VALID" : "INVALID"}`);
  console.log(`  Checks run:  ${result.checks_performed.join(", ")}`);
  console.log();

  if (result.errors.length > 0) {
    console.log("Errors:");
    for (const err of result.errors) {
      console.log(`  [FAIL] ${err}`);
    }
    console.log();
  }

  if (result.warnings.length > 0) {
    console.log("Warnings:");
    for (const warn of result.warnings) {
      console.log(`  [WARN] ${warn}`);
    }
    console.log();
  }

  // Pretty-print checks
  const checks = (receipt.checks ?? []) as Record<string, unknown>[];
  if (checks.length > 0) {
    console.log("-".repeat(50));
    console.log("CHECKS");
    console.log("-".repeat(50));
    for (const check of checks) {
      const icon = check.passed ? "PASS" : "FAIL";
      console.log(`  [${icon}] ${check.check_id}: ${check.name ?? ""}`);
      if (!check.passed && check.evidence) {
        console.log(`         evidence: ${check.evidence}`);
      }
    }
    console.log();
  }

  console.log("=".repeat(50));

  if (!result.valid) {
    process.exitCode = 1;
  }
}

export const verifyCommand = new Command("verify")
  .description("Verify a receipt")
  .argument("<file>", "Path to receipt JSON file")
  .option("--public-key <path>", "Path to Ed25519 public key for signature verification")
  .action(async (file, opts) => {
    await runVerify(file, opts);
  });
