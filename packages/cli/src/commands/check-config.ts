import { Command } from "commander";
import { readFileSync, existsSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import yaml from "js-yaml";

export async function runCheckConfig(file: string): Promise<void> {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!existsSync(file)) {
    console.error(`Error: Config file not found: ${file}`);
    process.exitCode = 1;
    return;
  }

  // 1. YAML syntax
  let data: Record<string, unknown>;
  try {
    data = yaml.load(readFileSync(file, "utf-8")) as Record<string, unknown>;
  } catch (e) {
    console.error(`Error: Invalid YAML syntax: ${e}`);
    process.exitCode = 1;
    return;
  }

  if (!data || typeof data !== "object") {
    console.error("Error: Config must be a YAML mapping.");
    process.exitCode = 1;
    return;
  }

  console.log(`Config: ${file}`);
  console.log();
  console.log("  [PASS] YAML syntax valid");

  // 2. Required fields
  const gw = (data.gateway ?? {}) as Record<string, unknown>;
  if (!data.gateway) {
    errors.push("Missing 'gateway' section");
  } else {
    const constPath = gw.constitution as string | undefined;
    if (!constPath) {
      errors.push("Missing gateway.constitution");
    } else {
      // 3. Constitution file exists
      let resolvedConst = resolve(constPath);
      if (!resolve(constPath).startsWith("/")) {
        resolvedConst = resolve(dirname(file), constPath);
      }
      if (existsSync(resolvedConst)) {
        console.log(`  [PASS] Constitution file exists: ${resolvedConst}`);
        try {
          const { loadConstitution } = await import("@sanna-ai/core");
          const c = loadConstitution(resolvedConst);
          if (c.policy_hash) {
            const sig = c.provenance.signature;
            if (sig && sig.value) {
              console.log(`  [PASS] Constitution is signed (key_id=${sig.key_id})`);
            } else {
              warnings.push("Constitution is hashed but NOT Ed25519 signed");
            }
          } else {
            warnings.push("Constitution has no policy_hash (unsigned)");
          }
        } catch (e) {
          errors.push(`Constitution load error: ${e}`);
        }
      } else {
        errors.push(`Constitution file not found: ${resolvedConst}`);
      }
    }

    // 4. Signing key
    const keyPath = gw.signing_key as string | undefined;
    if (keyPath) {
      let resolvedKey = resolve(keyPath);
      if (!resolve(keyPath).startsWith("/")) {
        resolvedKey = resolve(dirname(file), keyPath);
      }
      if (existsSync(resolvedKey)) {
        console.log(`  [PASS] Signing key exists: ${resolvedKey}`);
        try {
          const mode = statSync(resolvedKey).mode & 0o777;
          if (mode === 0o600) {
            console.log("  [PASS] Key permissions: 0o600");
          } else {
            warnings.push(`Key permissions are ${mode.toString(8).padStart(4, "0")}, expected 0o600`);
          }
        } catch {
          // Windows
        }
      } else {
        errors.push(`Signing key not found: ${resolvedKey}`);
      }
    } else {
      warnings.push("No signing_key configured (receipts will be unsigned)");
    }
  }

  // 5. Downstream servers
  const downstreams = (data.downstream ?? []) as Record<string, unknown>[];
  if (!Array.isArray(data.downstream) || downstreams.length === 0) {
    errors.push("No 'downstream' servers configured");
  } else {
    for (let i = 0; i < downstreams.length; i++) {
      const ds = downstreams[i];
      const name = ds.name ?? `server-${i}`;
      const cmd = ds.command;
      if (!cmd) {
        errors.push(`Downstream '${name}' has no command`);
      } else {
        console.log(`  [PASS] Downstream '${name}': ${cmd}`);
      }
    }
  }

  // Summary
  console.log();
  if (warnings.length > 0) {
    console.log("Warnings:");
    for (const w of warnings) {
      console.log(`  [WARN] ${w}`);
    }
  }

  if (errors.length > 0) {
    console.log("Errors:");
    for (const e of errors) {
      console.log(`  [FAIL] ${e}`);
    }
    console.log();
    console.log(`Result: INVALID (${errors.length} errors)`);
    process.exitCode = 1;
    return;
  }

  console.log("Result: VALID");
}

export const checkConfigCommand = new Command("check-config")
  .description("Validate gateway config (dry-run)")
  .argument("<file>", "Path to gateway YAML config file")
  .action(async (file) => {
    await runCheckConfig(file);
  });
