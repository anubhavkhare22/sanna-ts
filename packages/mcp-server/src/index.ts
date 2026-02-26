/**
 * Sanna MCP Server — entry point.
 *
 * Reads configuration from:
 *   1. Environment variables (SANNA_CONSTITUTION_PATH, etc.)
 *   2. Config file (sanna-mcp.json or sanna-mcp.yaml in CWD)
 *   3. CLI flags (--constitution-path, etc.)
 *
 * Priority: CLI flags > env vars > config file
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { runServer } from "./server.js";
import type { SannaMCPConfig } from "./server.js";

// ── Config file loading ─────────────────────────────────────────────

async function loadConfigFile(): Promise<Partial<SannaMCPConfig>> {
  const jsonPath = resolve("sanna-mcp.json");
  if (existsSync(jsonPath)) {
    try {
      const raw = readFileSync(jsonPath, "utf-8");
      const data = JSON.parse(raw) as Record<string, unknown>;
      return parseConfigData(data);
    } catch {
      // Silently ignore malformed config
    }
  }

  // Try YAML config (only if js-yaml available through @sanna-ai/core's dep)
  const yamlPath = resolve("sanna-mcp.yaml");
  if (existsSync(yamlPath)) {
    try {
      // Dynamic import to avoid hard dependency
      const yaml = await import("js-yaml");
      const raw = readFileSync(yamlPath, "utf-8");
      const data = yaml.load(raw) as Record<string, unknown>;
      return parseConfigData(data);
    } catch {
      // Silently ignore
    }
  }

  return {};
}

function parseConfigData(data: Record<string, unknown>): Partial<SannaMCPConfig> {
  const config: Partial<SannaMCPConfig> = {};
  if (typeof data.constitution_path === "string") {
    config.constitutionPath = data.constitution_path;
  }
  if (typeof data.db_path === "string") {
    config.dbPath = data.db_path;
  }
  if (typeof data.signing_key_path === "string") {
    config.signingKeyPath = data.signing_key_path;
  }
  if (typeof data.public_key_path === "string") {
    config.publicKeyPath = data.public_key_path;
  }
  return config;
}

// ── CLI arg parsing ─────────────────────────────────────────────────

function parseCliArgs(args: string[]): Partial<SannaMCPConfig> {
  const config: Partial<SannaMCPConfig> = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];
    if (arg === "--constitution-path" && next) {
      config.constitutionPath = next;
      i++;
    } else if (arg === "--db-path" && next) {
      config.dbPath = next;
      i++;
    } else if (arg === "--signing-key-path" && next) {
      config.signingKeyPath = next;
      i++;
    } else if (arg === "--public-key-path" && next) {
      config.publicKeyPath = next;
      i++;
    } else if (arg === "--help" || arg === "-h") {
      console.log(`sanna-mcp-server — Sanna protocol MCP server

Usage: sanna-mcp-server [options]

Options:
  --constitution-path <path>   Default constitution YAML path
  --db-path <path>             SQLite receipts database path
  --signing-key-path <path>    Ed25519 private key for signing
  --public-key-path <path>     Ed25519 public key for verification
  -h, --help                   Show this help

Environment variables:
  SANNA_CONSTITUTION_PATH      Default constitution YAML path
  SANNA_DB_PATH                SQLite receipts database path
  SANNA_SIGNING_KEY_PATH       Ed25519 private key for signing
  SANNA_PUBLIC_KEY_PATH        Ed25519 public key for verification

Config files (read from CWD):
  sanna-mcp.json               JSON config with snake_case keys
  sanna-mcp.yaml               YAML config with snake_case keys

Priority: CLI flags > environment variables > config file`);
      process.exit(0);
    }
  }
  return config;
}

// ── Env var parsing ─────────────────────────────────────────────────

function parseEnvVars(): Partial<SannaMCPConfig> {
  const config: Partial<SannaMCPConfig> = {};
  if (process.env.SANNA_CONSTITUTION_PATH) {
    config.constitutionPath = process.env.SANNA_CONSTITUTION_PATH;
  }
  if (process.env.SANNA_DB_PATH) {
    config.dbPath = process.env.SANNA_DB_PATH;
  }
  if (process.env.SANNA_SIGNING_KEY_PATH) {
    config.signingKeyPath = process.env.SANNA_SIGNING_KEY_PATH;
  }
  if (process.env.SANNA_PUBLIC_KEY_PATH) {
    config.publicKeyPath = process.env.SANNA_PUBLIC_KEY_PATH;
  }
  return config;
}

// ── Main ────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const fileConfig = await loadConfigFile();
  const envConfig = parseEnvVars();
  const cliConfig = parseCliArgs(process.argv.slice(2));

  // Merge: cli > env > file
  const config: SannaMCPConfig = {
    ...fileConfig,
    ...envConfig,
    ...cliConfig,
  };

  await runServer(config);
}

main().catch((err) => {
  console.error("Sanna MCP server fatal error:", err);
  process.exit(1);
});
