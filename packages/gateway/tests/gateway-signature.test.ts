import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import yaml from "js-yaml";
import {
  generateKeypair,
  exportPrivateKeyPem,
  exportPublicKeyPem,
  signConstitution,
  loadConstitution,
  saveConstitution,
} from "@sanna/core";

import { SannaGateway } from "../src/gateway.js";
import type { GatewayConfig } from "../src/config.js";

const ECHO_SERVER = resolve(
  import.meta.dirname,
  "fixtures/echo-server.ts",
);

let tmpDir: string;
let gateway: SannaGateway | null = null;

function makeConstitutionYaml(): string {
  return yaml.dump({
    schema_version: "1.0",
    identity: {
      agent_name: "test-agent",
      domain: "testing",
      description: "Test agent for signature tests",
      extensions: {},
    },
    provenance: {
      authored_by: "test",
      approved_by: ["test-approver"],
      approval_date: "2025-01-01",
      approval_method: "manual",
      change_history: [],
      signature: null,
    },
    boundaries: [
      {
        id: "B001",
        description: "Allow all actions for testing",
        category: "scope",
        severity: "medium",
      },
    ],
    trust_tiers: {
      autonomous: [],
      requires_approval: [],
      prohibited: [],
    },
    halt_conditions: [],
    invariants: [],
    authority_boundaries: null,
    trusted_sources: null,
  });
}

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sanna-gw-sig-test-"));
});

afterEach(async () => {
  if (gateway) {
    await gateway.stop();
    gateway = null;
  }
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("Gateway constitution signature verification", () => {
  it("enforced mode throws on unsigned constitution", async () => {
    const constitutionPath = join(tmpDir, "constitution.yaml");
    writeFileSync(constitutionPath, makeConstitutionYaml());

    const { privateKey, publicKey } = generateKeypair();
    const pubKeyPath = join(tmpDir, "public.pem");
    writeFileSync(pubKeyPath, exportPublicKeyPem(publicKey));

    const config: GatewayConfig = {
      listen: { transport: "stdio" },
      constitution: {
        path: constitutionPath,
        public_key_path: pubKeyPath,
      },
      enforcement: {
        mode: "enforced",
        default_policy: "allow",
      },
      downstreams: [
        {
          name: "echo",
          command: "npx",
          args: ["tsx", ECHO_SERVER],
        },
      ],
    };

    gateway = new SannaGateway(config);
    await expect(gateway.start()).rejects.toThrow(
      "signature verification failed",
    );
    gateway = null; // start failed, nothing to stop
  }, 30_000);

  it("enforced mode throws on tampered constitution", async () => {
    const constitutionPath = join(tmpDir, "constitution.yaml");

    // Generate keypair and write keys to disk
    const { privateKey, publicKey } = generateKeypair();
    const privKeyPath = join(tmpDir, "private.pem");
    const pubKeyPath = join(tmpDir, "public.pem");
    writeFileSync(privKeyPath, exportPrivateKeyPem(privateKey));
    writeFileSync(pubKeyPath, exportPublicKeyPem(publicKey));

    // Create and sign a valid constitution
    writeFileSync(constitutionPath, makeConstitutionYaml());
    const constitution = loadConstitution(constitutionPath);
    const signed = signConstitution(constitution, privateKey, "test-signer");
    saveConstitution(signed, constitutionPath);

    // Tamper with the constitution after signing
    const rawYaml = readFileSync(constitutionPath, "utf-8");
    const tampered = rawYaml.replace("test-agent", "tampered-agent");
    writeFileSync(constitutionPath, tampered);

    const config: GatewayConfig = {
      listen: { transport: "stdio" },
      constitution: {
        path: constitutionPath,
        public_key_path: pubKeyPath,
      },
      enforcement: {
        mode: "enforced",
        default_policy: "allow",
      },
      downstreams: [
        {
          name: "echo",
          command: "npx",
          args: ["tsx", ECHO_SERVER],
        },
      ],
    };

    gateway = new SannaGateway(config);
    await expect(gateway.start()).rejects.toThrow(
      "signature verification failed",
    );
    gateway = null; // start failed, nothing to stop
  }, 30_000);

  it("enforced mode with valid signature starts successfully", async () => {
    const constitutionPath = join(tmpDir, "constitution.yaml");

    // Generate keypair and write keys to disk
    const { privateKey, publicKey } = generateKeypair();
    const pubKeyPath = join(tmpDir, "public.pem");
    writeFileSync(pubKeyPath, exportPublicKeyPem(publicKey));

    // Create and sign a valid constitution
    writeFileSync(constitutionPath, makeConstitutionYaml());
    const constitution = loadConstitution(constitutionPath);
    const signed = signConstitution(constitution, privateKey, "test-signer");
    saveConstitution(signed, constitutionPath);

    const config: GatewayConfig = {
      listen: { transport: "stdio" },
      constitution: {
        path: constitutionPath,
        public_key_path: pubKeyPath,
      },
      enforcement: {
        mode: "enforced",
        default_policy: "allow",
      },
      downstreams: [
        {
          name: "echo",
          command: "npx",
          args: ["tsx", ECHO_SERVER],
        },
      ],
    };

    gateway = new SannaGateway(config);
    await expect(gateway.start()).resolves.not.toThrow();
  }, 30_000);

  it("permissive mode with invalid signature logs warning but starts", async () => {
    const constitutionPath = join(tmpDir, "constitution.yaml");
    writeFileSync(constitutionPath, makeConstitutionYaml());

    const { privateKey, publicKey } = generateKeypair();
    const pubKeyPath = join(tmpDir, "public.pem");
    writeFileSync(pubKeyPath, exportPublicKeyPem(publicKey));

    const config: GatewayConfig = {
      listen: { transport: "stdio" },
      constitution: {
        path: constitutionPath,
        public_key_path: pubKeyPath,
      },
      enforcement: {
        mode: "permissive",
        default_policy: "allow",
      },
      downstreams: [
        {
          name: "echo",
          command: "npx",
          args: ["tsx", ECHO_SERVER],
        },
      ],
    };

    // Capture stderr to verify the warning
    const stderrChunks: Buffer[] = [];
    const originalWrite = process.stderr.write;
    process.stderr.write = function (chunk: any, ...args: any[]) {
      stderrChunks.push(Buffer.from(chunk));
      return originalWrite.call(process.stderr, chunk, ...args);
    } as typeof process.stderr.write;

    try {
      gateway = new SannaGateway(config);
      await expect(gateway.start()).resolves.not.toThrow();

      const stderrOutput = Buffer.concat(stderrChunks).toString("utf-8");
      expect(stderrOutput).toContain("WARNING");
    } finally {
      process.stderr.write = originalWrite;
    }
  }, 30_000);
});
