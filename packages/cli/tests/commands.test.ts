import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import yaml from "js-yaml";
import {
  generateKeypair,
  exportPrivateKeyPem,
  exportPublicKeyPem,
  signConstitution,
  saveConstitution,
  loadConstitution,
  verifyConstitutionSignature,
  generateReceipt,
  signReceipt,
  verifyReceipt,
} from "@sanna-ai/core";
import type { Constitution, CheckResult } from "@sanna-ai/core";

function makeConstitution(): Constitution {
  return {
    schema_version: "1.0.0",
    identity: {
      agent_name: "cli-test-agent",
      domain: "testing",
      description: "CLI test agent",
      extensions: {},
    },
    provenance: {
      authored_by: "test@sanna.dev",
      approved_by: ["test@sanna.dev"],
      approval_date: "2026-02-22",
      approval_method: "test",
      change_history: [],
      signature: null,
    },
    boundaries: [
      { id: "B001", description: "Test", category: "scope", severity: "medium" },
    ],
    trust_tiers: { autonomous: [], requires_approval: [], prohibited: [] },
    halt_conditions: [],
    invariants: [
      { id: "INV_NO_FABRICATION", rule: "No fabrication", enforcement: "halt", check: null },
    ],
    policy_hash: null,
    authority_boundaries: null,
    trusted_sources: null,
  };
}

describe("CLI Commands (unit tests via imports)", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "sanna-cli-test-"));
  });

  afterEach(() => {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* */ }
  });

  describe("init", () => {
    it("should create a constitution file from a template", async () => {
      const { runInit } = await import("../src/commands/init.js");
      const output = join(tmpDir, "constitution.yaml");
      await runInit({
        output,
        template: "developer",
        agentName: "my-agent",
        domain: "test",
        description: "Test agent",
        nonInteractive: true,
      });

      expect(existsSync(output)).toBe(true);
      const content = readFileSync(output, "utf-8");
      expect(content).toContain("my-agent");
      expect(content).toContain("test");
      expect(content).toContain("sanna_constitution");
    });

    it("should use different templates", async () => {
      const { runInit } = await import("../src/commands/init.js");
      for (const template of ["developer", "privacy-focused", "locked-down", "minimal"]) {
        const output = join(tmpDir, `${template}.yaml`);
        await runInit({ output, template, nonInteractive: true });
        expect(existsSync(output)).toBe(true);
      }
    });

    it("should refuse to overwrite existing file", async () => {
      const { runInit } = await import("../src/commands/init.js");
      const output = join(tmpDir, "existing.yaml");
      writeFileSync(output, "existing content");
      process.exitCode = 0;
      await runInit({ output, template: "minimal", nonInteractive: true });
      expect(process.exitCode).toBe(1);
      process.exitCode = 0;
    });
  });

  describe("keygen", () => {
    it("should generate key files in the specified directory", async () => {
      const { runKeygen } = await import("../src/commands/keygen.js");
      const keyDir = join(tmpDir, "keys");
      await runKeygen({ outputDir: keyDir, label: "test" });

      // Should have created .key, .pub, .meta.json files
      const files = require("node:fs").readdirSync(keyDir) as string[];
      const keyFile = files.find((f: string) => f.endsWith(".key"));
      const pubFile = files.find((f: string) => f.endsWith(".pub"));
      const metaFile = files.find((f: string) => f.endsWith(".meta.json"));

      expect(keyFile).toBeDefined();
      expect(pubFile).toBeDefined();
      expect(metaFile).toBeDefined();

      // Meta should contain key_id and label
      const meta = JSON.parse(readFileSync(join(keyDir, metaFile!), "utf-8"));
      expect(meta.key_id).toBeTruthy();
      expect(meta.label).toBe("test");
      expect(meta.scheme).toBe("ed25519");
    });
  });

  describe("sign + verify-constitution round-trip", () => {
    it("should sign a constitution and verify it", () => {
      const keypair = generateKeypair("test");
      const constitution = makeConstitution();

      // Save unsigned constitution
      const constPath = join(tmpDir, "constitution.yaml");
      saveConstitution(constitution, constPath);

      // Sign it
      const loaded = loadConstitution(constPath);
      const signed = signConstitution(loaded, keypair.privateKey, "test@sanna.dev");
      saveConstitution(signed, constPath);

      // Verify
      const reloaded = loadConstitution(constPath);
      expect(reloaded.policy_hash).toBeTruthy();
      expect(reloaded.provenance.signature).toBeTruthy();
      expect(reloaded.provenance.signature!.value).toBeTruthy();
      expect(verifyConstitutionSignature(reloaded, keypair.publicKey)).toBe(true);
    });
  });

  describe("verify", () => {
    it("should verify a valid receipt", () => {
      const keypair = generateKeypair();
      const checks: CheckResult[] = [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ];
      const receipt = generateReceipt({
        correlation_id: "test-001",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks,
      });
      signReceipt(receipt as unknown as Record<string, unknown>, keypair.privateKey, "test");
      const result = verifyReceipt(receipt as unknown as Record<string, unknown>, keypair.publicKey);
      expect(result.valid).toBe(true);
    });

    it("should detect tampered receipt", () => {
      const keypair = generateKeypair();
      const checks: CheckResult[] = [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ];
      const receipt = generateReceipt({
        correlation_id: "test-001",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks,
      }) as unknown as Record<string, unknown>;
      signReceipt(receipt, keypair.privateKey, "test");

      // Tamper
      (receipt as any).status = "FAIL";
      const result = verifyReceipt(receipt, keypair.publicKey);
      expect(result.valid).toBe(false);
    });
  });

  describe("inspect", () => {
    it("should pretty-print a receipt without errors", async () => {
      const { runInspect } = await import("../src/commands/inspect.js");
      const receipt = generateReceipt({
        correlation_id: "test-001",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      });
      const receiptPath = join(tmpDir, "receipt.json");
      writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

      // Capture console output
      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runInspect(receiptPath, {});
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("SANNA RECEIPT");
      expect(output).toContain("PASS");
      expect(output).toContain("C1");
    });

    it("should output JSON when --json flag is set", async () => {
      const { runInspect } = await import("../src/commands/inspect.js");
      const receipt = generateReceipt({
        correlation_id: "test-001",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      });
      const receiptPath = join(tmpDir, "receipt.json");
      writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runInspect(receiptPath, { json: true });
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      const parsed = JSON.parse(output);
      expect(parsed.receipt_id).toBeTruthy();
    });
  });

  describe("diff", () => {
    it("should detect differences between two files", async () => {
      const { runDiff } = await import("../src/commands/diff.js");
      const fileA = join(tmpDir, "a.yaml");
      const fileB = join(tmpDir, "b.yaml");
      writeFileSync(fileA, "line1\nline2\nline3\n");
      writeFileSync(fileB, "line1\nline2-modified\nline3\n");

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runDiff(fileA, fileB);
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("---");
      expect(output).toContain("+++");
    });

    it("should report identical files", async () => {
      const { runDiff } = await import("../src/commands/diff.js");
      const fileA = join(tmpDir, "same.yaml");
      writeFileSync(fileA, "same content\n");

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runDiff(fileA, fileA);
      } finally {
        console.log = origLog;
      }

      expect(logs.join("\n")).toContain("identical");
    });
  });

  describe("demo", () => {
    it("should run the full demo without errors", async () => {
      const { runDemo } = await import("../src/commands/demo.js");
      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runDemo();
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("Sanna Demo");
      expect(output).toContain("Generated Ed25519 keypair");
      expect(output).toContain("Signed constitution");
      expect(output).toContain("Generated receipt");
      expect(output).toContain("Signed receipt");
      expect(output).toContain("Verified receipt");
      expect(output).toContain("VALID");
    });
  });

  describe("check-config", () => {
    it("should validate a correct gateway config", async () => {
      const { runCheckConfig } = await import("../src/commands/check-config.js");

      // Create a constitution and config that references it
      const keypair = generateKeypair();
      const constitution = signConstitution(makeConstitution(), keypair.privateKey, "test");
      const constPath = join(tmpDir, "constitution.yaml");
      saveConstitution(constitution, constPath);

      const keyPath = join(tmpDir, "signing.key");
      writeFileSync(keyPath, exportPrivateKeyPem(keypair.privateKey));
      try { require("node:fs").chmodSync(keyPath, 0o600); } catch { /* Windows */ }

      const config = {
        gateway: {
          constitution: constPath,
          signing_key: keyPath,
        },
        downstream: [
          { name: "test-server", command: "node server.js" },
        ],
      };
      const configPath = join(tmpDir, "gateway.yaml");
      writeFileSync(configPath, yaml.dump(config));

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runCheckConfig(configPath);
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("YAML syntax valid");
      expect(output).toContain("Result: VALID");
    });

    it("should detect missing config file", async () => {
      const { runCheckConfig } = await import("../src/commands/check-config.js");
      const logs: string[] = [];
      const origErr = console.error;
      console.error = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runCheckConfig(join(tmpDir, "nonexistent.yaml"));
      } finally {
        console.error = origErr;
      }
      expect(process.exitCode).toBe(1);
      process.exitCode = 0;
    });
  });

  describe("drift-report", () => {
    it("should report error for missing DB", async () => {
      const { runDriftReport } = await import("../src/commands/drift-report.js");
      const logs: string[] = [];
      const origErr = console.error;
      console.error = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runDriftReport({ db: join(tmpDir, "nonexistent.db"), window: 30 });
      } finally {
        console.error = origErr;
      }
      expect(process.exitCode).toBe(1);
      expect(logs.join("\n")).toContain("not found");
      process.exitCode = 0;
    });

    it("should generate a drift report from a populated store", async () => {
      const { runDriftReport } = await import("../src/commands/drift-report.js");
      const { ReceiptStore } = await import("@sanna-ai/core");

      process.env.SANNA_ALLOW_TEMP_DB = "1";
      const dbPath = join(tmpDir, "drift.db");
      const store = new ReceiptStore(dbPath);

      // Populate with some receipts
      for (let i = 0; i < 10; i++) {
        store.save({
          receipt_id: `r-${i}`,
          correlation_id: "test",
          timestamp: new Date(Date.now() - i * 86400000).toISOString(),
          status: "PASS",
          checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
          checks_passed: 1,
          checks_failed: 0,
          inputs: { q: "test" },
          outputs: { r: "test" },
          context_hash: "a".repeat(64),
          output_hash: "b".repeat(64),
          constitution_ref: { document_id: "agent-a/1.0", policy_hash: "c".repeat(64) },
        });
      }
      store.close();

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runDriftReport({ db: dbPath, window: 30 });
      } finally {
        console.log = origLog;
        delete process.env.SANNA_ALLOW_TEMP_DB;
      }

      const output = logs.join("\n");
      expect(output).toContain("Fleet Governance Report");
      expect(output).toContain("agent-a");
    });
  });
});
