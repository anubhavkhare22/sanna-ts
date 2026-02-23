import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { resolve } from "node:path";
import { DownstreamConnection } from "../src/downstream.js";

const ENV_REPORTER = resolve(
  import.meta.dirname,
  "fixtures/env-reporter.ts",
);

// Track connections for cleanup
const connections: DownstreamConnection[] = [];

// Sentinel values injected into process.env to verify they do NOT leak
const INJECTED_VARS = {
  HMAC_SECRET: "should-not-leak",
  AWS_SECRET_KEY: "should-not-leak",
} as const;

beforeEach(() => {
  for (const [key, value] of Object.entries(INJECTED_VARS)) {
    process.env[key] = value;
  }
});

afterEach(async () => {
  // Clean up injected vars
  for (const key of Object.keys(INJECTED_VARS)) {
    delete process.env[key];
  }
  // Disconnect all connections
  for (const conn of connections) {
    await conn.disconnect();
  }
  connections.length = 0;
});

function createConnection(
  env?: Record<string, string>,
): DownstreamConnection {
  const conn = new DownstreamConnection({
    name: "env-reporter",
    command: "npx",
    args: ["tsx", ENV_REPORTER],
    env,
  });
  connections.push(conn);
  return conn;
}

/** Call report_env and parse the returned JSON. */
async function getChildEnv(
  conn: DownstreamConnection,
): Promise<Record<string, string>> {
  const result = await conn.callTool("report_env", {});
  expect(result.isError).toBeFalsy();
  expect(result.content).toHaveLength(1);
  return JSON.parse(result.content[0].text as string);
}

describe("Downstream environment allowlist", () => {
  it("passes allowlisted runtime vars to child process", async () => {
    const conn = createConnection();
    await conn.connect();
    const childEnv = await getChildEnv(conn);

    // PATH and HOME are allowlisted and virtually always set.
    // Note: npx prepends its own entries to PATH, so the child's PATH
    // will contain (but not exactly equal) the gateway's PATH.
    if (process.env.PATH) {
      expect(childEnv.PATH).toBeDefined();
      expect(childEnv.PATH).toContain(process.env.PATH);
    }
    if (process.env.HOME) {
      expect(childEnv.HOME).toBe(process.env.HOME);
    }
  }, 30_000);

  it("does NOT pass non-allowlisted vars to child process", async () => {
    const conn = createConnection();
    await conn.connect();
    const childEnv = await getChildEnv(conn);

    expect(childEnv).not.toHaveProperty("HMAC_SECRET");
    expect(childEnv).not.toHaveProperty("AWS_SECRET_KEY");
  }, 30_000);

  it("includes explicit env config values in child process", async () => {
    const conn = createConnection({
      CUSTOM_API_KEY: "explicit-value-123",
      MY_SERVICE_URL: "https://example.com",
    });
    await conn.connect();
    const childEnv = await getChildEnv(conn);

    expect(childEnv.CUSTOM_API_KEY).toBe("explicit-value-123");
    expect(childEnv.MY_SERVICE_URL).toBe("https://example.com");
  }, 30_000);

  it("explicit env config overrides allowlisted values", async () => {
    const overriddenHome = "/tmp/overridden-home";
    const conn = createConnection({
      HOME: overriddenHome,
    });
    await conn.connect();
    const childEnv = await getChildEnv(conn);

    expect(childEnv.HOME).toBe(overriddenHome);
  }, 30_000);

  it("child env does not contain arbitrary gateway env vars", async () => {
    // Set additional non-allowlisted vars to further verify filtering
    process.env.DATABASE_URL = "postgres://secret@localhost/db";
    process.env.STRIPE_SECRET = "sk_live_secret";

    try {
      const conn = createConnection();
      await conn.connect();
      const childEnv = await getChildEnv(conn);

      expect(childEnv).not.toHaveProperty("DATABASE_URL");
      expect(childEnv).not.toHaveProperty("STRIPE_SECRET");
      expect(childEnv).not.toHaveProperty("HMAC_SECRET");
      expect(childEnv).not.toHaveProperty("AWS_SECRET_KEY");
    } finally {
      delete process.env.DATABASE_URL;
      delete process.env.STRIPE_SECRET;
    }
  }, 30_000);
});
