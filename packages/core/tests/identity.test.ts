import { describe, it, expect } from "vitest";
import {
  createIdentityClaim,
  verifyIdentityClaim,
  IdentityRegistry,
  generateKeypair,
} from "../src/index.js";

describe("createIdentityClaim", () => {
  it("should create an agent identity claim", () => {
    const kp = generateKeypair();
    const claim = createIdentityClaim(
      "agent_identity",
      kp.keyId,
      { name: "test-agent", version: "1.0" },
      kp.privateKey,
    );
    expect(claim.id).toBeTruthy();
    expect(claim.claim_type).toBe("agent_identity");
    expect(claim.subject_key_id).toBe(kp.keyId);
    expect(claim.claims.name).toBe("test-agent");
    expect(claim.signature).toBeTruthy();
    expect(claim.signer_key_id).toBe(kp.keyId);
  });

  it("should create an operator identity claim", () => {
    const kp = generateKeypair();
    const claim = createIdentityClaim(
      "operator_identity",
      kp.keyId,
      { email: "admin@example.com", role: "admin" },
      kp.privateKey,
    );
    expect(claim.claim_type).toBe("operator_identity");
    expect(claim.claims.email).toBe("admin@example.com");
  });

  it("should create an organization claim", () => {
    const kp = generateKeypair();
    const claim = createIdentityClaim(
      "organization",
      kp.keyId,
      { org: "Sanna Labs", jurisdiction: "US" },
      kp.privateKey,
    );
    expect(claim.claim_type).toBe("organization");
  });

  it("should set default expiry to 1 year", () => {
    const kp = generateKeypair();
    const claim = createIdentityClaim(
      "agent_identity",
      kp.keyId,
      { name: "agent" },
      kp.privateKey,
    );
    const issuedAt = new Date(claim.issued_at).getTime();
    const expiresAt = new Date(claim.expires_at).getTime();
    const diffHours = (expiresAt - issuedAt) / 3600_000;
    expect(diffHours).toBeCloseTo(8760, 0);
  });

  it("should respect custom expiry", () => {
    const kp = generateKeypair();
    const claim = createIdentityClaim(
      "agent_identity",
      kp.keyId,
      { name: "agent" },
      kp.privateKey,
      { expires_in_hours: 48 },
    );
    const issuedAt = new Date(claim.issued_at).getTime();
    const expiresAt = new Date(claim.expires_at).getTime();
    const diffHours = (expiresAt - issuedAt) / 3600_000;
    expect(diffHours).toBeCloseTo(48, 0);
  });

  it("should generate unique IDs", () => {
    const kp = generateKeypair();
    const c1 = createIdentityClaim("agent_identity", kp.keyId, {}, kp.privateKey);
    const c2 = createIdentityClaim("agent_identity", kp.keyId, {}, kp.privateKey);
    expect(c1.id).not.toBe(c2.id);
  });
});

describe("verifyIdentityClaim", () => {
  it("should verify a valid claim", () => {
    const kp = generateKeypair();
    const claim = createIdentityClaim(
      "agent_identity",
      kp.keyId,
      { name: "agent" },
      kp.privateKey,
    );
    const result = verifyIdentityClaim(claim, kp.publicKey);
    expect(result.valid).toBe(true);
    expect(result.expired).toBe(false);
    expect(result.signature_valid).toBe(true);
    expect(result.claim_type).toBe("agent_identity");
    expect(result.subject_key_id).toBe(kp.keyId);
  });

  it("should reject claim signed with different key", () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const claim = createIdentityClaim(
      "agent_identity",
      kp1.keyId,
      { name: "agent" },
      kp1.privateKey,
    );
    const result = verifyIdentityClaim(claim, kp2.publicKey);
    expect(result.valid).toBe(false);
    expect(result.signature_valid).toBe(false);
  });

  it("should detect tampered claims", () => {
    const kp = generateKeypair();
    const claim = createIdentityClaim(
      "agent_identity",
      kp.keyId,
      { name: "agent" },
      kp.privateKey,
    );
    // Tamper with claims
    claim.claims.name = "tampered-agent";
    const result = verifyIdentityClaim(claim, kp.publicKey);
    expect(result.valid).toBe(false);
    expect(result.signature_valid).toBe(false);
  });

  it("should detect expired claims", () => {
    const kp = generateKeypair();
    // Create claim that's already expired (negative hours)
    const claim = createIdentityClaim(
      "agent_identity",
      kp.keyId,
      { name: "agent" },
      kp.privateKey,
      { expires_in_hours: -1 },
    );
    const result = verifyIdentityClaim(claim, kp.publicKey);
    expect(result.expired).toBe(true);
    expect(result.valid).toBe(false);
    // Signature itself should still be valid
    expect(result.signature_valid).toBe(true);
  });
});

describe("IdentityRegistry", () => {
  it("should register and lookup a claim by key ID", () => {
    const registry = new IdentityRegistry();
    const kp = generateKeypair();
    const claim = createIdentityClaim(
      "agent_identity",
      kp.keyId,
      { name: "agent" },
      kp.privateKey,
    );
    expect(registry.register(claim, kp.publicKey)).toBe(true);
    expect(registry.size).toBe(1);

    const claims = registry.lookup(kp.keyId);
    expect(claims).toHaveLength(1);
    expect(claims[0].claims.name).toBe("agent");
  });

  it("should reject invalid claims", () => {
    const registry = new IdentityRegistry();
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const claim = createIdentityClaim(
      "agent_identity",
      kp1.keyId,
      { name: "agent" },
      kp1.privateKey,
    );
    // Try registering with wrong key
    expect(registry.register(claim, kp2.publicKey)).toBe(false);
    expect(registry.size).toBe(0);
  });

  it("should lookup by type", () => {
    const registry = new IdentityRegistry();
    const kp = generateKeypair();
    const agentClaim = createIdentityClaim(
      "agent_identity",
      kp.keyId,
      { name: "agent" },
      kp.privateKey,
    );
    const operatorClaim = createIdentityClaim(
      "operator_identity",
      kp.keyId,
      { email: "op@example.com" },
      kp.privateKey,
    );
    registry.register(agentClaim, kp.publicKey);
    registry.register(operatorClaim, kp.publicKey);

    expect(registry.lookupByType("agent_identity")).toHaveLength(1);
    expect(registry.lookupByType("operator_identity")).toHaveLength(1);
    expect(registry.lookupByType("organization")).toHaveLength(0);
  });

  it("should revoke and check revocation", () => {
    const registry = new IdentityRegistry();
    const kp = generateKeypair();
    const claim = createIdentityClaim(
      "agent_identity",
      kp.keyId,
      { name: "agent" },
      kp.privateKey,
    );
    registry.register(claim, kp.publicKey);

    expect(registry.isRevoked(claim.id)).toBe(false);
    expect(registry.revoke(claim.id)).toBe(true);
    expect(registry.isRevoked(claim.id)).toBe(true);
  });

  it("should return false for revoking unknown claim", () => {
    const registry = new IdentityRegistry();
    expect(registry.revoke("nonexistent")).toBe(false);
  });

  it("should get a single claim by ID", () => {
    const registry = new IdentityRegistry();
    const kp = generateKeypair();
    const claim = createIdentityClaim(
      "agent_identity",
      kp.keyId,
      { name: "agent" },
      kp.privateKey,
    );
    registry.register(claim, kp.publicKey);

    const retrieved = registry.get(claim.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe(claim.id);
  });

  it("should return undefined for unknown claim ID", () => {
    const registry = new IdentityRegistry();
    expect(registry.get("nonexistent")).toBeUndefined();
  });

  it("should return empty array for unknown key ID", () => {
    const registry = new IdentityRegistry();
    expect(registry.lookup("nonexistent")).toHaveLength(0);
  });

  it("should reject expired claims", () => {
    const registry = new IdentityRegistry();
    const kp = generateKeypair();
    const claim = createIdentityClaim(
      "agent_identity",
      kp.keyId,
      { name: "expired-agent" },
      kp.privateKey,
      { expires_in_hours: -1 }, // Already expired
    );
    // Signature is valid but claim is expired — should be rejected
    expect(registry.register(claim, kp.publicKey)).toBe(false);
    expect(registry.size).toBe(0);
  });

  it("should register multiple claims for same key", () => {
    const registry = new IdentityRegistry();
    const kp = generateKeypair();
    const c1 = createIdentityClaim("agent_identity", kp.keyId, { name: "a1" }, kp.privateKey);
    const c2 = createIdentityClaim("agent_identity", kp.keyId, { name: "a2" }, kp.privateKey);
    registry.register(c1, kp.publicKey);
    registry.register(c2, kp.publicKey);
    expect(registry.lookup(kp.keyId)).toHaveLength(2);
  });
});
