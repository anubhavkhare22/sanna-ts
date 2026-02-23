/**
 * Sanna Protocol — Identity Claims
 *
 * Signed assertions about agents, operators, and organizations.
 * Claims are Ed25519-signed and can be registered in a verifiable registry.
 */

import { randomUUID } from "node:crypto";
import type { KeyObject } from "node:crypto";

import { canonicalize } from "./hashing.js";
import { sign, verify, getKeyId } from "./crypto.js";
import type {
  IdentityClaim,
  IdentityClaimType,
  ClaimVerificationResult,
} from "./types.js";

// ── Claim creation ──────────────────────────────────────────────────

export interface CreateClaimOptions {
  expires_in_hours?: number;
}

/**
 * Build the canonical signable data for an identity claim.
 * Excludes the signature field itself.
 */
function buildClaimSignableData(claim: Omit<IdentityClaim, "signature">): Buffer {
  const signable = canonicalize({
    id: claim.id,
    claim_type: claim.claim_type,
    subject_key_id: claim.subject_key_id,
    claims: claim.claims,
    issued_at: claim.issued_at,
    expires_at: claim.expires_at,
    signer_key_id: claim.signer_key_id,
  });
  return Buffer.from(signable, "utf-8");
}

/**
 * Create and sign an identity claim.
 *
 * @param type Type of claim (agent_identity, operator_identity, organization)
 * @param subjectKeyId Key ID of the subject being claimed about
 * @param claims Key-value pairs of claim data (e.g., { name: "...", email: "..." })
 * @param signingKey Ed25519 private key to sign the claim
 * @param options Expiry configuration
 */
export function createIdentityClaim(
  type: IdentityClaimType,
  subjectKeyId: string,
  claims: Record<string, string>,
  signingKey: KeyObject,
  options: CreateClaimOptions = {},
): IdentityClaim {
  const expiresInHours = options.expires_in_hours ?? 8760; // 1 year
  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiresInHours * 3600_000);
  const signerKeyId = getKeyId(signingKey);

  const claimBase: Omit<IdentityClaim, "signature"> = {
    id: randomUUID(),
    claim_type: type,
    subject_key_id: subjectKeyId,
    claims,
    issued_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    signer_key_id: signerKeyId,
  };

  const data = buildClaimSignableData(claimBase);
  const signature = sign(data, signingKey);

  return { ...claimBase, signature };
}

// ── Claim verification ──────────────────────────────────────────────

/**
 * Verify an identity claim's signature and expiry.
 *
 * @param claim The identity claim to verify
 * @param publicKey Ed25519 public key of the signer
 */
export function verifyIdentityClaim(
  claim: IdentityClaim,
  publicKey: KeyObject,
): ClaimVerificationResult {
  const expired = new Date(claim.expires_at).getTime() < Date.now();

  // Verify key_id matches
  const expectedKeyId = getKeyId(publicKey);
  if (claim.signer_key_id !== expectedKeyId) {
    return {
      valid: false,
      expired,
      signature_valid: false,
      claim_type: claim.claim_type,
      subject_key_id: claim.subject_key_id,
    };
  }

  let signatureValid = false;
  try {
    const data = buildClaimSignableData(claim);
    signatureValid = verify(data, claim.signature, publicKey);
  } catch {
    signatureValid = false;
  }

  return {
    valid: signatureValid && !expired,
    expired,
    signature_valid: signatureValid,
    claim_type: claim.claim_type,
    subject_key_id: claim.subject_key_id,
  };
}

// ── Identity Registry ───────────────────────────────────────────────

/**
 * A registry of verified identity claims.
 * Claims must pass signature verification to be registered.
 */
export class IdentityRegistry {
  private _claims = new Map<string, IdentityClaim>();
  private _byKeyId = new Map<string, Set<string>>();
  private _byType = new Map<IdentityClaimType, Set<string>>();
  private _revoked = new Set<string>();

  /**
   * Verify and register a claim.
   * Returns true if the claim was valid and registered.
   */
  register(claim: IdentityClaim, publicKey: KeyObject): boolean {
    const result = verifyIdentityClaim(claim, publicKey);
    if (!result.signature_valid || result.expired) return false;

    this._claims.set(claim.id, structuredClone(claim));

    // Index by subject key
    if (!this._byKeyId.has(claim.subject_key_id)) {
      this._byKeyId.set(claim.subject_key_id, new Set());
    }
    this._byKeyId.get(claim.subject_key_id)!.add(claim.id);

    // Index by type
    if (!this._byType.has(claim.claim_type)) {
      this._byType.set(claim.claim_type, new Set());
    }
    this._byType.get(claim.claim_type)!.add(claim.id);

    return true;
  }

  /**
   * Look up all claims for a given key ID.
   */
  lookup(keyId: string): IdentityClaim[] {
    const ids = this._byKeyId.get(keyId);
    if (!ids) return [];
    return [...ids]
      .map((id) => this._claims.get(id))
      .filter((c): c is IdentityClaim => c !== undefined)
      .map((c) => structuredClone(c));
  }

  /**
   * Look up all claims of a given type.
   */
  lookupByType(type: IdentityClaimType): IdentityClaim[] {
    const ids = this._byType.get(type);
    if (!ids) return [];
    return [...ids]
      .map((id) => this._claims.get(id))
      .filter((c): c is IdentityClaim => c !== undefined)
      .map((c) => structuredClone(c));
  }

  /**
   * Revoke a claim by ID.
   */
  revoke(claimId: string): boolean {
    if (!this._claims.has(claimId)) return false;
    this._revoked.add(claimId);
    const claim = this._claims.get(claimId)!;
    claim.revoked = true;
    return true;
  }

  /**
   * Check if a claim is revoked.
   */
  isRevoked(claimId: string): boolean {
    return this._revoked.has(claimId);
  }

  /**
   * Get a single claim by ID.
   */
  get(claimId: string): IdentityClaim | undefined {
    const claim = this._claims.get(claimId);
    return claim ? structuredClone(claim) : undefined;
  }

  /**
   * Get the count of registered claims.
   */
  get size(): number {
    return this._claims.size;
  }
}
