/**
 * Sanna Gateway — Receipt v2.0 Triad
 *
 * Enhanced receipt generation with three deterministic hashes:
 * - input_hash:     hash of the incoming request (tool + args)
 * - reasoning_hash: hash of governance reasoning (decision + checks)
 * - action_hash:    hash of the action taken (result + flags)
 */

import { hashObj, hashContent } from "@sanna-ai/core";
import type { AuthorityDecision, CheckResult } from "@sanna-ai/core";

// ── Types ────────────────────────────────────────────────────────────

export interface ReceiptTriad {
  input_hash: string;
  reasoning_hash: string;
  action_hash: string;
}

// ── Hash computation ─────────────────────────────────────────────────

/**
 * Hash of the incoming request: tool name + arguments.
 */
export function computeInputHash(
  toolName: string,
  args: Record<string, unknown>,
): string {
  return hashObj({ tool_name: toolName, arguments: args });
}

/**
 * Hash of governance reasoning: authority decision, check results,
 * and optional justification.
 */
export function computeReasoningHash(
  authorityDecision: AuthorityDecision,
  checkResults: CheckResult[],
  justification?: string,
): string {
  return hashObj({
    decision: authorityDecision.decision,
    reason: authorityDecision.reason,
    boundary_type: authorityDecision.boundary_type,
    checks: checkResults.map((c) => ({
      check_id: c.check_id,
      passed: c.passed,
      severity: c.severity,
    })),
    justification: justification ?? null,
  });
}

/**
 * Hash of the action taken: the tool result, whether it was allowed,
 * and whether escalation was involved.
 */
export function computeActionHash(
  toolResult: unknown,
  wasAllowed: boolean,
  wasEscalated: boolean,
): string {
  // Normalize result to string for hashing
  const resultStr =
    typeof toolResult === "string"
      ? toolResult
      : JSON.stringify(toolResult ?? null);

  return hashContent(
    `allowed=${wasAllowed}:escalated=${wasEscalated}:result=${resultStr}`,
  );
}

/**
 * Build the complete receipt triad from pre-computed hashes.
 */
export function buildReceiptTriad(
  inputHash: string,
  reasoningHash: string,
  actionHash: string,
): ReceiptTriad {
  return {
    input_hash: inputHash,
    reasoning_hash: reasoningHash,
    action_hash: actionHash,
  };
}
