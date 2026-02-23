import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import {
  evaluateAuthority,
  normalizeAuthorityName,
} from "../src/evaluator.js";
import { loadConstitution } from "../src/constitution.js";
import type { Constitution, AuthorityBoundaries } from "../src/types.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");

// ── Helper: build a minimal constitution with authority boundaries ───

function makeConstitution(ab: AuthorityBoundaries | null = null): Constitution {
  return {
    schema_version: "1.0.0",
    identity: { agent_name: "test", domain: "testing", description: "", extensions: {} },
    provenance: {
      authored_by: "test@test.com",
      approved_by: ["test@test.com"],
      approval_date: "2026-01-01",
      approval_method: "manual",
      change_history: [],
      signature: null,
    },
    boundaries: [{ id: "B001", description: "Test", category: "scope", severity: "high" }],
    trust_tiers: { autonomous: [], requires_approval: [], prohibited: [] },
    halt_conditions: [],
    invariants: [],
    policy_hash: null,
    authority_boundaries: ab,
    trusted_sources: null,
  };
}

// ── normalizeAuthorityName (Appendix D) ──────────────────────────────

describe("normalizeAuthorityName", () => {
  it("normalizes camelCase", () => {
    expect(normalizeAuthorityName("deleteFile")).toBe("delete.file");
  });

  it("normalizes snake_case", () => {
    expect(normalizeAuthorityName("delete_file")).toBe("delete.file");
  });

  it("normalizes kebab-case", () => {
    expect(normalizeAuthorityName("delete-file")).toBe("delete.file");
  });

  it("normalizes PascalCase", () => {
    expect(normalizeAuthorityName("DeleteFile")).toBe("delete.file");
  });

  it("normalizes uppercase acronyms", () => {
    expect(normalizeAuthorityName("HTTPSClient")).toBe("https.client");
  });

  it("normalizes mixed separators", () => {
    expect(normalizeAuthorityName("API-patch-page")).toBe("api.patch.page");
  });

  it("handles digit transitions", () => {
    expect(normalizeAuthorityName("tool2use")).toBe("tool.2.use");
  });
});

// ── evaluateAuthority ────────────────────────────────────────────────

describe("evaluateAuthority — no boundaries", () => {
  it("allows when no authority_boundaries defined", () => {
    const c = makeConstitution(null);
    const result = evaluateAuthority("anything", {}, c);
    expect(result.decision).toBe("allow");
    expect(result.boundary_type).toBe("uncategorized");
  });

  it("allows when boundaries section is empty", () => {
    const c = makeConstitution({
      cannot_execute: [],
      must_escalate: [],
      can_execute: [],
      default_escalation: "log",
    });
    const result = evaluateAuthority("anything", {}, c);
    expect(result.decision).toBe("allow");
    expect(result.boundary_type).toBe("uncategorized");
  });
});

describe("evaluateAuthority — cannot_execute", () => {
  const ab: AuthorityBoundaries = {
    cannot_execute: ["*_credential*", "shell_*"],
    must_escalate: [],
    can_execute: ["*_read", "*_list"],
    default_escalation: "log",
  };

  it("halts on credential access", () => {
    const c = makeConstitution(ab);
    const result = evaluateAuthority("get_credential_token", {}, c);
    expect(result.decision).toBe("halt");
    expect(result.boundary_type).toBe("cannot_execute");
  });

  it("halts on shell commands", () => {
    const c = makeConstitution(ab);
    const result = evaluateAuthority("shell_exec", {}, c);
    expect(result.decision).toBe("halt");
    expect(result.boundary_type).toBe("cannot_execute");
  });
});

describe("evaluateAuthority — must_escalate", () => {
  const ab: AuthorityBoundaries = {
    cannot_execute: [],
    must_escalate: [
      { condition: "write operation", target: null },
      { condition: "create operation", target: null },
      { condition: "delete operation", target: { type: "webhook", url: "https://example.com" } },
    ],
    can_execute: ["*_read"],
    default_escalation: "log",
  };

  it("escalates on write operation", () => {
    const c = makeConstitution(ab);
    // Action context must contain ALL significant keywords from condition
    const result = evaluateAuthority("write_operation", {}, c);
    expect(result.decision).toBe("escalate");
    expect(result.boundary_type).toBe("must_escalate");
  });

  it("escalates on create operation", () => {
    const c = makeConstitution(ab);
    const result = evaluateAuthority("create_operation", {}, c);
    expect(result.decision).toBe("escalate");
    expect(result.boundary_type).toBe("must_escalate");
  });

  it("escalates on delete operation", () => {
    const c = makeConstitution(ab);
    const result = evaluateAuthority("delete_operation", {}, c);
    expect(result.decision).toBe("escalate");
    expect(result.boundary_type).toBe("must_escalate");
  });

  it("escalates when params contain matching keywords", () => {
    const c = makeConstitution(ab);
    const result = evaluateAuthority("execute", { operation: "write", table: "users" }, c);
    expect(result.decision).toBe("escalate");
    expect(result.boundary_type).toBe("must_escalate");
  });

  it("does not escalate when not all keywords match", () => {
    const c = makeConstitution(ab);
    const result = evaluateAuthority("db_write", {}, c);
    // "write operation" needs both "write" AND "operation" — only "write" present
    expect(result.decision).toBe("allow");
    expect(result.boundary_type).toBe("uncategorized");
  });
});

describe("evaluateAuthority — can_execute", () => {
  const ab: AuthorityBoundaries = {
    cannot_execute: [],
    must_escalate: [],
    can_execute: ["*_read", "*_search", "*_list"],
    default_escalation: "log",
  };

  it("allows explicitly permitted actions", () => {
    const c = makeConstitution(ab);
    const result = evaluateAuthority("user_read", {}, c);
    expect(result.decision).toBe("allow");
    expect(result.boundary_type).toBe("can_execute");
  });

  it("allows search actions", () => {
    const c = makeConstitution(ab);
    const result = evaluateAuthority("document_search", {}, c);
    expect(result.decision).toBe("allow");
    expect(result.boundary_type).toBe("can_execute");
  });
});

describe("evaluateAuthority — priority order", () => {
  it("cannot_execute overrides can_execute", () => {
    const ab: AuthorityBoundaries = {
      cannot_execute: ["admin_read"],
      must_escalate: [],
      can_execute: ["*_read"],
      default_escalation: "log",
    };
    const c = makeConstitution(ab);
    const result = evaluateAuthority("admin_read", {}, c);
    expect(result.decision).toBe("halt");
    expect(result.boundary_type).toBe("cannot_execute");
  });

  it("cannot_execute overrides must_escalate", () => {
    const ab: AuthorityBoundaries = {
      cannot_execute: ["dangerous_delete"],
      must_escalate: [{ condition: "Any delete operation", target: null }],
      can_execute: [],
      default_escalation: "log",
    };
    const c = makeConstitution(ab);
    const result = evaluateAuthority("dangerous_delete", {}, c);
    expect(result.decision).toBe("halt");
  });
});

describe("evaluateAuthority — unknown/default", () => {
  it("allows unknown actions by default", () => {
    const ab: AuthorityBoundaries = {
      cannot_execute: ["shell_exec"],
      must_escalate: [],
      can_execute: ["file_read"],
      default_escalation: "log",
    };
    const c = makeConstitution(ab);
    const result = evaluateAuthority("something_entirely_new", {}, c);
    expect(result.decision).toBe("allow");
    expect(result.boundary_type).toBe("uncategorized");
  });
});

describe("evaluateAuthority — exact match security", () => {
  it("'user' in can_execute does NOT match 'delete_user'", () => {
    const ab: AuthorityBoundaries = {
      cannot_execute: [],
      must_escalate: [],
      can_execute: ["user"],
      default_escalation: "log",
    };
    const c = makeConstitution(ab);
    const result = evaluateAuthority("delete_user", {}, c);
    // Should NOT match — "user" is not a glob, must be exact
    expect(result.boundary_type).toBe("uncategorized");
  });

  it("'credential_access' in cannot_execute does NOT match bare 'access'", () => {
    const ab: AuthorityBoundaries = {
      cannot_execute: ["credential_access"],
      must_escalate: [],
      can_execute: [],
      default_escalation: "log",
    };
    const c = makeConstitution(ab);
    const result = evaluateAuthority("access", {}, c);
    // Should NOT match — exact match only
    expect(result.decision).toBe("allow");
  });

  it("glob 'read_*' matches 'read_file' but not 'write_file'", () => {
    const ab: AuthorityBoundaries = {
      cannot_execute: [],
      must_escalate: [],
      can_execute: ["read_*"],
      default_escalation: "log",
    };
    const c = makeConstitution(ab);
    expect(evaluateAuthority("read_file", {}, c).boundary_type).toBe("can_execute");
    expect(evaluateAuthority("write_file", {}, c).boundary_type).toBe("uncategorized");
  });

  it("glob '*_delete' matches 'user_delete' but not 'delete_user'", () => {
    const ab: AuthorityBoundaries = {
      cannot_execute: ["*_delete"],
      must_escalate: [],
      can_execute: [],
      default_escalation: "log",
    };
    const c = makeConstitution(ab);
    expect(evaluateAuthority("user_delete", {}, c).decision).toBe("halt");
    expect(evaluateAuthority("delete_user", {}, c).decision).toBe("allow");
  });

  it("exact 'search' matches 'search' but not 'search_all' or 'deep_search'", () => {
    const ab: AuthorityBoundaries = {
      cannot_execute: [],
      must_escalate: [],
      can_execute: ["search"],
      default_escalation: "log",
    };
    const c = makeConstitution(ab);
    expect(evaluateAuthority("search", {}, c).boundary_type).toBe("can_execute");
    expect(evaluateAuthority("search_all", {}, c).boundary_type).toBe("uncategorized");
    expect(evaluateAuthority("deep_search", {}, c).boundary_type).toBe("uncategorized");
  });

  it("separator normalization: read_file === readFile === read.file", () => {
    const ab: AuthorityBoundaries = {
      cannot_execute: [],
      must_escalate: [],
      can_execute: ["read_file"],
      default_escalation: "log",
    };
    const c = makeConstitution(ab);
    expect(evaluateAuthority("read_file", {}, c).boundary_type).toBe("can_execute");
    expect(evaluateAuthority("readFile", {}, c).boundary_type).toBe("can_execute");
    expect(evaluateAuthority("read.file", {}, c).boundary_type).toBe("can_execute");
  });
});

describe("evaluateAuthority — full-featured constitution fixture", () => {
  const c = loadConstitution(resolve(FIXTURES, "constitutions/full-featured.yaml"));

  it("halts on credential access", () => {
    const result = evaluateAuthority("get_credential_token", {}, c);
    expect(result.decision).toBe("halt");
    expect(result.boundary_type).toBe("cannot_execute");
  });

  it("halts on shell commands", () => {
    const result = evaluateAuthority("shell_exec", {}, c);
    expect(result.decision).toBe("halt");
    expect(result.boundary_type).toBe("cannot_execute");
  });

  it("allows read operations", () => {
    const result = evaluateAuthority("document_read", {}, c);
    expect(result.decision).toBe("allow");
    expect(result.boundary_type).toBe("can_execute");
  });

  it("escalates when all condition keywords match", () => {
    // Condition: "Any write or create operation" — significant: any, write, create, operation
    // All 4 must appear in action context
    const result = evaluateAuthority("any_create_operation", { write: "true" }, c);
    expect(result.decision).toBe("escalate");
    expect(result.boundary_type).toBe("must_escalate");
  });

  it("escalates delete operations when all keywords match", () => {
    // Condition: "Any delete operation" — significant: any, delete, operation
    const result = evaluateAuthority("any_delete_operation", {}, c);
    expect(result.decision).toBe("escalate");
    expect(result.boundary_type).toBe("must_escalate");
  });

  it("allows when not all escalation keywords present", () => {
    // "database_write" only has "write" — missing "any", "create", "operation"
    const result = evaluateAuthority("database_write", { table: "records" }, c);
    expect(result.decision).toBe("allow");
    expect(result.boundary_type).toBe("uncategorized");
  });
});
