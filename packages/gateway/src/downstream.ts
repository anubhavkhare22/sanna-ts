/**
 * Sanna Gateway — Downstream Connection
 *
 * Manages child process MCP servers. Spawns a subprocess,
 * connects an MCP client over stdio, and provides methods
 * to list and call tools.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { DownstreamConfig } from "./config.js";

// ── Types ────────────────────────────────────────────────────────────

export interface ToolInfo {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface ToolCallResult {
  content: Array<{ type: string; text?: string; [key: string]: unknown }>;
  isError?: boolean;
}

export type DisconnectCallback = (name: string, code: number | null) => void;

// ── Downstream Connection ────────────────────────────────────────────

export class DownstreamConnection {
  readonly name: string;
  private _config: DownstreamConfig;
  private _client: Client | null = null;
  private _transport: StdioClientTransport | null = null;
  private _connected = false;
  private _onDisconnect: DisconnectCallback | null = null;

  constructor(config: DownstreamConfig) {
    this.name = config.name;
    this._config = config;
  }

  /**
   * Register a callback for unexpected disconnection.
   */
  onDisconnect(callback: DisconnectCallback): void {
    this._onDisconnect = callback;
  }

  /**
   * Spawn the child process and establish an MCP client connection.
   */
  async connect(): Promise<void> {
    if (this._connected) return;

    // Build environment: allowlist of essential runtime vars + downstream env.
    // Secrets needed by specific downstreams must be explicitly configured
    // in downstream.env config — never leak gateway-level secrets.
    const ENV_ALLOWLIST = new Set([
      "PATH", "HOME", "TMPDIR", "TEMP", "TMP",
      "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL",
      "NODE_ENV", "NODE_OPTIONS",
      "TERM", "COLORTERM",
    ]);
    const baseEnv: Record<string, string> = {};
    for (const key of ENV_ALLOWLIST) {
      if (process.env[key] !== undefined) {
        baseEnv[key] = process.env[key]!;
      }
    }
    const env: Record<string, string> = {
      ...baseEnv,
      ...(this._config.env ?? {}),
    };

    this._transport = new StdioClientTransport({
      command: this._config.command,
      args: this._config.args,
      env,
      stderr: "pipe",
    });

    this._client = new Client(
      { name: `sanna-gateway/${this.name}`, version: "0.1.0" },
    );

    // Handle transport close
    this._transport.onclose = () => {
      if (this._connected) {
        this._connected = false;
        this._onDisconnect?.(this.name, null);
      }
    };

    // Capture stderr for logging
    this._transport.onerror = (err) => {
      if (process.env.SANNA_DEBUG) {
        process.stderr.write(
          `[sanna-gateway] downstream '${this.name}' error: ${err.message}\n`,
        );
      }
    };

    await this._client.connect(this._transport);
    this._connected = true;
  }

  /**
   * Get available tools from the downstream server.
   */
  async listTools(): Promise<ToolInfo[]> {
    if (!this._client || !this._connected) {
      throw new Error(`Downstream '${this.name}' is not connected`);
    }
    const result = await this._client.listTools();
    return result.tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema as Record<string, unknown> | undefined,
    }));
  }

  /**
   * Forward a tool call to the downstream server.
   */
  async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<ToolCallResult> {
    if (!this._client || !this._connected) {
      throw new Error(`Downstream '${this.name}' is not connected`);
    }
    const result = await this._client.callTool({ name, arguments: args });
    return {
      content: result.content as ToolCallResult["content"],
      isError: result.isError,
    };
  }

  /**
   * Check if the downstream is currently connected.
   */
  isConnected(): boolean {
    return this._connected;
  }

  /**
   * Graceful shutdown: close transport (sends SIGTERM to child).
   * Falls back to tree-kill if needed.
   */
  async disconnect(): Promise<void> {
    if (!this._connected && !this._transport) return;

    this._connected = false;
    const transport = this._transport;
    this._transport = null;
    this._client = null;

    if (transport) {
      // Get PID before closing
      const pid = transport.pid;

      try {
        await transport.close();
      } catch {
        // Transport already closed
      }

      // If the process is still alive, force kill via tree-kill
      if (pid) {
        try {
          const treeKill = (await import("tree-kill")).default;
          await new Promise<void>((resolve) => {
            treeKill(pid, "SIGKILL", () => resolve());
          });
        } catch {
          // Process already exited
        }
      }
    }
  }
}
