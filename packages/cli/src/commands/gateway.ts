import { Command } from "commander";
import { resolve } from "node:path";
import { existsSync } from "node:fs";

export async function runGateway(configPath: string): Promise<void> {
  const resolved = resolve(configPath);
  if (!existsSync(resolved)) {
    console.error(`Error: Config file not found: ${resolved}`);
    process.exitCode = 1;
    return;
  }

  const { loadGatewayConfig, SannaGateway } = await import("@sanna-ai/gateway");
  const { StdioServerTransport } = await import(
    "@modelcontextprotocol/sdk/server/stdio.js"
  );

  const config = loadGatewayConfig(resolved);
  const gateway = new SannaGateway(config);

  const shutdown = async () => {
    process.stderr.write("[sanna-gateway] shutting down...\n");
    await gateway.stop();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  await gateway.start();

  const transport = new StdioServerTransport();
  await gateway.getServer().connect(transport);
}

export const gatewayCommand = new Command("gateway")
  .description("Start the Sanna enforcement gateway")
  .argument("<config>", "Path to gateway.yaml config file")
  .action(async (config) => {
    await runGateway(config);
  });
