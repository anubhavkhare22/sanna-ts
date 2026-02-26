import { Command } from "commander";

export async function runMigrate(
  source: string,
  options: { config?: string; output?: string },
): Promise<void> {
  const { migrateClaudeConfig, migrateCursorConfig } = await import(
    "@sanna-ai/gateway"
  );

  const outputPath = options.output ?? "gateway.yaml";

  try {
    if (source === "claude") {
      const result = migrateClaudeConfig(options.config, outputPath);
      console.log(`Generated gateway config: ${result}`);
    } else if (source === "cursor") {
      const result = migrateCursorConfig(options.config, outputPath);
      console.log(`Generated gateway config: ${result}`);
    } else {
      console.error(`Unknown source: ${source}. Use 'claude' or 'cursor'.`);
      process.exitCode = 1;
      return;
    }

    console.log(`
Next steps:
  1. Edit ${outputPath} to configure enforcement settings
  2. Edit constitution.yaml with your agent's boundaries
  3. Generate signing keys: sanna keygen
  4. Start the gateway: sanna gateway ${outputPath}`);
  } catch (err) {
    console.error(
      `Migration failed: ${err instanceof Error ? err.message : err}`,
    );
    process.exitCode = 1;
  }
}

export const migrateCommand = new Command("migrate")
  .description("Migrate existing MCP config to gateway format")
  .argument("<source>", "Source format: claude or cursor")
  .option("--config <path>", "Path to source config file")
  .option("--output <path>", "Output path for gateway.yaml", "gateway.yaml")
  .action(async (source, options) => {
    await runMigrate(source, options);
  });
