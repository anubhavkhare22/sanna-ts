import { Command } from "commander";
import { existsSync } from "node:fs";
import {
  ReceiptStore,
  DriftAnalyzer,
  formatDriftReport,
  exportDriftReport,
} from "@sanna-ai/core";

export async function runDriftReport(options: {
  db: string;
  window: number;
  json?: boolean;
  threshold?: number;
}): Promise<void> {
  if (!existsSync(options.db)) {
    console.error(`Error: Receipt store not found: ${options.db}`);
    console.error("Run agents with ReceiptStore to populate it first.");
    process.exitCode = 1;
    return;
  }

  const store = new ReceiptStore(options.db);
  try {
    const analyzer = new DriftAnalyzer(store);
    const report = analyzer.analyze(options.window, {
      threshold: options.threshold ?? 0.15,
    });

    if (options.json) {
      console.log(exportDriftReport(report, "json"));
    } else {
      console.log(formatDriftReport(report));
    }

    if (report.fleet_status === "CRITICAL") {
      process.exitCode = 1;
    }
  } finally {
    store.close();
  }
}

export const driftReportCommand = new Command("drift-report")
  .description("Fleet governance drift report")
  .option("--db <path>", "Path to receipt store DB", ".sanna/receipts.db")
  .option("--window <days>", "Analysis window in days", "30")
  .option("--json", "Machine-readable JSON output")
  .option("--threshold <rate>", "Failure-rate threshold 0-1", "0.15")
  .action(async (opts) => {
    await runDriftReport({
      db: opts.db,
      window: parseInt(opts.window, 10),
      json: opts.json,
      threshold: parseFloat(opts.threshold),
    });
  });
