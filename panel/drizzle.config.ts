import type { Config } from "drizzle-kit";
import path from "node:path";

export default {
  schema: "./src/db/schema.ts",
  out: "./src/db/migrations",
  dialect: "sqlite",
  dbCredentials: {
    url: process.env.PANEL_DB_PATH ?? path.join(process.cwd(), "data", "findings.db"),
  },
} satisfies Config;
