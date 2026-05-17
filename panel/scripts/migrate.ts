// Bootstraps the SQLite DB by triggering the migration block in src/db/client.ts.
// CREATE-IF-NOT-EXISTS only; the schema lives inline in that file.
import "../src/db/client";

console.log("[panel] DB migrations applied.");
