import * as Effect from "effect/Effect";
import * as SqlClient from "effect/sql/SqlClient";

export default Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;

  // What a verified sender already delivered to a task: a signed timestamp
  // with its digest, or the sender's own delivery id. Kept 48 hours, longer
  // than the largest timestamp tolerance, so a resend runs once.
  yield* sql`
    CREATE TABLE IF NOT EXISTS scheduled_task_webhook_sender_deliveries (
      task_id TEXT NOT NULL,
      claim_key TEXT NOT NULL,
      seen_at TEXT NOT NULL,
      PRIMARY KEY (task_id, claim_key)
    )
  `;

  yield* sql`
    CREATE INDEX IF NOT EXISTS idx_scheduled_task_webhook_sender_deliveries_seen
    ON scheduled_task_webhook_sender_deliveries(seen_at)
  `;
});
