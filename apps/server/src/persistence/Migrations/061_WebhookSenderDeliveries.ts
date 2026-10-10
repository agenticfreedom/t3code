import * as Effect from "effect/Effect";
import * as SqlClient from "effect/sql/SqlClient";

export default Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;

  // Signed-timestamp requests a task already ran, by timestamp and digest.
  // Kept 48 hours, longer than the largest tolerance, so a resend runs once.
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
