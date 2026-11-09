/** Record the verified temp migration after applying its SQL to an ephemeral D1 fixture. */
export async function recordTempFixtureMigration(db: D1Database, { name, sha256 }: { name: string; sha256: string }): Promise<void> {
  if (name !== "0039_legacy_temp_baseline.sql") return;
  const results = await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS subs_bot_schema_migrations (
    position INTEGER PRIMARY KEY CHECK (position >= 1),
    name TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    mode TEXT NOT NULL CHECK (mode = 'applied' OR (position = 1 AND mode = 'adopted')),
    applied_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK (applied_at > 0)
) STRICT`),
    db.prepare("INSERT INTO subs_bot_schema_migrations (position,name,sha256,mode) VALUES (39,?,?,'applied')")
      .bind(name, sha256),
  ]);
  if (results.length !== 2 || results.some(({ success }) => !success) || results[1].meta.changes !== 1) {
    throw new Error("Could not record the temporary-node fixture migration.");
  }
}
