CREATE TABLE telegram_general_isolation_window (
  bot_id TEXT PRIMARY KEY NOT NULL,
  profile TEXT NOT NULL CHECK(profile='full-v1'),
  release_revision TEXT NOT NULL CHECK(length(release_revision)=40 AND release_revision NOT GLOB '*[^0-9a-f]*'),
  active_sha256 TEXT NOT NULL CHECK(length(active_sha256)=64 AND active_sha256 NOT GLOB '*[^0-9a-f]*'),
  admin_id TEXT NOT NULL,
  member_id TEXT NOT NULL CHECK(member_id<>admin_id),
  group_id TEXT NOT NULL,
  generation INTEGER CHECK(generation BETWEEN 1 AND 9007199254740991),
  opened_epoch INTEGER CHECK(opened_epoch BETWEEN 1 AND 9007199254740991),
  CHECK((generation IS NULL)=(opened_epoch IS NULL))
) STRICT;
