CREATE TABLE telegram_general_auth_actions (
  receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox(receipt_id),
  bot_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  target_id TEXT NOT NULL,
  message_date INTEGER NOT NULL,
  update_id INTEGER NOT NULL,
  result TEXT NOT NULL CHECK(result IN ('changed','unchanged','stale','unavailable')),
  revision INTEGER,
  CHECK((revision IS NOT NULL)=(result IN ('changed','unchanged')))
) STRICT;
CREATE INDEX telegram_general_auth_target ON telegram_general_auth_actions (bot_id,generation,target_id,message_date,update_id) WHERE revision IS NOT NULL;
