CREATE TABLE telegram_general_groups (
  bot_id TEXT NOT NULL REFERENCES telegram_general_policy(bot_id),
  generation INTEGER NOT NULL CHECK(generation>0),
  chat_id TEXT NOT NULL CHECK(chat_id GLOB '-[1-9]*' AND chat_id NOT GLOB '-*[^0-9]*'),
  chat_type TEXT NOT NULL CHECK(chat_type IN ('group','supergroup')),
  PRIMARY KEY(bot_id,generation,chat_id)
) STRICT;
