CREATE TABLE telegram_general_read_lane (
  bot_id TEXT PRIMARY KEY NOT NULL,
  epoch INTEGER NOT NULL CHECK (epoch BETWEEN 1 AND 9007199254740991),
  mode TEXT NOT NULL CHECK (mode IN ('isolated','closed','general')),
  generation INTEGER CHECK (generation BETWEEN 1 AND 9007199254740991),
  member_date INTEGER CHECK (member_date BETWEEN 1 AND 9007199254740991),
  member_message INTEGER CHECK (member_message BETWEEN 1 AND 9007199254740991),
  CHECK ((member_date IS NULL)=(member_message IS NULL)),
  CHECK (generation IS NOT NULL OR member_date IS NULL),
  CHECK (mode<>'isolated' OR generation IS NULL),
  CHECK (mode<>'general' OR generation IS NOT NULL)
) STRICT;
