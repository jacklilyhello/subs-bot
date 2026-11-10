CREATE TABLE telegram_page_jump_activation_journal (
    bot_id TEXT NOT NULL CHECK (
        length(bot_id) BETWEEN 1 AND 16
        AND length(CAST(bot_id AS BLOB)) = length(bot_id)
        AND bot_id NOT GLOB '*[^0-9]*'
        AND substr(bot_id,1,1) <> '0'
        AND (length(bot_id) < 16 OR bot_id <= '9007199254740991')
    ),
    epoch INTEGER NOT NULL CHECK (epoch BETWEEN 1 AND 9007199254740991),
    intent_run_id INTEGER NOT NULL CHECK (intent_run_id BETWEEN epoch+1 AND 9007199254740991),
    stage_sha256 TEXT NOT NULL CHECK (length(stage_sha256)=64 AND stage_sha256 NOT GLOB '*[^0-9a-f]*'),
    prior_sha256 TEXT NOT NULL CHECK (length(prior_sha256)=64 AND prior_sha256 NOT GLOB '*[^0-9a-f]*'),
    candidate_sha256 TEXT NOT NULL CHECK (length(candidate_sha256)=64 AND candidate_sha256 NOT GLOB '*[^0-9a-f]*'),
    prior_deployment_id TEXT NOT NULL CHECK (length(prior_deployment_id)=36),
    prior_version_id TEXT NOT NULL CHECK (length(prior_version_id)=36),
    candidate_version_id TEXT NOT NULL CHECK (length(candidate_version_id)=36 AND candidate_version_id<>prior_version_id),
    restores_epoch INTEGER CHECK (restores_epoch BETWEEN 1 AND epoch-1),
    deployment_id TEXT CHECK (length(deployment_id)=36 AND deployment_id<>prior_deployment_id),
    PRIMARY KEY (bot_id,epoch),
    FOREIGN KEY (bot_id,restores_epoch) REFERENCES telegram_page_jump_activation_journal(bot_id,epoch)
) STRICT;
