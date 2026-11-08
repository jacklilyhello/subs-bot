"""Hosted SQLite checks for batch work during selected and bulk fixture operations."""

from pathlib import Path
import unittest

from test_telegram_aggregate_smoke import COHORT, IDENTITY, KEY, POLICY, STAMP, FakeResources
from cloudflare_isolation import CloudflareError
from d1_migrations import _assert_sql
from telegram_bulk_trash_smoke import BulkCohort
from telegram_selected_smoke import SelectedCohort
from telegram_view_fixtures import FixtureError, statement


class ProviderBatchFixtureQuietTests(unittest.TestCase):
    def setUp(self):
        self.cloud = FakeResources()
        self.addCleanup(self.cloud.db.close)
        self.now = STAMP
        self.cloud.db.create_function("unixepoch", 0, lambda: self.now)
        self.update = 0

    def cohorts(self):
        return tuple(kind(self.cloud, POLICY, COHORT, KEY, IDENTITY) for kind in (SelectedCohort, BulkCohort))

    def quiet(self, cohorts, expected):
        for cohort in cohorts:
            with self.subTest(cohort=type(cohort).__name__):
                if expected:
                    cohort.require_quiet([])
                else:
                    with self.assertRaisesRegex(FixtureError, "in-flight"):
                        cohort.require_quiet([])

    def inbox(self, bot, actor, marker):
        self.update += 1
        return self.cloud.db.execute("""INSERT INTO telegram_inbox
          (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
          VALUES (?,?,?,?,'private',?,unixepoch(),'help',?) RETURNING receipt_id""",
          (bot, self.update, actor, actor, self.update, marker)).fetchone()[0]

    def batch(self, bot, actor):
        preview = self.inbox(bot, actor, "provider-batch-preview:v1")
        batch = self.inbox(bot, actor, "provider-batch-confirm:v1")
        with self.cloud.db:
            self.cloud.db.execute("""INSERT INTO telegram_provider_batches
              (batch_id,preview_receipt_id,origin_attempt,bot_id,actor_id,actor_role,auth_message_date,
               auth_message_id,admission_nonce,target_count,skipped_count,created_at,expires_at)
              VALUES (?,?,1,?,?,'admin',0,0,?,1,0,unixepoch(),unixepoch()+2700)""",
              (batch, preview, bot, actor, str(batch)))
            self.cloud.db.execute("""INSERT INTO telegram_provider_batch_jobs
              (batch_id,ordinal,owner_id,request_key,kind,subscription_id,source_sha256,expected_generation,
               expected_lifecycle_revision,state,created_at,due_at,expires_at)
              VALUES (?,1,?,?,'refresh',1,?,0,0,'waiting',unixepoch(),unixepoch(),unixepoch()+2700)""",
              (batch, actor, f"{batch:064x}", "e" * 64))
        return batch

    def test_old_schema_is_quiet_and_a_schema_change_invalidates_the_cas(self):
        self.cloud.db.executescript("""DROP TABLE telegram_provider_batch_interactions;
          DROP TABLE telegram_provider_batch_jobs;
          DROP TABLE telegram_provider_batches;
          DROP INDEX telegram_provider_batch_preview_order;""")
        older = self.cohorts()
        self.quiet(older, True)
        migrations = Path(__file__).resolve().parents[1] / "migrations"
        self.cloud.db.executescript((migrations / "0031_telegram_provider_batch_queue.sql").read_text("utf-8"))
        self.quiet(older, False)
        core = self.cohorts()
        self.quiet(core, True)
        self.batch(POLICY["botId"], POLICY["adminId"])
        self.quiet(core, False)
        self.cloud.db.executescript("DROP TABLE telegram_provider_batch_jobs;")
        with self.assertRaisesRegex(FixtureError, "batch fixture schema differs"):
            self.cohorts()

    def test_scoped_parent_child_and_transactional_cleanup_fence(self):
        cohorts = self.cohorts()
        self.batch("881020", POLICY["adminId"])
        self.batch(POLICY["botId"], "881021")
        self.quiet(cohorts, True)
        selected_guard = cohorts[0].quiet([], assertion=True)
        condition, params = cohorts[1].quiet([])
        bulk_guard = statement(_assert_sql(condition), *params)
        batch = self.batch(POLICY["botId"], POLICY["memberId"])
        self.quiet(cohorts, False)
        for guard in (selected_guard, bulk_guard):
            with self.assertRaises(CloudflareError):
                self.cloud.api("POST", self.cloud.database + "/query", {"batch": [
                    statement("UPDATE telegram_inbox SET command='start' WHERE receipt_id=?", batch), guard]})
            self.assertEqual(self.cloud.query("SELECT command FROM telegram_inbox WHERE receipt_id=?", (batch,)),
                             [{"command": "help"}])
        self.now += 900
        self.cloud.db.execute("""UPDATE telegram_provider_batches SET finished_at=unixepoch()-900,
            saved_count=1,failed_count=0,stale_count=0,expired_count=0 WHERE batch_id=?""", (batch,))
        self.quiet(cohorts, False)
        self.cloud.db.execute("UPDATE telegram_provider_batch_jobs SET state='done',result_code='saved',finished_at=unixepoch() WHERE batch_id=?",
                              (batch,))
        self.quiet(cohorts, True)

    def test_unconsumed_ticket_and_recoverable_terminal_hold_both_cohorts(self):
        cohorts = self.cohorts()
        preview = self.inbox(POLICY["botId"], POLICY["adminId"], "provider-batch-preview:v1")
        self.cloud.db.execute("""INSERT INTO telegram_provider_batch_interactions
          (receipt_id,kind,actor_role,auth_message_date,auth_message_id,ready_at,targets,token_sha256,origin_attempt,expires_at)
          VALUES (?,'preview','admin',0,0,unixepoch(),'[[1,0,0]]',?,1,unixepoch()+1)""", (preview, "a" * 64))
        self.quiet(cohorts, False)
        self.now += 1
        self.quiet(cohorts, True)

        batch = self.batch(POLICY["botId"], POLICY["adminId"])
        self.cloud.db.execute("""UPDATE telegram_provider_batches SET finished_at=unixepoch(),
            saved_count=1,failed_count=0,stale_count=0,expired_count=0 WHERE batch_id=?""", (batch,))
        self.cloud.db.execute("UPDATE telegram_provider_batch_jobs SET state='done',result_code='saved',finished_at=unixepoch() WHERE batch_id=?",
                              (batch,))
        self.quiet(cohorts, False)
        self.cloud.db.execute("""INSERT INTO telegram_provider_batch_interactions
          (receipt_id,kind,batch_id,actor_role,auth_message_date,auth_message_id,ready_at)
          VALUES (?,'terminal',?,'admin',0,0,unixepoch())""", (batch, batch))
        self.quiet(cohorts, False)
        self.cloud.db.execute("INSERT INTO telegram_outbox (receipt_id,state) VALUES (?,'pending')", (batch,))
        self.quiet(cohorts, False)
        self.cloud.db.execute("UPDATE telegram_outbox SET state='sent',sent_message_id=100 WHERE receipt_id=?", (batch,))
        self.quiet(cohorts, True)


if __name__ == "__main__":
    unittest.main()
