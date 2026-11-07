import type { TelegramPolicy } from "./protocol.ts";

/** Match a recorded origin's isolation role. Retirement can classify a stale lease without authorizing delivery or work. */
export function isolatedTelegramRoleEpochSql(
  policy: Readonly<Pick<TelegramPolicy, "adminId" | "memberId">>,
  inbox: "inbox" | "earlier",
  mode: "current" | "recorded" = "current",
): { sql: string; bindings: readonly [string, string] } {
  const currentMember = mode === "current" ? `AND COALESCE((
    SELECT allowed = 1 AND message_date = origin.auth_message_date AND message_id = origin.auth_message_id
    FROM telegram_auth WHERE bot_id = ${inbox}.bot_id AND user_id = ${inbox}.actor_id
  ), origin.auth_message_date = 0 AND origin.auth_message_id = 0)` : "";
  return {
    sql: `((${inbox}.actor_id = ? AND origin.actor_role = 'admin' AND origin.auth_message_date = 0 AND origin.auth_message_id = 0)
      OR (${inbox}.actor_id = ? AND origin.actor_role = 'member' AND ${inbox}.message_date > origin.auth_message_date
        ${currentMember}))`,
    bindings: [policy.adminId, policy.memberId],
  };
}
