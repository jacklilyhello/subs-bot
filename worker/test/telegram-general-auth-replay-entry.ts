// Only the hosted oracle bundles this adapter. It has no Bot API credentials or outbound Telegram path.
import { acceptGeneralAuthReplay, drainGeneralAuthReplay, type GeneralAuthReplayPin } from "../src/telegram/general-auth-replay.ts";

interface Env {
  DB: D1Database;
  REPLAY_PIN: GeneralAuthReplayPin;
}

export default {
  async fetch(request, env) {
    try {
      const path = new URL(request.url).pathname;
      if (path === "/telegram/webhook") {
        return new Response(null, { status: await acceptGeneralAuthReplay(env.DB, env.REPLAY_PIN, request) });
      }
      if (path !== "/test/drain" || request.method !== "POST") return new Response(null, { status: 404 });
      const outcome = await drainGeneralAuthReplay(env.DB, env.REPLAY_PIN, async (body) => {
        const response = await fetch("https://transport.fixture.invalid/sendMessage", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        });
        return response.ok;
      });
      return Response.json({ outcome });
    } catch {
      return new Response(null, { status: 503 });
    }
  },
} satisfies ExportedHandler<Env>;
