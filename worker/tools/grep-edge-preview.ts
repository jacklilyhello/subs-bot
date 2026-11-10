import { probeGrepRuntimeShape } from "./grep-runtime-probe.ts";

declare const PROBE_REVISION: string;

const headers = { "Cache-Control": "private, no-store", "X-Subs-Bot-Grep-Preview": PROBE_REVISION };

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== "/" || url.search) {
      return new Response(null, { status: 404, headers });
    }
    if (request.method === "GET") return new Response(null, { status: 204, headers });
    if (request.method !== "POST") return new Response(null, { status: 405, headers });
    try {
      return Response.json(await probeGrepRuntimeShape(), { headers });
    } catch {
      return new Response(null, { status: 502, headers });
    }
  },
};
