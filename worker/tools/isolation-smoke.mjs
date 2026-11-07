import { readFile } from "node:fs/promises";
import { verifyIsolation } from "./verify-isolation.mjs";

const origin = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
const fixture = JSON.parse(await readFile(process.argv[2], "utf8"));
await verifyIsolation(fixture, process.env.BUILD_REVISION, (path, init) => fetch(origin + path, init));

console.log("Cloudflare verified: exact revision, small and >2 MB private snapshots, Sing-box, Clash aliases, HEAD, 404 and 406.");
