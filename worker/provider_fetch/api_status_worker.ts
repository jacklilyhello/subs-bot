import { DurableObject, WorkerEntrypoint, WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import type { ProviderApiStatusResult, ProviderApiStatusV2Input, ProviderApiStatusV2Prober } from "../src/provider-fetch-contract.ts";
import {
  API_STATUS_SERVICE, apiStatusFailure, exercise, probePinnedProviderApiStatusV2, providerApiStatusResult,
  providerApiStatusV2Expired, providerApiStatusV2Request, ProviderProbeError, REVISION,
} from "./controller.ts";

interface Env {
  BUILD_REVISION: string;
}

declare global {
  namespace Cloudflare {
    interface GlobalProps {
      mainModule: typeof import("./api_status_worker.ts");
      durableNamespaces: "ProviderContainer";
    }
  }
}

const SINGLETON = "provider-api-status-v2";
const SMOKE_STATUS_URL = "https://subs-bot-cf-dev-01.lilyya.workers.dev/v1/models";
const SMOKE_STATUS_KEY = "synthetic-provider-smoke-key";

interface Probe {
  providerRevision: string;
  isolatedRevision: string;
}

function validProbe(probe: Probe, revision: string): boolean {
  return typeof probe === "object" && probe !== null && Object.keys(probe).length === 2
    && typeof revision === "string" && REVISION.test(revision) && probe.providerRevision === revision
    && typeof probe.isolatedRevision === "string" && REVISION.test(probe.isolatedRevision);
}

export class ProviderContainer extends DurableObject<Env> {
  private busy = false;

  async probeApiStatusV2(input: ProviderApiStatusV2Input): Promise<ProviderApiStatusResult> {
    try {
      const request = providerApiStatusV2Request(input);
      if (request === null) return apiStatusFailure("invalid-request");
      if (request.providerRevision !== this.env.BUILD_REVISION) return apiStatusFailure("unavailable");
      if (providerApiStatusV2Expired(request.dispatchBeforeMs)) return apiStatusFailure("timeout");
      const container = this.ctx.container;
      if (!this.ctx.id.equals(this.ctx.exports.ProviderContainer.idFromName(SINGLETON)) || !container) {
        return apiStatusFailure("unavailable");
      }
      if (this.busy) return apiStatusFailure("busy");
      this.busy = true;
      try {
        return await probePinnedProviderApiStatusV2(container, request, API_STATUS_SERVICE);
      } finally {
        this.busy = false;
      }
    } catch {
      return apiStatusFailure("unavailable");
    }
  }

  async prove(probe: Probe) {
    const revision = this.env.BUILD_REVISION;
    const container = this.ctx.container;
    if (!this.ctx.id.equals(this.ctx.exports.ProviderContainer.idFromName(SINGLETON))
        || !validProbe(probe, revision) || this.busy || !container) {
      throw new Error("Provider smoke admission rejected.");
    }
    this.busy = true;
    try {
      const key = `smoke:${revision}`;
      if (await this.ctx.storage.get(key)) throw new Error("Provider smoke was already admitted for this revision.");
      await this.ctx.storage.put(key, true);
      return await exercise(container, revision, probe.isolatedRevision, API_STATUS_SERVICE);
    } catch (error) {
      return { ok: false, stage: error instanceof ProviderProbeError ? error.stage : "admission" };
    } finally {
      this.busy = false;
    }
  }
}

export class ProviderApiStatus extends WorkerEntrypoint<Env> implements ProviderApiStatusV2Prober {
  async probeApiStatusV2(input: ProviderApiStatusV2Input): Promise<ProviderApiStatusResult> {
    try {
      const request = providerApiStatusV2Request(input);
      if (request === null) return apiStatusFailure("invalid-request");
      if (request.providerRevision !== this.env.BUILD_REVISION) return apiStatusFailure("unavailable");
      if (providerApiStatusV2Expired(request.dispatchBeforeMs)) return apiStatusFailure("timeout");
      const result = await this.ctx.exports.ProviderContainer.getByName(SINGLETON).probeApiStatusV2(request);
      return providerApiStatusResult(result);
    } catch {
      return apiStatusFailure("unavailable");
    }
  }
}

export class ProviderSmoke extends WorkflowEntrypoint<Env, Probe> {
  async run(event: WorkflowEvent<Probe>, step: WorkflowStep) {
    const revision = this.env.BUILD_REVISION;
    if (!validProbe(event.payload, revision) || event.workflowName !== API_STATUS_SERVICE + "-smoke"
        || event.instanceId !== `provider-smoke-${revision}`) {
      throw new Error("Provider smoke request differs from the pinned release.");
    }
    const egress = await step.do("verify fixed provider egress", { retries: { limit: 0, delay: "1 second" }, timeout: "75 seconds" }, async () => {
      try {
        return await this.ctx.exports.ProviderContainer.getByName(SINGLETON).prove(event.payload);
      } catch {
        throw new Error("Provider container smoke failed.");
      }
    });
    if (!egress.ok || !("imageSha256" in egress)) return egress;
    const apiStatus = await step.do("verify fixed API status RPC", { retries: { limit: 0, delay: "1 second" }, timeout: "45 seconds" }, async () => {
      const result = await this.ctx.exports.ProviderApiStatus.probeApiStatusV2({
        url: SMOKE_STATUS_URL, key: SMOKE_STATUS_KEY, providerRevision: revision,
        imageSha256: egress.imageSha256, dispatchBeforeMs: Date.now() + 30_000,
      });
      if (!result.ok || result.status !== 404) throw new Error("The fixed provider API status probe did not return the expected status.");
      return result.status;
    });
    return { ...egress, apiStatus };
  }
}

export default {
  fetch(): Response {
    return new Response("Not found.", { status: 404, headers: {
      "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
    } });
  },
} satisfies ExportedHandler<Env>;
