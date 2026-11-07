import { DurableObject, WorkerEntrypoint, WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import type { ProviderFetchInput, ProviderFetchResult } from "../src/provider-fetch-contract.ts";
import {
  exercise, fetchPinnedProvider, providerFailure, providerPayload, providerRequest, ProviderProbeError, REVISION, SERVICE, SINGLETON,
} from "./controller.ts";

interface Env {
  BUILD_REVISION: string;
  PROVIDER_CONTAINER: DurableObjectNamespace<ProviderContainer>;
}

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

  async fetchSubscription(input: ProviderFetchInput): Promise<ProviderFetchResult> {
    try {
      const request = providerRequest(input);
      if (request === null) return providerFailure("invalid-request");
      const revision = this.env.BUILD_REVISION;
      if (request.providerRevision !== revision) return providerFailure("unavailable");
      const payload = providerPayload({ url: request.url });
      if (payload === null) return providerFailure("invalid-request");
      const singleton = this.env.PROVIDER_CONTAINER.idFromName(SINGLETON);
      const container = this.ctx.container;
      if (!this.ctx.id.equals(singleton) || !container || typeof revision !== "string" || !REVISION.test(revision)) {
        return providerFailure("unavailable");
      }
      if (this.busy) return providerFailure("busy");
      this.busy = true;
      try {
        return await fetchPinnedProvider(container, revision, payload, request.imageSha256);
      } finally {
        this.busy = false;
      }
    } catch {
      return providerFailure("unavailable");
    }
  }

  async prove(probe: Probe) {
    const revision = this.env.BUILD_REVISION;
    const singleton = this.env.PROVIDER_CONTAINER.idFromName(SINGLETON);
    if (!this.ctx.id.equals(singleton) || !validProbe(probe, revision) || this.busy || !this.ctx.container) {
      throw new Error("Provider smoke admission rejected.");
    }
    this.busy = true;
    try {
      const key = `smoke:${revision}`;
      if (await this.ctx.storage.get(key)) throw new Error("Provider smoke was already admitted for this revision.");
      await this.ctx.storage.put(key, true);
      return await exercise(this.ctx.container, revision, probe.isolatedRevision);
    } catch (error) {
      // Store a fixed stage only, even when a platform error contains request data.
      return { ok: false, stage: error instanceof ProviderProbeError ? error.stage : "admission" };
    } finally {
      this.busy = false;
    }
  }
}

export class ProviderFetch extends WorkerEntrypoint<Env> {
  async fetchSubscription(input: ProviderFetchInput): Promise<ProviderFetchResult> {
    try {
      const request = providerRequest(input);
      if (request === null) return providerFailure("invalid-request");
      if (request.providerRevision !== this.env.BUILD_REVISION) return providerFailure("unavailable");
      return await this.env.PROVIDER_CONTAINER.getByName(SINGLETON).fetchSubscription(request);
    } catch {
      return providerFailure("unavailable");
    }
  }
}

export class ProviderSmoke extends WorkflowEntrypoint<Env, Probe> {
  async run(event: WorkflowEvent<Probe>, step: WorkflowStep) {
    const revision = this.env.BUILD_REVISION;
    if (!validProbe(event.payload, revision) || event.workflowName !== SERVICE + "-smoke"
        || event.instanceId !== `provider-smoke-${revision}`) {
      throw new Error("Provider smoke request differs from the pinned release.");
    }
    return step.do("verify fixed provider egress", { retries: { limit: 0, delay: "1 second" }, timeout: "75 seconds" }, async () => {
      try {
        const container = this.env.PROVIDER_CONTAINER.getByName(SINGLETON);
        return await container.prove(event.payload);
      } catch {
        throw new Error("Provider container smoke failed.");
      }
    });
  }
}

export default {
  fetch(): Response {
    return new Response("Not found.", { status: 404, headers: {
      "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
    } });
  },
} satisfies ExportedHandler<Env>;
