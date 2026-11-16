import { DurableObject, WorkerEntrypoint, WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import type {
  ProviderApiStatusInput, ProviderApiStatusProber, ProviderApiStatusResult, ProviderApiStatusV2Input, ProviderApiStatusV2Prober,
  ProviderFetchInput, ProviderFetchResult,
} from "../src/provider-fetch-contract.ts";
import {
  apiStatusFailure, exercise, fetchPinnedProvider, probePinnedProviderApiStatus, probePinnedProviderApiStatusV2,
  providerApiStatusRequest, providerApiStatusResult, providerApiStatusV2Expired, providerApiStatusV2Request,
  providerFailure, providerPayload, providerRequest, ProviderProbeError, REVISION, SERVICE, SINGLETON,
  readProviderRuntimeTarget, exerciseProviderRelease,
} from "./controller.ts";

interface Env {
  BUILD_REVISION: string;
  PROVIDER_TARGET_JSON?: string;
}

declare global {
  namespace Cloudflare {
    interface GlobalProps {
      mainModule: typeof import("./worker.ts");
      durableNamespaces: "ProviderContainer";
    }
  }
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
      const singleton = this.ctx.exports.ProviderContainer.idFromName(SINGLETON);
      const container = this.ctx.container;
      if (!this.ctx.id.equals(singleton) || !container || typeof revision !== "string" || !REVISION.test(revision)) {
        return providerFailure("unavailable");
      }
      if (this.busy) return providerFailure("busy");
      const target = this.env.PROVIDER_TARGET_JSON === undefined ? undefined : readProviderRuntimeTarget(this.env.PROVIDER_TARGET_JSON);
      if (target === null) return providerFailure("unavailable");
      this.busy = true;
      try {
        return await fetchPinnedProvider(container, revision, payload, request.imageSha256, target);
      } finally {
        this.busy = false;
      }
    } catch {
      return providerFailure("unavailable");
    }
  }

  async probeApiStatus(input: ProviderApiStatusInput): Promise<ProviderApiStatusResult> {
    try {
      const request = providerApiStatusRequest(input);
      if (request === null) return apiStatusFailure("invalid-request");
      const revision = this.env.BUILD_REVISION;
      if (request.providerRevision !== revision) return apiStatusFailure("unavailable");
      const singleton = this.ctx.exports.ProviderContainer.idFromName(SINGLETON);
      const container = this.ctx.container;
      if (!this.ctx.id.equals(singleton) || !container) return apiStatusFailure("unavailable");
      if (this.busy) return apiStatusFailure("busy");
      this.busy = true;
      try {
        return await probePinnedProviderApiStatus(container, request);
      } finally {
        this.busy = false;
      }
    } catch {
      return apiStatusFailure("unavailable");
    }
  }

  async probeApiStatusV2(input: ProviderApiStatusV2Input): Promise<ProviderApiStatusResult> {
    try {
      const request = providerApiStatusV2Request(input);
      if (!request) return apiStatusFailure("invalid-request");
      if (request.providerRevision !== this.env.BUILD_REVISION) return apiStatusFailure("unavailable");
      if (providerApiStatusV2Expired(request.dispatchBeforeMs)) return apiStatusFailure("timeout");
      const singleton = this.ctx.exports.ProviderContainer.idFromName(SINGLETON);
      const container = this.ctx.container;
      if (!this.ctx.id.equals(singleton) || !container) return apiStatusFailure("unavailable");
      if (this.busy) return apiStatusFailure("busy");
      this.busy = true;
      try {
        return await probePinnedProviderApiStatusV2(container, request);
      } finally {
        this.busy = false;
      }
    } catch {
      return apiStatusFailure("unavailable");
    }
  }

  async prove(probe: Probe) {
    const revision = this.env.BUILD_REVISION;
    const singleton = this.ctx.exports.ProviderContainer.idFromName(SINGLETON);
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
      // Store fixed stage/stop diagnostics only; platform errors can contain request data.
      return { ok: false, stage: error instanceof ProviderProbeError ? error.stage : "admission",
        ...(error instanceof ProviderProbeError && error.stop ? { stop: error.stop } : {}) };
    } finally {
      this.busy = false;
    }
  }

  async proveRelease(probe: ReleaseProbe) {
    const revision = this.env.BUILD_REVISION;
    const target = readProviderRuntimeTarget(this.env.PROVIDER_TARGET_JSON);
    const singleton = this.ctx.exports.ProviderContainer.idFromName(SINGLETON);
    if (!target || !this.ctx.id.equals(singleton) || !validReleaseProbe(probe, revision) || this.busy || !this.ctx.container) {
      throw new Error("Provider release smoke admission rejected.");
    }
    this.busy = true;
    try {
      const key = `release-smoke:${revision}:${probe.imageSha256}`;
      if (await this.ctx.storage.get(key)) throw new Error("Provider release smoke was already admitted.");
      await this.ctx.storage.put(key, true);
      return await exerciseProviderRelease(this.ctx.container, revision, probe.imageSha256, target,
        probe.healthUrl, probe.healthRevision, probe.healthSha256);
    } catch (error) {
      return { ok: false, stage: error instanceof ProviderProbeError ? error.stage : "admission",
        ...(error instanceof ProviderProbeError && error.stop ? { stop: error.stop } : {}) };
    } finally { this.busy = false; }
  }
}

interface ReleaseProbe {
  providerRevision: string; imageSha256: string; healthUrl: string; healthRevision: string; healthSha256: string;
}

function validReleaseProbe(probe: ReleaseProbe, revision: string): boolean {
  return typeof probe === "object" && probe !== null && Object.keys(probe).length === 5
    && REVISION.test(revision) && probe.providerRevision === revision
    && typeof probe.imageSha256 === "string" && /^[0-9a-f]{64}(?![\s\S])/u.test(probe.imageSha256)
    && typeof probe.healthRevision === "string" && REVISION.test(probe.healthRevision)
    && typeof probe.healthSha256 === "string" && /^[0-9a-f]{64}(?![\s\S])/u.test(probe.healthSha256)
    && typeof probe.healthUrl === "string" && /^https:\/\/[a-z0-9.-]+\/health(?![\s\S])/u.test(probe.healthUrl);
}

export class ProviderReleaseSmoke extends WorkflowEntrypoint<Env, ReleaseProbe> {
  async run(event: WorkflowEvent<ReleaseProbe>, step: WorkflowStep) {
    const target = readProviderRuntimeTarget(this.env.PROVIDER_TARGET_JSON);
    if (!target || !validReleaseProbe(event.payload, this.env.BUILD_REVISION)
      || event.workflowName !== target.service + "-smoke"
      || event.instanceId !== `provider-release-${this.env.BUILD_REVISION}`) throw new Error("Provider release smoke target differs.");
    const egress = await step.do("verify approved provider release", { retries: { limit: 0, delay: "1 second" }, timeout: "150 seconds" }, async () => {
      return this.ctx.exports.ProviderContainer.getByName(SINGLETON).proveRelease(event.payload);
    });
    if (!egress.ok || !("imageSha256" in egress)) return egress;
    await step.do("verify exact named ProviderFetch RPC", { retries: { limit: 0, delay: "1 second" }, timeout: "75 seconds" }, async () => {
      const result = await this.ctx.exports.ProviderFetch.fetchSubscription({ url: event.payload.healthUrl,
        providerRevision: event.payload.providerRevision, imageSha256: event.payload.imageSha256 });
      if (!result.ok || result.bodySha256 !== event.payload.healthSha256 || result.body.byteLength !== egress.healthBytes) {
        throw new Error("The exact named ProviderFetch RPC did not return the approved health fixture.");
      }
    });
    return { ...egress, rpcVerified: true };
  }
}

export class ProviderFetch extends WorkerEntrypoint<Env> implements ProviderApiStatusProber, ProviderApiStatusV2Prober {
  async fetchSubscription(input: ProviderFetchInput): Promise<ProviderFetchResult> {
    try {
      const request = providerRequest(input);
      if (request === null) return providerFailure("invalid-request");
      if (request.providerRevision !== this.env.BUILD_REVISION) return providerFailure("unavailable");
      return await this.ctx.exports.ProviderContainer.getByName(SINGLETON).fetchSubscription(request);
    } catch {
      return providerFailure("unavailable");
    }
  }

  async probeApiStatus(input: ProviderApiStatusInput): Promise<ProviderApiStatusResult> {
    try {
      const request = providerApiStatusRequest(input);
      if (request === null) return apiStatusFailure("invalid-request");
      if (request.providerRevision !== this.env.BUILD_REVISION) return apiStatusFailure("unavailable");
      const container = this.ctx.exports.ProviderContainer.getByName(SINGLETON);
      return providerApiStatusResult(await container.probeApiStatus(request));
    } catch {
      return apiStatusFailure("unavailable");
    }
  }

  async probeApiStatusV2(input: ProviderApiStatusV2Input): Promise<ProviderApiStatusResult> {
    try {
      const request = providerApiStatusV2Request(input);
      if (!request) return apiStatusFailure("invalid-request");
      if (request.providerRevision !== this.env.BUILD_REVISION) return apiStatusFailure("unavailable");
      if (providerApiStatusV2Expired(request.dispatchBeforeMs)) return apiStatusFailure("timeout");
      const container = this.ctx.exports.ProviderContainer.getByName(SINGLETON);
      return providerApiStatusResult(await container.probeApiStatusV2(request));
    } catch {
      return apiStatusFailure("unavailable");
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
        const container = this.ctx.exports.ProviderContainer.getByName(SINGLETON);
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
