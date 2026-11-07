export const PROVIDER_REVISION = /^[a-f0-9]{40}(?![\s\S])/u;
export const PROVIDER_SHA256 = /^[a-f0-9]{64}(?![\s\S])/u;
export const PROVIDER_MAX_BODY_BYTES = 10 * 1024 * 1024;
export const PROVIDER_MAX_METADATA_BYTES = 3072;
export const PROVIDER_METADATA_FIELDS = ["content-type", "content-disposition", "profile-title", "subscription-userinfo"] as const;

export type ProviderMetadata = Partial<Record<typeof PROVIDER_METADATA_FIELDS[number], string>>;
export type ProviderFailureCode = "invalid-request" | "invalid-url" | "blocked-address" | "busy" | "invalid-auth"
  | "dns-failed" | "tls-failed" | "unavailable" | "timeout" | "invalid-redirect" | "redirect-limit" | "http-status"
  | "body-too-large" | "invalid-body";

export interface ProviderPin {
  providerRevision: string;
  imageSha256: string;
}

export interface ProviderFetchInput extends ProviderPin { url: string }

export type ProviderFetchResult =
  | { ok: true; body: ArrayBuffer; bodySha256: string; metadata?: ProviderMetadata }
  | { ok: false; code: ProviderFailureCode; retryable: boolean; upstreamStatus?: number };

export interface ProviderFetcher {
  fetchSubscription(input: ProviderFetchInput): Promise<ProviderFetchResult>;
}

export const PROVIDER_API_STATUS_MAX_ELAPSED_MS = 15_000;

export interface ProviderApiStatusInput extends ProviderPin { url: string; key: string }

export type ProviderApiStatusFailureCode = Extract<ProviderFailureCode, "invalid-request" | "invalid-url" | "invalid-auth"
  | "blocked-address" | "busy" | "dns-failed" | "tls-failed" | "unavailable" | "timeout" | "invalid-body">;

export type ProviderApiStatusResult =
  | { ok: true; status: number; elapsedMs: number }
  | { ok: false; code: ProviderApiStatusFailureCode };

export interface ProviderApiStatusProber {
  probeApiStatus(input: ProviderApiStatusInput): Promise<ProviderApiStatusResult>;
}
