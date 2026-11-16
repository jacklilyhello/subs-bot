/** One bounded subscription-fetch lifecycle, including cold allocation and cleanup.
 * Startup covers the start RPC/inactivity ACK and HTTP readiness together.
 * The caller deadline and live lease leave time for parsing and publication.
 * API-status V2's independent dispatch deadline is deliberately unchanged.
 */
export const PROVIDER_STARTUP_MS = 120_000;
export const PROVIDER_FETCH_MS = 28_000;
export const PROVIDER_STOP_MS = 10_000;
export const PROVIDER_FORCE_CLEANUP_MS = 10_000;
export const PROVIDER_RPC_TIMEOUT_MS = 180_000;
export const PROVIDER_LEASE_HEADROOM_MS = 210_000;
export const PROVIDER_LEASE_SECONDS = 240;

export const RELEASE_EGRESS_SECONDS = 300;
export const RELEASE_RPC_SECONDS = 210;
export const RELEASE_POLL_SECONDS = 600;
