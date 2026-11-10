export const ISOLATION_PUBLIC_ORIGIN = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
export const PRODUCTION_PUBLIC_ORIGIN = "https://subs-bot.lilyya.top";

export type PublicOrigin = typeof ISOLATION_PUBLIC_ORIGIN | typeof PRODUCTION_PUBLIC_ORIGIN;

export function parsePublicOrigin(value: unknown): PublicOrigin | null {
  if (value === undefined) return ISOLATION_PUBLIC_ORIGIN;
  return value === ISOLATION_PUBLIC_ORIGIN || value === PRODUCTION_PUBLIC_ORIGIN ? value : null;
}
