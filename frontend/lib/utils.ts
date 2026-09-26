import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Merge Tailwind classes safely — use instead of raw `clsx` when Tailwind classes may conflict. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** Format an ISO timestamp to a readable local time string. */
export function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

/** Format an ISO timestamp to a readable date string. */
export function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString([], {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

/** Human-readable duration from milliseconds. */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
}

/** Severity to a numeric rank for sorting (higher = more severe). */
export function severityRank(sev: string): number {
  const order: Record<string, number> = {
    critical: 5, high: 4, medium: 3, low: 2, info: 1,
  };
  return order[sev.toLowerCase()] ?? 0;
}

/** Truncate a string to maxLen, adding ellipsis. */
export function truncate(s: string, maxLen = 80): string {
  return s.length > maxLen ? s.slice(0, maxLen - 1) + "…" : s;
}
