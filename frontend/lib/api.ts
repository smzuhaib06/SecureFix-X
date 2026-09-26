import type {
  DashboardStats,
  Investigation,
  InvestigationSummary,
} from "./types";

const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  // Investigations
  listInvestigations: () =>
    req<InvestigationSummary[]>("/api/investigations"),

  getInvestigation: (id: string) =>
    req<Investigation>(`/api/investigations/${id}`),

  createInvestigation: (payload: {
    title: string;
    issue_description: string;
    repository_path?: string;
    repository_url?: string;
  }) =>
    req<Investigation>("/api/investigations", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  deleteInvestigation: (id: string) =>
    fetch(`${BASE}/api/investigations/${id}`, { method: "DELETE" }),

  approveRemediation: (id: string, approved: boolean, comment?: string) =>
    req<Investigation>(`/api/investigations/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ approved, comment }),
    }),

  // Demo shortcut
  createDemoInvestigation: () =>
    req<Investigation>("/api/demo/create-investigation", { method: "POST" }),

  // Dashboard
  getDashboardStats: () => req<DashboardStats>("/api/dashboard/stats"),

  // SSE stream URL (consumed directly by EventSource)
  streamUrl: (id: string) => `${BASE}/api/investigations/${id}/stream`,

  // Report download URL
  reportUrl: (id: string) => `${BASE}/api/investigations/${id}/report`,
};
