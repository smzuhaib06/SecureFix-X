"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ShieldAlert, ArrowRight, Plus } from "lucide-react";
import Sidebar from "@/components/layout/Sidebar";
import { Card, CardBody } from "@/components/ui/Card";
import { SeverityBadge, ConfidenceBadge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import type { InvestigationSummary, Investigation, AgentFinding, Severity } from "@/lib/types";
import { clsx } from "clsx";

interface FlatFinding extends AgentFinding {
  investigationId: string;
  investigationTitle: string;
  agentName: string;
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function FindingsPage() {
  const [findings, setFindings] = useState<FlatFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<Severity | "all">("all");

  useEffect(() => {
    api.listInvestigations().then(async (summaries) => {
      const flat: FlatFinding[] = [];

      await Promise.all(
        summaries.map(async (s) => {
          try {
            const inv: Investigation = await api.getInvestigation(s.id);
            for (const [agentName, result] of Object.entries(inv.agent_results)) {
              for (const finding of result.findings) {
                flat.push({
                  ...finding,
                  investigationId: inv.id,
                  investigationTitle: inv.title,
                  agentName,
                });
              }
            }
          } catch {}
        })
      );

      // Sort by severity
      flat.sort((a, b) => {
        const ai = SEVERITY_ORDER.indexOf(a.severity);
        const bi = SEVERITY_ORDER.indexOf(b.severity);
        return ai - bi;
      });

      setFindings(flat);
    }).catch(console.error).finally(() => setLoading(false));
  }, []);

  const filtered = filter === "all"
    ? findings
    : findings.filter((f) => f.severity === filter);

  const counts = SEVERITY_ORDER.reduce((acc, sev) => {
    acc[sev] = findings.filter((f) => f.severity === sev).length;
    return acc;
  }, {} as Record<Severity, number>);

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <header className="bg-white border-b border-slate-200 px-8 py-5">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-xl font-bold text-slate-900">Findings</h1>
              <p className="text-sm text-slate-500 mt-0.5">
                {findings.length} finding{findings.length !== 1 ? "s" : ""} across all investigations
              </p>
            </div>
            <Link
              href="/investigations/new"
              className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2.5 rounded-lg text-sm font-semibold hover:bg-blue-700 transition-colors"
            >
              <Plus size={15} />
              New Investigation
            </Link>
          </div>
        </header>

        <main className="flex-1 px-8 py-6 space-y-4">
          {/* Severity filter bar */}
          <div className="flex items-center gap-2 flex-wrap">
            <FilterChip
              label={`All (${findings.length})`}
              active={filter === "all"}
              onClick={() => setFilter("all")}
            />
            {SEVERITY_ORDER.map((sev) => (
              counts[sev] > 0 && (
                <FilterChip
                  key={sev}
                  label={`${sev.charAt(0).toUpperCase() + sev.slice(1)} (${counts[sev]})`}
                  active={filter === sev}
                  onClick={() => setFilter(sev)}
                  severity={sev}
                />
              )
            ))}
          </div>

          {loading ? (
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-24 bg-white rounded-lg border border-slate-200 animate-pulse" />
              ))}
            </div>
          ) : filtered.length === 0 ? (
            <Card>
              <CardBody className="text-center py-14">
                <ShieldAlert size={32} className="text-slate-300 mx-auto mb-3" />
                <p className="text-sm text-slate-500">
                  {findings.length === 0
                    ? "No findings yet — start an investigation to see results."
                    : `No ${filter} findings.`}
                </p>
              </CardBody>
            </Card>
          ) : (
            <Card>
              <div className="divide-y divide-slate-100">
                {filtered.map((f, i) => (
                  <div key={i} className="px-5 py-4 hover:bg-slate-50 transition-colors">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                          <SeverityBadge severity={f.severity} />
                          <ConfidenceBadge confidence={f.confidence} />
                          <span className="text-xs text-slate-400 bg-slate-100 px-2 py-0.5 rounded font-mono">
                            {f.agentName.replace("_agent", "")}
                          </span>
                        </div>
                        <p className="text-sm font-semibold text-slate-800">{f.title}</p>
                        {f.root_cause && (
                          <p className="text-xs text-slate-500 mt-1 leading-relaxed line-clamp-2">
                            {f.root_cause}
                          </p>
                        )}
                        {f.files.length > 0 && (
                          <div className="flex items-center gap-2 mt-2 flex-wrap">
                            {f.files.slice(0, 3).map((file) => (
                              <code
                                key={file}
                                className="text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded"
                              >
                                {file.split("/").pop()}
                              </code>
                            ))}
                          </div>
                        )}
                        {f.evidence.length > 0 && (
                          <ul className="mt-2 space-y-0.5">
                            {f.evidence.slice(0, 2).map((ev, j) => (
                              <li key={j} className="text-xs text-slate-500 flex items-start gap-1.5">
                                <span className="text-slate-300 shrink-0 mt-0.5">›</span>
                                {ev}
                              </li>
                            ))}
                          </ul>
                        )}
                      </div>
                      <Link
                        href={`/investigations/${f.investigationId}?tab=evidence`}
                        className="shrink-0 flex items-center gap-1 text-xs text-slate-400 hover:text-blue-600 transition-colors"
                      >
                        <span className="hidden sm:block max-w-[120px] truncate text-right">
                          {f.investigationTitle}
                        </span>
                        <ArrowRight size={13} />
                      </Link>
                    </div>
                    {f.recommendation && (
                      <p className="mt-2 text-xs text-blue-700 bg-blue-50 rounded px-3 py-1.5">
                        💡 {f.recommendation}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </Card>
          )}
        </main>
      </div>
    </div>
  );
}

function FilterChip({
  label, active, onClick, severity,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  severity?: Severity;
}) {
  const severityActive: Record<Severity, string> = {
    critical: "bg-red-100 text-red-700 border-red-300",
    high:     "bg-orange-100 text-orange-700 border-orange-300",
    medium:   "bg-amber-100 text-amber-700 border-amber-300",
    low:      "bg-green-100 text-green-700 border-green-300",
    info:     "bg-sky-100 text-sky-700 border-sky-300",
  };

  return (
    <button
      onClick={onClick}
      className={clsx(
        "px-3 py-1.5 rounded-full text-xs font-medium border transition-colors",
        active
          ? severity
            ? severityActive[severity]
            : "bg-slate-900 text-white border-slate-900"
          : "bg-white text-slate-500 border-slate-200 hover:border-slate-300 hover:text-slate-700",
      )}
    >
      {label}
    </button>
  );
}
