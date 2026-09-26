"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { FileText, Download, ArrowRight, CheckCircle2, Clock } from "lucide-react";
import Sidebar from "@/components/layout/Sidebar";
import { Card, CardBody } from "@/components/ui/Card";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import type { InvestigationSummary } from "@/lib/types";

export default function ReportsPage() {
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listInvestigations()
      .then((invs) => setInvestigations(invs.filter((i) => i.status === "completed")))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <header className="bg-white border-b border-slate-200 px-8 py-5">
          <h1 className="text-xl font-bold text-slate-900">Reports</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Remediation reports for completed investigations
          </p>
        </header>

        <main className="flex-1 px-8 py-6">
          {loading ? (
            <div className="space-y-3">
              {[1, 2].map((i) => (
                <div key={i} className="h-20 bg-white rounded-lg border border-slate-200 animate-pulse" />
              ))}
            </div>
          ) : investigations.length === 0 ? (
            <Card>
              <CardBody className="text-center py-14">
                <FileText size={32} className="text-slate-300 mx-auto mb-3" />
                <p className="text-sm font-medium text-slate-500">No completed investigations yet</p>
                <p className="text-xs text-slate-400 mt-1">
                  Reports are generated automatically when an investigation is verified.
                </p>
                <Link
                  href="/investigations/new"
                  className="mt-4 inline-flex items-center gap-2 text-sm text-blue-600 hover:underline font-medium"
                >
                  Start an investigation →
                </Link>
              </CardBody>
            </Card>
          ) : (
            <Card>
              <div className="divide-y divide-slate-100">
                <div className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-4 px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wide">
                  <span>Investigation</span>
                  <span>Severity</span>
                  <span>Status</span>
                  <span>Date</span>
                  <span>Report</span>
                </div>
                {investigations.map((inv) => (
                  <div
                    key={inv.id}
                    className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-4 items-center px-5 py-4 hover:bg-slate-50 transition-colors"
                  >
                    <div className="min-w-0">
                      <Link
                        href={`/investigations/${inv.id}`}
                        className="text-sm font-medium text-slate-800 hover:text-blue-600 truncate block"
                      >
                        {inv.title}
                      </Link>
                      <p className="text-xs text-slate-400 mt-0.5 font-mono">{inv.id}</p>
                    </div>
                    <div>
                      {inv.severity
                        ? <SeverityBadge severity={inv.severity} />
                        : <span className="text-xs text-slate-300">—</span>}
                    </div>
                    <div><StatusBadge status={inv.status} /></div>
                    <div className="text-xs text-slate-400">
                      {new Date(inv.created_at).toLocaleDateString()}
                    </div>
                    <div className="flex items-center gap-2">
                      <a
                        href={api.reportUrl(inv.id)}
                        download
                        className="flex items-center gap-1.5 text-xs text-blue-600 hover:text-blue-800 border border-blue-200 hover:border-blue-400 px-3 py-1.5 rounded-lg transition-colors font-medium"
                      >
                        <Download size={12} />
                        .md
                      </a>
                      <Link
                        href={`/investigations/${inv.id}`}
                        className="text-slate-300 hover:text-slate-500"
                      >
                        <ArrowRight size={14} />
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Report format explanation */}
          {investigations.length > 0 && (
            <div className="mt-6 bg-blue-50 border border-blue-100 rounded-lg px-5 py-4">
              <p className="text-xs font-semibold text-blue-700 mb-2">Report Contents</p>
              <div className="grid grid-cols-3 gap-4 text-xs text-blue-600">
                {[
                  "Executive Summary",
                  "Finding & Severity",
                  "Root Cause Analysis",
                  "Attack / Failure Path",
                  "Affected Components",
                  "Agent Findings",
                  "Evidence Correlation",
                  "Code Patch (diff)",
                  "Regression Test",
                  "Verification Results",
                  "Investigation Timeline",
                  "Residual Risk",
                ].map((item) => (
                  <div key={item} className="flex items-center gap-1.5">
                    <CheckCircle2 size={11} className="text-blue-400 shrink-0" />
                    {item}
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
