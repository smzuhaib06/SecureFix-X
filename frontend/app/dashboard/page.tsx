"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import {
  Search, ShieldAlert, CheckCircle2, Award,
  TrendingDown, ArrowRight, Plus, Play, RefreshCw,
} from "lucide-react";
import Sidebar from "@/components/layout/Sidebar";
import { Card, CardBody } from "@/components/ui/Card";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import type { DashboardStats, InvestigationSummary } from "@/lib/types";

const AGENTS = [
  "Repository Intelligence",
  "Security Investigation",
  "Code Analysis",
  "Dependency Analysis",
  "Configuration Analysis",
  "Test Coverage",
  "Runtime & Logs",
];

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    else setRefreshing(true);
    try {
      const [s, invs] = await Promise.all([api.getDashboardStats(), api.listInvestigations()]);
      setStats(s);
      setInvestigations(invs.slice(0, 5));
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Auto-refresh every 5s if any investigation is active
  useEffect(() => {
    const hasActive = investigations.some((i) =>
      ["pending", "running", "applying", "verifying"].includes(i.status)
    );
    if (!hasActive) return;
    const id = setInterval(() => load(true), 5000);
    return () => clearInterval(id);
  }, [investigations, load]);

  const statCards = stats
    ? [
        { label: "Active Investigations", value: stats.active_investigations,   icon: Search,       color: "text-blue-600",  bg: "bg-blue-50"   },
        { label: "Critical Findings",     value: stats.critical_findings,       icon: ShieldAlert,  color: "text-red-600",   bg: "bg-red-50"    },
        { label: "Issues Fixed",          value: stats.issues_fixed,            icon: CheckCircle2, color: "text-green-600", bg: "bg-green-50"  },
        { label: "Verified Remediations", value: stats.verified_remediations,   icon: Award,        color: "text-indigo-600",bg: "bg-indigo-50" },
      ]
    : [];

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <header className="bg-white border-b border-slate-200 px-8 py-5">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-xl font-bold text-slate-900">Dashboard</h1>
              <p className="text-sm text-slate-500 mt-0.5">Security investigation overview</p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => load(true)}
                disabled={refreshing}
                className="p-2 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded-lg transition-colors"
                title="Refresh"
              >
                <RefreshCw size={15} className={refreshing ? "animate-spin" : ""} />
              </button>
              <Link
                href="/demo"
                className="flex items-center gap-2 bg-slate-100 text-slate-700 px-4 py-2.5 rounded-lg text-sm font-semibold hover:bg-slate-200 transition-colors"
              >
                <Play size={13} />
                Live Demo
              </Link>
              <Link
                href="/investigations/new"
                className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2.5 rounded-lg text-sm font-semibold hover:bg-blue-700 transition-colors"
              >
                <Plus size={15} />
                New Investigation
              </Link>
            </div>
          </div>
        </header>

        <main className="flex-1 px-8 py-6 space-y-6">
          {/* Stat cards */}
          <div className="grid grid-cols-4 gap-4">
            {loading
              ? Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="h-24 bg-white rounded-lg border border-slate-200 animate-pulse" />
                ))
              : statCards.map((s) => (
                  <Card key={s.label}>
                    <CardBody className="flex items-center gap-4">
                      <div className={`w-10 h-10 rounded-lg ${s.bg} flex items-center justify-center shrink-0`}>
                        <s.icon size={18} className={s.color} />
                      </div>
                      <div>
                        <p className="text-2xl font-bold text-slate-900">{s.value}</p>
                        <p className="text-xs text-slate-500 mt-0.5">{s.label}</p>
                      </div>
                    </CardBody>
                  </Card>
                ))}
          </div>

          <div className="grid grid-cols-3 gap-6">
            {/* Recent investigations */}
            <div className="col-span-2">              <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-slate-700">Recent Investigations</h2>
                <Link href="/investigations" className="text-xs text-blue-600 hover:underline flex items-center gap-1">
                  View all <ArrowRight size={12} />
                </Link>
              </div>
              <Card>
                {investigations.length === 0 && !loading ? (
                  <CardBody>
                    <div className="text-center py-8">
                      <p className="text-sm text-slate-500">No investigations yet.</p>
                      <Link
                        href="/investigations/new"
                        className="mt-3 inline-flex items-center gap-1.5 text-sm text-blue-600 hover:underline font-medium"
                      >
                        <Plus size={14} /> Start your first investigation
                      </Link>
                    </div>
                  </CardBody>
                ) : (
                  <div className="divide-y divide-slate-100">
                    {investigations.map((inv) => (
                      <Link
                        key={inv.id}
                        href={`/investigations/${inv.id}`}
                        className="flex items-center gap-4 px-5 py-3.5 hover:bg-slate-50 transition-colors"
                      >
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-slate-800 truncate">{inv.title}</p>
                          <p className="text-xs text-slate-400 mt-0.5">{inv.id}</p>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {inv.severity && <SeverityBadge severity={inv.severity} />}
                          <StatusBadge status={inv.status} />
                        </div>
                        {/* Progress bar */}
                        <div className="w-16 shrink-0">
                          <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-blue-500 rounded-full transition-all"
                              style={{ width: `${inv.progress_pct}%` }}
                            />
                          </div>
                        </div>
                        <ArrowRight size={14} className="text-slate-300" />
                      </Link>
                    ))}
                  </div>
                )}
              </Card>
            </div>

            {/* Demo metrics + Agents */}
            <div className="space-y-4">
              {stats && (
                <Card>
                  <CardBody>
                    <div className="flex items-center gap-2 mb-3">
                      <TrendingDown size={16} className="text-green-600" />
                      <p className="text-sm font-semibold text-slate-700">Demo Metrics</p>
                    </div>
                    <p className="text-xs text-slate-400 mb-3 italic">
                      Measurements from demonstration scenario
                    </p>
                    <div className="space-y-2">
                      <MetricRow
                        label="Investigation time"
                        before="Manual: 2h 15m"
                        after={`↓ ${stats.demo_metrics.avg_investigation_time_reduction_pct}%`}
                      />
                      <MetricRow
                        label="Files inspected"
                        before={`Manual: ${stats.demo_metrics.avg_files_inspected_before}`}
                        after={`AI: ${stats.demo_metrics.avg_relevant_files_securefix}`}
                      />
                      <MetricRow
                        label="Workflow steps"
                        before={`Before: ${stats.demo_metrics.manual_steps_before}`}
                        after={`After: ${stats.demo_metrics.automated_steps_after}`}
                      />
                    </div>
                  </CardBody>
                </Card>
              )}

              <Card>
                <CardBody>
                  <div className="flex items-center gap-2 mb-3">
                    <Play size={15} className="text-blue-600" />
                    <p className="text-sm font-semibold text-slate-700">Hackathon Demo</p>
                  </div>
                  <p className="text-xs text-slate-500 mb-3 leading-relaxed">
                    Walk through the SecureBank BOLA vulnerability detection,
                    fix, and verification scenario step by step.
                  </p>
                  <Link
                    href="/demo"
                    className="flex items-center gap-2 bg-blue-600 text-white px-3 py-2 rounded-lg text-xs font-semibold hover:bg-blue-700 transition-colors w-full justify-center"
                  >
                    <Play size={12} />
                    Start Live Demo
                  </Link>
                </CardBody>
              </Card>

              <Card>
                <CardBody>
                  <p className="text-sm font-semibold text-slate-700 mb-3">Available Agents</p>
                  <div className="space-y-1.5">
                    {AGENTS.map((a) => (
                      <div key={a} className="flex items-center gap-2 text-xs text-slate-600">
                        <span className="w-1.5 h-1.5 rounded-full bg-green-400 shrink-0" />
                        {a}
                      </div>
                    ))}
                  </div>
                </CardBody>
              </Card>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

function MetricRow({ label, before, after }: { label: string; before: string; after: string }) {
  return (
    <div className="text-xs">
      <p className="text-slate-500 mb-0.5">{label}</p>
      <div className="flex items-center gap-2">
        <span className="text-slate-400 line-through">{before}</span>
        <span className="text-green-600 font-semibold">{after}</span>
      </div>
    </div>
  );
}
