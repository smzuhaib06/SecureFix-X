"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Plus, ArrowRight, Search, Trash2 } from "lucide-react";
import Sidebar from "@/components/layout/Sidebar";
import { Card } from "@/components/ui/Card";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import type { InvestigationSummary } from "@/lib/types";

export default function InvestigationsPage() {
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    api.listInvestigations()
      .then(setInvestigations)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    await api.deleteInvestigation(id);
    load();
  };

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <header className="bg-white border-b border-slate-200 px-8 py-5">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-xl font-bold text-slate-900">Investigations</h1>
              <p className="text-sm text-slate-500 mt-0.5">
                {investigations.length} investigation{investigations.length !== 1 ? "s" : ""}
              </p>
            </div>
            <div className="flex items-center gap-3">
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

        <main className="flex-1 px-8 py-6">
          {loading ? (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="h-20 bg-white rounded-lg border border-slate-200 animate-pulse" />
              ))}
            </div>
          ) : investigations.length === 0 ? (
            <Card>
              <div className="text-center py-16">
                <Search size={32} className="text-slate-300 mx-auto mb-3" />
                <p className="text-slate-500 font-medium">No investigations yet</p>
                <p className="text-sm text-slate-400 mt-1">Start by submitting a security finding.</p>
                <Link
                  href="/investigations/new"
                  className="mt-4 inline-flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-blue-700 transition-colors"
                >
                  <Plus size={14} />
                  New Investigation
                </Link>
              </div>
            </Card>
          ) : (
            <Card>
              <div className="divide-y divide-slate-100">
                {/* Table header */}
                <div className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-4 px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wide">
                  <span>Investigation</span>
                  <span>Severity</span>
                  <span>Status</span>
                  <span>Progress</span>
                  <span></span>
                </div>

                {investigations.map((inv) => (
                  <Link
                    key={inv.id}
                    href={`/investigations/${inv.id}`}
                    className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-4 items-center px-5 py-4 hover:bg-slate-50 transition-colors group"
                  >
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-slate-800 truncate">{inv.title}</p>
                      <p className="text-xs text-slate-400 mt-0.5">
                        {inv.id} · {new Date(inv.created_at).toLocaleDateString()}
                      </p>
                    </div>
                    <div>{inv.severity ? <SeverityBadge severity={inv.severity} /> : <span className="text-xs text-slate-300">—</span>}</div>
                    <div><StatusBadge status={inv.status} /></div>
                    <div className="w-24">
                      <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-blue-500 rounded-full transition-all"
                          style={{ width: `${inv.progress_pct}%` }}
                        />
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5 text-right">{inv.progress_pct}%</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={(e) => handleDelete(inv.id, e)}
                        className="p-1.5 rounded text-slate-300 hover:text-red-400 hover:bg-red-50 transition-colors opacity-0 group-hover:opacity-100"
                      >
                        <Trash2 size={13} />
                      </button>
                      <ArrowRight size={14} className="text-slate-300 group-hover:text-slate-500 transition-colors" />
                    </div>
                  </Link>
                ))}
              </div>
            </Card>
          )}
        </main>
      </div>
    </div>
  );
}
