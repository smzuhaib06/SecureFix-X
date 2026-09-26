"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { CheckCircle2, XCircle, ShieldCheck, ShieldX, ArrowRight } from "lucide-react";
import Sidebar from "@/components/layout/Sidebar";
import { Card, CardBody } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import type { Investigation } from "@/lib/types";
import { clsx } from "clsx";

export default function VerificationPage() {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listInvestigations().then(async (summaries) => {
      const full = await Promise.all(
        summaries
          .filter((s) => s.status === "completed")
          .map((s) => api.getInvestigation(s.id).catch(() => null))
      );
      setInvestigations(full.filter((i): i is Investigation => i !== null && !!i.verification));
    }).catch(console.error).finally(() => setLoading(false));
  }, []);

  const verified = investigations.filter((i) => i.verification?.overall_status === "verified");
  const failed   = investigations.filter((i) => i.verification?.overall_status !== "verified");

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <header className="bg-white border-b border-slate-200 px-8 py-5">
          <h1 className="text-xl font-bold text-slate-900">Verification</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Post-remediation verification results
          </p>
        </header>

        <main className="flex-1 px-8 py-6 space-y-6">
          {/* Summary cards */}
          <div className="grid grid-cols-3 gap-4">
            <SummaryCard
              icon={ShieldCheck}
              label="Verified"
              value={verified.length}
              color="text-green-600"
              bg="bg-green-50"
            />
            <SummaryCard
              icon={ShieldX}
              label="Needs Review"
              value={failed.length}
              color="text-red-500"
              bg="bg-red-50"
            />
            <SummaryCard
              icon={CheckCircle2}
              label="Total Verified"
              value={investigations.length}
              color="text-blue-600"
              bg="bg-blue-50"
            />
          </div>

          {loading ? (
            <div className="space-y-3">
              {[1, 2].map((i) => (
                <div key={i} className="h-28 bg-white rounded-lg border border-slate-200 animate-pulse" />
              ))}
            </div>
          ) : investigations.length === 0 ? (
            <Card>
              <CardBody className="text-center py-14">
                <ShieldCheck size={32} className="text-slate-300 mx-auto mb-3" />
                <p className="text-sm text-slate-500">No verification results yet.</p>
                <Link href="/investigations/new" className="mt-3 text-sm text-blue-600 hover:underline inline-block">
                  Start an investigation →
                </Link>
              </CardBody>
            </Card>
          ) : (
            <Card>
              <div className="divide-y divide-slate-100">
                {investigations.map((inv) => {
                  const v = inv.verification!;
                  const isVerified = v.overall_status === "verified";
                  return (
                    <div key={inv.id} className="px-5 py-4 hover:bg-slate-50 transition-colors">
                      <div className="flex items-start gap-4">
                        <div className={clsx(
                          "w-9 h-9 rounded-lg flex items-center justify-center shrink-0 mt-0.5",
                          isVerified ? "bg-green-50" : "bg-red-50",
                        )}>
                          {isVerified
                            ? <ShieldCheck size={16} className="text-green-600" />
                            : <ShieldX size={16} className="text-red-500" />}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <Link
                              href={`/investigations/${inv.id}?tab=verification`}
                              className="text-sm font-semibold text-slate-800 hover:text-blue-600 truncate"
                            >
                              {inv.title}
                            </Link>
                            {inv.severity && <SeverityBadge severity={inv.severity} />}
                          </div>
                          <p className="text-xs text-slate-500 mb-3">{v.summary}</p>
                          {/* Check grid */}
                          <div className="grid grid-cols-2 md:grid-cols-3 gap-1.5">
                            {v.checks.map((check, i) => (
                              <div key={i} className="flex items-center gap-1.5 text-xs text-slate-600">
                                {check.status === "passed"
                                  ? <CheckCircle2 size={11} className="text-green-500 shrink-0" />
                                  : check.status === "skipped"
                                  ? <span className="w-3 h-3 rounded-full border border-slate-300 inline-block shrink-0" />
                                  : <XCircle size={11} className="text-red-400 shrink-0" />}
                                <span className="truncate">{check.name}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                        <div className="flex items-center gap-3 shrink-0">
                          <span className={clsx(
                            "text-xs font-bold px-2.5 py-1 rounded uppercase tracking-wide",
                            isVerified
                              ? "bg-green-100 text-green-700"
                              : "bg-red-100 text-red-700",
                          )}>
                            {v.overall_status}
                          </span>
                          <Link href={`/investigations/${inv.id}`} className="text-slate-300 hover:text-slate-500">
                            <ArrowRight size={14} />
                          </Link>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </Card>
          )}
        </main>
      </div>
    </div>
  );
}

function SummaryCard({
  icon: Icon, label, value, color, bg,
}: {
  icon: React.ElementType;
  label: string;
  value: number;
  color: string;
  bg: string;
}) {
  return (
    <Card>
      <CardBody className="flex items-center gap-4">
        <div className={`w-10 h-10 rounded-lg ${bg} flex items-center justify-center shrink-0`}>
          <Icon size={18} className={color} />
        </div>
        <div>
          <p className="text-2xl font-bold text-slate-900">{value}</p>
          <p className="text-xs text-slate-500 mt-0.5">{label}</p>
        </div>
      </CardBody>
    </Card>
  );
}
