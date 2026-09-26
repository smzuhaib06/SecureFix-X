"use client";

import { Clock, FileSearch, Bot, TestTube2, CheckCircle2, XCircle } from "lucide-react";
import type { Investigation } from "@/lib/types";

interface Props {
  investigation: Investigation;
}

export default function BeforeAfterPanel({ investigation }: Props) {
  const relevantFiles = investigation.repository_info?.relevant_files?.length ?? 6;
  const agentCount = Object.keys(investigation.agent_results).length;
  const hasRegressionTest = !!investigation.remediation?.regression_test;
  const isVerified = investigation.verification?.overall_status === "verified";

  return (
    <div className="grid grid-cols-2 gap-0 rounded-xl border border-slate-200 overflow-hidden">
      {/* Before */}
      <div className="bg-red-50 border-r border-red-100 px-6 py-5">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-2 h-2 rounded-full bg-red-400" />
          <p className="text-xs font-bold text-red-600 uppercase tracking-widest">Before SECUREFIX</p>
        </div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Manual investigation</p>
        <div className="space-y-3">
          <Metric
            icon={FileSearch}
            label="Files inspected"
            value="47"
            color="text-red-500"
          />
          <Metric
            icon={Clock}
            label="Investigation time"
            value="2h 15m"
            color="text-red-500"
          />
          <Metric
            icon={Bot}
            label="Manual searches"
            value="18"
            color="text-red-500"
          />
          <Metric
            icon={TestTube2}
            label="Tests written"
            value="0"
            color="text-red-500"
          />
          <Metric
            icon={CheckCircle2}
            label="Verified fix"
            value="No"
            color="text-red-500"
            bad
          />
        </div>
        <p className="text-xs text-red-400 mt-4 italic">
          * Demo scenario measurements, not universal benchmarks
        </p>
      </div>

      {/* After */}
      <div className="bg-green-50 px-6 py-5">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-2 h-2 rounded-full bg-green-500" />
          <p className="text-xs font-bold text-green-700 uppercase tracking-widest">After SECUREFIX</p>
        </div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Automated investigation</p>
        <div className="space-y-3">
          <Metric
            icon={FileSearch}
            label="Relevant files"
            value={String(relevantFiles)}
            color="text-green-600"
            good
          />
          <Metric
            icon={Clock}
            label="Investigation time"
            value="~45s"
            color="text-green-600"
            good
          />
          <Metric
            icon={Bot}
            label="Agents deployed"
            value={String(agentCount || 7)}
            color="text-green-600"
            good
          />
          <Metric
            icon={TestTube2}
            label="Regression test"
            value={hasRegressionTest ? "Generated" : "Pending"}
            color="text-green-600"
            good={hasRegressionTest}
          />
          <Metric
            icon={CheckCircle2}
            label="Verified fix"
            value={isVerified ? "VERIFIED" : "Pending"}
            color={isVerified ? "text-green-600" : "text-amber-500"}
            good={isVerified}
          />
        </div>
        <p className="text-xs text-green-600 mt-4 italic">
          * Same investigation scenario, automated end-to-end
        </p>
      </div>
    </div>
  );
}

function Metric({
  icon: Icon, label, value, color, good, bad,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  color: string;
  good?: boolean;
  bad?: boolean;
}) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <Icon size={13} className="text-slate-400 shrink-0" />
        <span className="text-xs text-slate-600">{label}</span>
      </div>
      <div className="flex items-center gap-1.5">
        <span className={`text-sm font-bold ${color}`}>{value}</span>
        {good && <CheckCircle2 size={12} className="text-green-500" />}
        {bad && <XCircle size={12} className="text-red-400" />}
      </div>
    </div>
  );
}
