import { clsx } from "clsx";
import type { Severity, InvestigationStatus, AgentStatus } from "@/lib/types";

const severityStyles: Record<Severity, string> = {
  critical: "bg-red-100 text-red-700 border border-red-200",
  high:     "bg-orange-100 text-orange-700 border border-orange-200",
  medium:   "bg-amber-100 text-amber-700 border border-amber-200",
  low:      "bg-green-100 text-green-700 border border-green-200",
  info:     "bg-sky-100 text-sky-700 border border-sky-200",
};

const statusStyles: Record<string, string> = {
  pending:           "bg-slate-100 text-slate-600",
  running:           "bg-blue-100 text-blue-700",
  awaiting_approval: "bg-amber-100 text-amber-700",
  applying:          "bg-indigo-100 text-indigo-700",
  verifying:         "bg-purple-100 text-purple-700",
  completed:         "bg-green-100 text-green-700",
  failed:            "bg-red-100 text-red-700",
  // agent statuses
  skipped:           "bg-slate-100 text-slate-500",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={clsx(
      "inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide",
      severityStyles[severity] ?? severityStyles.info,
    )}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const label = status.replace(/_/g, " ");
  return (
    <span className={clsx(
      "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium capitalize",
      statusStyles[status] ?? "bg-slate-100 text-slate-600",
    )}>
      {status === "running" && (
        <span className="w-1.5 h-1.5 rounded-full bg-blue-500 mr-1.5 pulse-dot" />
      )}
      {label}
    </span>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: number }) {
  const pct = Math.round(confidence * 100);
  const color =
    pct >= 85 ? "text-green-700 bg-green-50 border-green-200" :
    pct >= 60 ? "text-amber-700 bg-amber-50 border-amber-200" :
                "text-slate-600 bg-slate-50 border-slate-200";
  return (
    <span className={clsx(
      "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
      color,
    )}>
      {pct}% confidence
    </span>
  );
}
