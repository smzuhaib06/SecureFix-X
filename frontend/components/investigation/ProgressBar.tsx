"use client";

import { clsx } from "clsx";

interface Props {
  pct: number;
  status: string;
  showLabel?: boolean;
  className?: string;
}

export default function ProgressBar({ pct, status, showLabel = false, className }: Props) {
  const barColor =
    status === "completed"    ? "bg-green-500" :
    status === "failed"       ? "bg-red-400"   :
    status === "awaiting_approval" ? "bg-amber-400" :
    status === "verifying"    ? "bg-purple-500" :
                                "bg-blue-500";

  return (
    <div className={clsx("w-full", className)}>
      {showLabel && (
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs text-slate-400 capitalize">{status.replace(/_/g, " ")}</span>
          <span className="text-xs font-medium text-slate-600">{pct}%</span>
        </div>
      )}
      <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
        <div
          className={clsx("h-full rounded-full transition-all duration-500", barColor)}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
