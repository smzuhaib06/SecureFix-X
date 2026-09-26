"use client";

import { CheckCircle2, XCircle, MinusCircle, ShieldCheck, ShieldX } from "lucide-react";
import type { VerificationResult } from "@/lib/types";
import { clsx } from "clsx";

interface Props {
  result: VerificationResult;
}

const statusIcon = (s: string) => {
  if (s === "passed") return <CheckCircle2 size={15} className="text-green-500 shrink-0" />;
  if (s === "failed") return <XCircle size={15} className="text-red-500 shrink-0" />;
  return <MinusCircle size={15} className="text-slate-400 shrink-0" />;
};

export default function VerificationPanel({ result }: Props) {
  const isVerified = result.overall_status === "verified";

  return (
    <div className="space-y-4">
      {/* Overall status banner */}
      <div className={clsx(
        "flex items-center gap-3 px-4 py-3 rounded-lg border",
        isVerified
          ? "bg-green-50 border-green-200"
          : result.overall_status === "partial"
          ? "bg-amber-50 border-amber-200"
          : "bg-red-50 border-red-200",
      )}>
        {isVerified
          ? <ShieldCheck size={20} className="text-green-600 shrink-0" />
          : <ShieldX size={20} className="text-red-500 shrink-0" />
        }
        <div>
          <p className={clsx(
            "font-semibold text-sm",
            isVerified ? "text-green-800" : "text-red-800",
          )}>
            Remediation Status:{" "}
            {result.overall_status.toUpperCase()}
          </p>
          <p className="text-xs text-slate-600 mt-0.5">{result.summary}</p>
        </div>
      </div>

      {/* Checks list */}
      <div className="space-y-2">
        {result.checks.map((check, i) => (
          <div key={i} className="flex items-start gap-2.5 text-sm">
            {statusIcon(check.status)}
            <div>
              <span className="font-medium text-slate-700">{check.name}</span>
              {check.detail && (
                <p className="text-xs text-slate-500 mt-0.5">{check.detail}</p>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Exploit blocked indicator */}
      <div className={clsx(
        "flex items-center gap-2 text-sm px-4 py-2.5 rounded-lg border",
        result.exploit_blocked
          ? "bg-green-50 border-green-200 text-green-700"
          : "bg-slate-50 border-slate-200 text-slate-600",
      )}>
        {result.exploit_blocked
          ? <ShieldCheck size={15} className="text-green-600 shrink-0" />
          : <MinusCircle size={15} className="text-slate-400 shrink-0" />
        }
        <span className="font-medium">
          {result.exploit_blocked
            ? "Original exploit vector blocked — attack returns HTTP 403"
            : "Exploit block status unconfirmed — manual verification recommended"}
        </span>
      </div>
    </div>
  );
}
