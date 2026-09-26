"use client";

import { clsx } from "clsx";
import { CheckCircle2, XCircle, Loader2, Clock, Bot } from "lucide-react";
import type { AgentResult } from "@/lib/types";

const AGENT_LABELS: Record<string, string> = {
  repository_agent: "Repository Intelligence",
  security_agent:   "Security Investigation",
  code_agent:       "Code Analysis",
  dependency_agent: "Dependency Analysis",
  config_agent:     "Configuration Analysis",
  test_agent:       "Test Coverage",
  runtime_agent:    "Runtime & Logs",
};

const AGENT_ORDER = [
  "repository_agent",
  "security_agent",
  "code_agent",
  "dependency_agent",
  "config_agent",
  "test_agent",
  "runtime_agent",
];

interface Props {
  agentResults: Record<string, AgentResult>;
  currentAgents?: string[];
}

export default function AgentActivityPanel({ agentResults, currentAgents = [] }: Props) {
  return (
    <div className="space-y-1">
      {AGENT_ORDER.map((agentKey) => {
        const result = agentResults[agentKey];
        const isRunning = currentAgents.includes(agentKey);
        const label = AGENT_LABELS[agentKey] || agentKey;

        let icon: React.ReactNode;
        let rowClass: string;

        if (result?.status === "completed") {
          icon = <CheckCircle2 size={15} className="text-green-500 shrink-0" />;
          rowClass = "text-slate-700";
        } else if (result?.status === "failed") {
          icon = <XCircle size={15} className="text-red-400 shrink-0" />;
          rowClass = "text-slate-500";
        } else if (isRunning) {
          icon = <Loader2 size={15} className="text-blue-500 shrink-0 animate-spin" />;
          rowClass = "text-blue-700 font-medium";
        } else {
          icon = <Clock size={15} className="text-slate-300 shrink-0" />;
          rowClass = "text-slate-400";
        }

        return (
          <div
            key={agentKey}
            className={clsx(
              "flex items-center gap-2.5 px-3 py-2 rounded-md text-sm",
              rowClass,
            )}
          >
            {icon}
            <span className="flex-1">{label}</span>
            {result?.status === "completed" && (
              <span className="text-xs text-slate-400">
                {result.findings.length} finding{result.findings.length !== 1 ? "s" : ""}
              </span>
            )}
            {result?.duration_ms && result.duration_ms > 0 && (
              <span className="text-xs text-slate-300">
                {(result.duration_ms / 1000).toFixed(1)}s
              </span>
            )}
            {result?.status === "failed" && (
              <span className="text-xs text-red-400">⚠ failed</span>
            )}
          </div>
        );
      })}
    </div>
  );
}
