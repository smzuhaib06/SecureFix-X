"use client";

import { useEffect, useState } from "react";
import { Bot, CheckCircle2, Zap, Shield, Code2, Package, Settings2, TestTube2, Activity } from "lucide-react";
import Sidebar from "@/components/layout/Sidebar";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { api } from "@/lib/api";
import type { InvestigationSummary } from "@/lib/types";

const AGENT_META = [
  {
    key: "repository_agent",
    name: "Repository Intelligence",
    icon: Zap,
    color: "text-blue-600",
    bg: "bg-blue-50",
    desc: "Indexes repository structure, identifies languages, frameworks, API routes, authentication components, and database access patterns.",
    outputs: ["project_type", "languages", "frameworks", "api_routes", "auth_components", "entry_points"],
  },
  {
    key: "security_agent",
    name: "Security Investigation",
    icon: Shield,
    color: "text-red-600",
    bg: "bg-red-50",
    desc: "Detects vulnerable data flows, missing authorization checks, dangerous sinks, and exploit conditions using pattern-based analysis.",
    outputs: ["findings", "severity", "attack_path", "root_cause", "confidence"],
  },
  {
    key: "code_agent",
    name: "Code Analysis",
    icon: Code2,
    color: "text-indigo-600",
    bg: "bg-indigo-50",
    desc: "Performs data-flow and control-flow analysis on files relevant to the investigation. Identifies unverified direct object references.",
    outputs: ["data_flow", "control_flow", "vulnerable_functions", "line_ranges"],
  },
  {
    key: "dependency_agent",
    name: "Dependency Analysis",
    icon: Package,
    color: "text-amber-600",
    bg: "bg-amber-50",
    desc: "Scans package manifests for vulnerable or outdated dependencies. Only flags packages actually relevant to the reported issue.",
    outputs: ["vulnerable_packages", "versions", "cve_ids", "relevance"],
  },
  {
    key: "config_agent",
    name: "Configuration Analysis",
    icon: Settings2,
    color: "text-orange-600",
    bg: "bg-orange-50",
    desc: "Analyzes Dockerfile, docker-compose, .env files, and application config for security misconfigurations, debug mode, CORS issues.",
    outputs: ["hardcoded_secrets", "insecure_defaults", "cors_policy", "exposed_ports"],
  },
  {
    key: "test_agent",
    name: "Test Coverage",
    icon: TestTube2,
    color: "text-green-600",
    bg: "bg-green-50",
    desc: "Identifies missing regression tests, assesses existing test coverage, and auto-generates a regression test after the fix is approved.",
    outputs: ["coverage_gaps", "test_files", "generated_regression_test"],
  },
  {
    key: "runtime_agent",
    name: "Runtime & Logs",
    icon: Activity,
    color: "text-purple-600",
    bg: "bg-purple-50",
    desc: "Analyzes application logs for exploitation evidence, error patterns, and suspicious access sequences. Clearly states when logs are unavailable.",
    outputs: ["log_evidence", "error_patterns", "access_anomalies"],
  },
];

export default function AgentsPage() {
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [agentRunCounts, setAgentRunCounts] = useState<Record<string, number>>({});

  useEffect(() => {
    api.listInvestigations().then(async (invs) => {
      setInvestigations(invs);
      const counts: Record<string, number> = {};
      await Promise.all(
        invs.map(async (s) => {
          try {
            const inv = await api.getInvestigation(s.id);
            for (const [name, result] of Object.entries(inv.agent_results)) {
              if (result.status === "completed") {
                counts[name] = (counts[name] ?? 0) + 1;
              }
            }
          } catch {}
        })
      );
      setAgentRunCounts(counts);
    }).catch(console.error);
  }, []);

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <header className="bg-white border-b border-slate-200 px-8 py-5">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-xl font-bold text-slate-900">Agents</h1>
              <p className="text-sm text-slate-500 mt-0.5">
                7 specialized AI agents — run in parallel after repository indexing
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-500 bg-green-50 border border-green-200 px-3 py-2 rounded-lg">
              <CheckCircle2 size={13} className="text-green-500" />
              All agents operational
            </div>
          </div>
        </header>

        <main className="flex-1 px-8 py-6">
          {/* Pipeline diagram */}
          <Card className="mb-6">
            <CardBody>
              <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-4">
                Execution Pipeline
              </p>
              <div className="flex items-center gap-2 flex-wrap">
                <PipelineStep label="Repository Intelligence" note="sequential" />
                <Arrow />
                <div className="flex flex-col gap-1 border border-slate-200 rounded-lg px-3 py-2">
                  <p className="text-xs text-slate-400 mb-1 font-medium">Parallel execution</p>
                  {["Security", "Code", "Dependency", "Config", "Test", "Runtime"].map((a) => (
                    <div key={a} className="text-xs text-slate-600 flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-blue-400 shrink-0" />
                      {a} Agent
                    </div>
                  ))}
                </div>
                <Arrow />
                <PipelineStep label="Evidence Correlation" />
                <Arrow />
                <PipelineStep label="Root Cause" />
                <Arrow />
                <PipelineStep label="Patch + Verify" />
              </div>
            </CardBody>
          </Card>

          {/* Agent cards */}
          <div className="grid grid-cols-2 gap-4">
            {AGENT_META.map((agent) => {
              const runCount = agentRunCounts[agent.key] ?? 0;
              return (
                <Card key={agent.key}>
                  <CardBody>
                    <div className="flex items-start gap-3">
                      <div className={`w-9 h-9 ${agent.bg} rounded-lg flex items-center justify-center shrink-0`}>
                        <agent.icon size={16} className={agent.color} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between mb-1">
                          <p className="text-sm font-semibold text-slate-800">{agent.name}</p>
                          <div className="flex items-center gap-1.5">
                            {runCount > 0 && (
                              <span className="text-xs text-slate-400">{runCount} run{runCount !== 1 ? "s" : ""}</span>
                            )}
                            <div className="flex items-center gap-1 text-xs text-green-600">
                              <CheckCircle2 size={11} />
                              Ready
                            </div>
                          </div>
                        </div>
                        <p className="text-xs text-slate-500 leading-relaxed mb-3">{agent.desc}</p>
                        <div>
                          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1.5">
                            Output fields
                          </p>
                          <div className="flex flex-wrap gap-1">
                            {agent.outputs.map((o) => (
                              <span
                                key={o}
                                className="text-xs bg-slate-100 text-slate-500 px-2 py-0.5 rounded font-mono"
                              >
                                {o}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  </CardBody>
                </Card>
              );
            })}
          </div>
        </main>
      </div>
    </div>
  );
}

function PipelineStep({ label, note }: { label: string; note?: string }) {
  return (
    <div className="flex flex-col items-center text-center">
      <div className="bg-blue-50 border border-blue-200 rounded-lg px-3 py-2 text-xs font-medium text-blue-700">
        {label}
      </div>
      {note && <p className="text-xs text-slate-400 mt-0.5">{note}</p>}
    </div>
  );
}

function Arrow() {
  return <div className="text-slate-300 text-sm font-bold shrink-0">→</div>;
}
