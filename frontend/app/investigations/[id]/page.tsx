"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { useParams, useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft, CheckCircle2, Clock, FileCode2, ShieldAlert,
  GitBranch, Wrench, AlertTriangle, ThumbsUp, ThumbsDown,
  Code2, TestTube2, BarChart3, FileText, Download, TrendingDown,
  Brain,
} from "lucide-react";
import Sidebar from "@/components/layout/Sidebar";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { SeverityBadge, StatusBadge, ConfidenceBadge } from "@/components/ui/Badge";
import AgentActivityPanel from "@/components/investigation/AgentActivityPanel";
import AttackPathVisual from "@/components/investigation/AttackPathVisual";
import DiffViewer from "@/components/investigation/DiffViewer";
import VerificationPanel from "@/components/investigation/VerificationPanel";
import BeforeAfterPanel from "@/components/investigation/BeforeAfterPanel";
import AIReasoningPanel from "@/components/investigation/AIReasoningPanel";
import { api } from "@/lib/api";
import type { Investigation, ProgressEvent } from "@/lib/types";

type Tab = "overview" | "ai-reasoning" | "agents" | "evidence" | "root-cause" | "patch" | "verification" | "timeline" | "before-after";

export default function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const searchParams = useSearchParams();
  const router = useRouter();
  const [inv, setInv] = useState<Investigation | null>(null);
  const initialTab = (searchParams.get("tab") as Tab) || "overview";
  const [tab, setTab] = useState<Tab>(initialTab);
  const [liveMessages, setLiveMessages] = useState<string[]>([]);
  const [runningAgents, setRunningAgents] = useState<string[]>([]);
  const [approving, setApproving] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  // ── Load investigation ─────────────────────────────────────────────────────
  useEffect(() => {
    if (!id) return;
    api.getInvestigation(id).then(setInv).catch(console.error);
  }, [id]);

  const handleTabChange = useCallback((newTab: Tab) => {
    setTab(newTab);
    router.replace(`/investigations/${id}?tab=${newTab}`, { scroll: false });
  }, [id, router]);

  // Synchronize tab state if URL query param changes
  useEffect(() => {
    const tabParam = searchParams.get("tab") as Tab;
    if (tabParam && ["overview", "ai-reasoning", "agents", "evidence", "root-cause", "patch", "verification", "timeline", "before-after"].includes(tabParam)) {
      setTab(tabParam);
    }
  }, [searchParams]);

  // ── Polling fallback (every 3s while running) ─────────────────────────────
  useEffect(() => {
    if (!id) return;
    const interval = setInterval(() => {
      if (inv && ["pending", "running", "applying", "verifying"].includes(inv.status)) {
        api.getInvestigation(id).then(setInv).catch(() => {});
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [id, inv?.status]);

  // ── SSE stream ─────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!id) return;
    const es = new EventSource(api.streamUrl(id));
    esRef.current = es;

    es.onmessage = (e) => {
      try {
        const event: ProgressEvent = JSON.parse(e.data);
        if ("type" in event) return; // heartbeat

        setLiveMessages((prev) => [...prev.slice(-30), event.message]);

        if (event.event_type === "agent_started" && event.agent) {
          setRunningAgents((prev) => [...prev, event.agent!]);
        }
        if (
          (event.event_type.startsWith("agent_") && event.event_type !== "agent_started") ||
          event.event_type === "agent_completed" ||
          event.event_type === "agent_failed"
        ) {
          setRunningAgents((prev) => prev.filter((a) => a !== event.agent));
        }

        // Refresh investigation data on key events
        if (
          event.event_type === "agent_completed" ||
          event.event_type === "correlation_done" ||
          event.event_type === "root_cause_done" ||
          event.event_type === "patch_ready" ||
          event.event_type === "verification_done" ||
          event.event_type === "status_change"
        ) {
          api.getInvestigation(id).then(setInv).catch(console.error);
        }

        // Stop streaming on terminal state
        if (event.progress_pct >= 100 || event.event_type === "error") {
          es.close();
          api.getInvestigation(id).then(setInv).catch(console.error);
        }
      } catch {}
    };

    es.onerror = () => es.close();
    return () => es.close();
  }, [id]);

  const handleApprove = async (approved: boolean) => {
    if (!inv) return;
    setApproving(true);
    try {
      const updated = await api.approveRemediation(inv.id, approved);
      setInv(updated);
      if (approved) {
        // Re-open stream for verification progress
        esRef.current?.close();
        const es = new EventSource(api.streamUrl(inv.id));
        esRef.current = es;
        es.onmessage = (e) => {
          try {
            const event: ProgressEvent = JSON.parse(e.data);
            if ("type" in event) return;
            setLiveMessages((prev) => [...prev.slice(-30), event.message]);
            if (event.progress_pct >= 100) {
              es.close();
              api.getInvestigation(inv.id).then(setInv).catch(console.error);
            } else {
              api.getInvestigation(inv.id).then(setInv).catch(console.error);
            }
          } catch {}
        };
        es.onerror = () => es.close();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setApproving(false);
    }
  };

  if (!inv) {
    return (
      <div className="flex min-h-screen bg-slate-50">
        <Sidebar />
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto" />
            <p className="text-sm text-slate-500 mt-3">Loading investigation…</p>
          </div>
        </div>
      </div>
    );
  }

  const tabs: { key: Tab; label: string; icon: React.ElementType }[] = [
    { key: "overview",     label: "Overview",     icon: BarChart3     },
    { key: "ai-reasoning", label: "AI Reasoning", icon: Brain         },
    { key: "agents",       label: "Agents",       icon: GitBranch     },
    { key: "evidence",     label: "Evidence",     icon: ShieldAlert   },
    { key: "root-cause",   label: "Root Cause",   icon: AlertTriangle },
    { key: "patch",        label: "Patch",        icon: Wrench        },
    { key: "verification", label: "Verification", icon: CheckCircle2  },
    { key: "before-after", label: "Before/After", icon: TrendingDown  },
    { key: "timeline",     label: "Timeline",     icon: Clock         },
  ];

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="bg-white border-b border-slate-200 px-8 py-4 shrink-0">
          <div className="flex items-start gap-3">
            <Link href="/investigations" className="text-slate-400 hover:text-slate-600 mt-1">
              <ArrowLeft size={17} />
            </Link>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-mono text-slate-400 bg-slate-100 px-2 py-0.5 rounded">
                  {inv.id}
                </span>
                {inv.severity && <SeverityBadge severity={inv.severity} />}
                <StatusBadge status={inv.status} />
              </div>
              <h1 className="text-lg font-bold text-slate-900 truncate">{inv.title}</h1>
            </div>
            {/* Progress */}
            <div className="shrink-0 text-right flex items-center gap-3">
              {inv.status === "completed" && (
                <a
                  href={api.reportUrl(inv.id)}
                  download
                  className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-blue-600 border border-slate-200 hover:border-blue-300 px-3 py-1.5 rounded-lg transition-colors"
                >
                  <Download size={12} />
                  Report
                </a>
              )}
              <div>
                <p className="text-xs text-slate-400 mb-1">{inv.progress_pct}%</p>
                <div className="w-32 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-500 rounded-full transition-all"
                    style={{ width: `${inv.progress_pct}%` }}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex items-center gap-1 mt-4 -mb-px">
            {tabs.map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => handleTabChange(key)}
                className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
                  tab === key
                    ? "border-blue-600 text-blue-700"
                    : "border-transparent text-slate-500 hover:text-slate-700"
                }`}
              >
                <Icon size={12} />
                {label}
              </button>
            ))}
          </div>
        </header>

        {/* Body */}
        <main className="flex-1 overflow-y-auto px-8 py-6">
          {tab === "overview" && <OverviewTab inv={inv} liveMessages={liveMessages} />}
          {tab === "ai-reasoning" && <AIReasoningPanel inv={inv} />}
          {tab === "agents" && <AgentsTab inv={inv} runningAgents={runningAgents} />}
          {tab === "evidence" && <EvidenceTab inv={inv} />}
          {tab === "root-cause" && <RootCauseTab inv={inv} />}
          {tab === "patch" && (
            <PatchTab inv={inv} onApprove={handleApprove} approving={approving} />
          )}
          {tab === "verification" && <VerificationTab inv={inv} />}
          {tab === "before-after" && <BeforeAfterTab inv={inv} />}
          {tab === "timeline" && <TimelineTab inv={inv} />}
        </main>
      </div>
    </div>
  );
}

// ── Tab components ────────────────────────────────────────────────────────────

function OverviewTab({ inv, liveMessages }: { inv: Investigation; liveMessages: string[] }) {
  return (
    <div className="grid grid-cols-3 gap-5">
      {/* Left: Issue + correlation */}
      <div className="col-span-2 space-y-4">
        <Card>
          <CardHeader>
            <p className="text-sm font-semibold text-slate-700">Issue Description</p>
          </CardHeader>
          <CardBody>
            <p className="text-sm text-slate-600 leading-relaxed">{inv.issue_description}</p>
          </CardBody>
        </Card>

        {inv.correlation && (
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <p className="text-sm font-semibold text-slate-700">Primary Finding</p>
                <ConfidenceBadge confidence={inv.correlation.confidence} />
              </div>
            </CardHeader>
            <CardBody className="space-y-4">
              <p className="text-sm font-semibold text-slate-800">{inv.correlation.primary_finding}</p>
              {inv.severity && <SeverityBadge severity={inv.severity} />}

              {inv.correlation.affected_files.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
                    Affected Files
                  </p>
                  <div className="space-y-1">
                    {inv.correlation.affected_files.map((f) => (
                      <div key={f} className="flex items-center gap-2 text-xs">
                        <FileCode2 size={12} className="text-slate-400 shrink-0" />
                        <code className="text-slate-600 font-mono">{f}</code>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardBody>
          </Card>
        )}

        {inv.root_cause && (
          <Card>
            <CardHeader>
              <p className="text-sm font-semibold text-slate-700">Root Cause Summary</p>
            </CardHeader>
            <CardBody className="space-y-3">
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1">Symptom</p>
                <p className="text-sm text-slate-600">{inv.root_cause.symptom}</p>
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1">Root Cause</p>
                <p className="text-sm text-slate-700 font-medium">{inv.root_cause.root_cause}</p>
              </div>
              {inv.root_cause.cwe_id && (
                <div className="flex items-center gap-2">
                  <span className="text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded font-mono">
                    {inv.root_cause.cwe_id}
                  </span>
                  {inv.root_cause.cvss_score && (
                    <span className="text-xs bg-red-50 text-red-700 border border-red-200 px-2 py-0.5 rounded font-semibold">
                      CVSS {inv.root_cause.cvss_score}
                    </span>
                  )}
                </div>
              )}
            </CardBody>
          </Card>
        )}

        {/* Approval card */}
        {inv.status === "awaiting_approval" && inv.remediation && (
          <ApprovalCard inv={inv} />
        )}
      </div>

      {/* Right: Attack path + live feed */}
      <div className="space-y-4">
        {inv.correlation?.attack_path && inv.correlation.attack_path.length > 0 && (
          <Card>
            <CardHeader>
              <p className="text-sm font-semibold text-slate-700">Attack Path</p>
            </CardHeader>
            <CardBody>
              <AttackPathVisual steps={inv.correlation.attack_path} />
            </CardBody>
          </Card>
        )}

        {liveMessages.length > 0 && (
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-blue-500 pulse-dot" />
                <p className="text-xs font-semibold text-slate-600">Live Activity</p>
              </div>
            </CardHeader>
            <CardBody className="max-h-48 overflow-y-auto">
              <div className="space-y-1">
                {liveMessages.slice(-15).map((msg, i) => (
                  <p key={i} className="text-xs text-slate-500 leading-relaxed">{msg}</p>
                ))}
              </div>
            </CardBody>
          </Card>
        )}

        {inv.verification && (
          <Card>
            <CardHeader>
              <p className="text-sm font-semibold text-slate-700">Verification</p>
            </CardHeader>
            <CardBody>
              <VerificationPanel result={inv.verification} />
            </CardBody>
          </Card>
        )}
      </div>
    </div>
  );
}

function ApprovalCard({ inv }: { inv: Investigation }) {
  const [approving, setApproving] = useState(false);

  const handle = async (approved: boolean) => {
    setApproving(true);
    try {
      await api.approveRemediation(inv.id, approved);
      window.location.reload();
    } finally {
      setApproving(false);
    }
  };

  return (
    <Card className="border-amber-200 bg-amber-50">
      <CardBody>
        <p className="text-sm font-semibold text-amber-900 mb-1">Awaiting Your Approval</p>
        <p className="text-xs text-amber-700 mb-3">
          SECUREFIX proposes {inv.remediation!.patches.length} file change(s).
          Risk: <strong>{inv.remediation!.risk_level}</strong>.
        </p>
        <p className="text-xs text-amber-600 mb-4">{inv.remediation!.risk_explanation}</p>
        <div className="flex gap-2">
          <button
            onClick={() => handle(true)}
            disabled={approving}
            className="flex items-center gap-1.5 bg-green-600 text-white px-4 py-2 rounded-lg text-xs font-semibold hover:bg-green-700 disabled:opacity-50 transition-colors"
          >
            <ThumbsUp size={13} />
            Approve &amp; Apply
          </button>
          <button
            onClick={() => handle(false)}
            disabled={approving}
            className="flex items-center gap-1.5 bg-white text-red-600 border border-red-200 px-4 py-2 rounded-lg text-xs font-semibold hover:bg-red-50 disabled:opacity-50 transition-colors"
          >
            <ThumbsDown size={13} />
            Reject
          </button>
        </div>
      </CardBody>
    </Card>
  );
}

function AgentsTab({ inv, runningAgents }: { inv: Investigation; runningAgents: string[] }) {
  return (
    <div className="grid grid-cols-2 gap-5">
      <Card>
        <CardHeader>
          <p className="text-sm font-semibold text-slate-700">Agent Execution Status</p>
        </CardHeader>
        <CardBody>
          <AgentActivityPanel agentResults={inv.agent_results} currentAgents={runningAgents} />
        </CardBody>
      </Card>

      <div className="space-y-3">
        {Object.entries(inv.agent_results).map(([name, result]) => (
          <Card key={name}>
            <CardBody>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-semibold text-slate-700 capitalize">
                  {name.replace("_", " ")}
                </p>
                <StatusBadge status={result.status} />
              </div>
              <p className="text-xs text-slate-500 mb-2">{result.summary}</p>
              {result.error && (
                <p className="text-xs text-red-500 bg-red-50 rounded px-2 py-1">⚠ {result.error}</p>
              )}
              {result.findings.length > 0 && (
                <div className="space-y-1 mt-2">
                  {result.findings.slice(0, 3).map((f, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs text-slate-600">
                      <SeverityBadge severity={f.severity} />
                      <span className="truncate">{f.title}</span>
                    </div>
                  ))}
                </div>
              )}
            </CardBody>
          </Card>
        ))}
      </div>
    </div>
  );
}

function EvidenceTab({ inv }: { inv: Investigation }) {
  if (!inv.correlation) {
    return <p className="text-sm text-slate-500">Evidence correlation not yet complete.</p>;
  }
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold text-slate-700">Corroborating Evidence</p>
            <ConfidenceBadge confidence={inv.correlation.confidence} />
          </div>
        </CardHeader>
        <CardBody>
          <div className="space-y-3">
            {inv.correlation.corroborating_evidence.map((ev, i) => (
              <div key={i} className="flex items-start gap-3 text-sm">
                <span className="inline-flex items-center shrink-0 px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-600 mt-0.5">
                  {ev.source.replace("_agent", "")}
                </span>
                <div>
                  <p className="text-slate-700">{ev.description}</p>
                  {ev.file && (
                    <p className="text-xs text-slate-400 mt-0.5 font-mono">
                      {ev.file}{ev.line_range ? `:${ev.line_range}` : ""}
                    </p>
                  )}
                </div>
              </div>
            ))}
            {inv.correlation.corroborating_evidence.length === 0 && (
              <p className="text-sm text-slate-400">No corroborating evidence collected yet.</p>
            )}
          </div>
        </CardBody>
      </Card>

      {/* All agent findings */}
      {Object.entries(inv.agent_results)
        .filter(([, r]) => r.findings.length > 0)
        .map(([agent, result]) => (
          <Card key={agent}>
            <CardHeader>
              <p className="text-sm font-semibold text-slate-700 capitalize">
                {agent.replace("_", " ")} findings
              </p>
            </CardHeader>
            <CardBody className="space-y-4">
              {result.findings.map((f, i) => (
                <div key={i} className="border-b border-slate-100 pb-4 last:border-0 last:pb-0">
                  <div className="flex items-center gap-2 mb-2">
                    <SeverityBadge severity={f.severity} />
                    <ConfidenceBadge confidence={f.confidence} />
                    <p className="text-sm font-semibold text-slate-700">{f.title}</p>
                  </div>
                  {f.evidence.length > 0 && (
                    <ul className="space-y-1">
                      {f.evidence.map((e, j) => (
                        <li key={j} className="text-xs text-slate-600 flex items-start gap-1.5">
                          <span className="text-slate-300 shrink-0 mt-0.5">›</span>
                          {e}
                        </li>
                      ))}
                    </ul>
                  )}
                  {f.recommendation && (
                    <p className="text-xs text-blue-700 bg-blue-50 rounded px-3 py-2 mt-2">
                      💡 {f.recommendation}
                    </p>
                  )}
                </div>
              ))}
            </CardBody>
          </Card>
        ))}
    </div>
  );
}

function RootCauseTab({ inv }: { inv: Investigation }) {
  if (!inv.root_cause) {
    return <p className="text-sm text-slate-500">Root cause analysis not yet complete.</p>;
  }
  const rc = inv.root_cause;
  return (
    <div className="grid grid-cols-2 gap-5">
      <div className="space-y-4">
        <Card>
          <CardHeader><p className="text-sm font-semibold text-slate-700">Symptom</p></CardHeader>
          <CardBody><p className="text-sm text-slate-600">{rc.symptom}</p></CardBody>
        </Card>
        <Card>
          <CardHeader><p className="text-sm font-semibold text-slate-700">Root Cause</p></CardHeader>
          <CardBody>
            <p className="text-sm text-slate-700 leading-relaxed">{rc.root_cause}</p>
          </CardBody>
        </Card>
        <Card>
          <CardHeader><p className="text-sm font-semibold text-slate-700">Why It Happens</p></CardHeader>
          <CardBody>
            <p className="text-sm text-slate-600 leading-relaxed">{rc.why_it_happens}</p>
          </CardBody>
        </Card>
      </div>
      <div className="space-y-4">
        <Card>
          <CardHeader><p className="text-sm font-semibold text-slate-700">Impact</p></CardHeader>
          <CardBody>
            <p className="text-sm text-slate-600 leading-relaxed">{rc.impact}</p>
          </CardBody>
        </Card>
        {(rc.cwe_id || rc.cvss_score) && (
          <Card>
            <CardHeader><p className="text-sm font-semibold text-slate-700">Classification</p></CardHeader>
            <CardBody className="flex items-center gap-3">
              {rc.cwe_id && (
                <span className="text-sm font-mono bg-slate-100 text-slate-700 px-3 py-1.5 rounded">
                  {rc.cwe_id}
                </span>
              )}
              {rc.cvss_score && (
                <span className="text-sm font-bold bg-red-50 text-red-700 border border-red-200 px-3 py-1.5 rounded">
                  CVSS {rc.cvss_score}
                </span>
              )}
            </CardBody>
          </Card>
        )}
        {rc.affected_components.length > 0 && (
          <Card>
            <CardHeader><p className="text-sm font-semibold text-slate-700">Affected Components</p></CardHeader>
            <CardBody>
              <div className="space-y-1">
                {rc.affected_components.map((c) => (
                  <div key={c} className="flex items-center gap-2 text-xs text-slate-600">
                    <FileCode2 size={12} className="text-slate-400 shrink-0" />
                    <code className="font-mono">{c}</code>
                  </div>
                ))}
              </div>
            </CardBody>
          </Card>
        )}
      </div>
    </div>
  );
}

function PatchTab({
  inv, onApprove, approving,
}: {
  inv: Investigation;
  onApprove: (approved: boolean) => void;
  approving: boolean;
}) {
  if (!inv.remediation) {
    return <p className="text-sm text-slate-500">Patch not yet generated.</p>;
  }
  const r = inv.remediation;

  return (
    <div className="space-y-5">
      {/* Summary */}
      <Card>
        <CardBody>
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-slate-800 mb-1">{r.summary}</p>
              <p className="text-xs text-slate-500">
                {r.files_changed.length} file(s) to modify · Risk:{" "}
                <span className={r.risk_level === "low" ? "text-green-600" : r.risk_level === "medium" ? "text-amber-600" : "text-red-600"}>
                  {r.risk_level.toUpperCase()}
                </span>
              </p>
              <p className="text-xs text-slate-400 mt-1">{r.risk_explanation}</p>
            </div>
            <StatusBadge status={r.status} />
          </div>
        </CardBody>
      </Card>

      {/* Approval actions */}
      {inv.status === "awaiting_approval" && (
        <Card className="border-amber-200 bg-amber-50">
          <CardBody>
            <p className="text-sm font-semibold text-amber-900 mb-1">
              AI investigates. Human approves. System verifies.
            </p>
            <p className="text-xs text-amber-700 mb-4">
              Review the proposed patch below, then approve or reject.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => onApprove(true)}
                disabled={approving}
                className="flex items-center gap-2 bg-green-600 text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-green-700 disabled:opacity-50 transition-colors"
              >
                <ThumbsUp size={14} />
                Approve &amp; Apply
              </button>
              <button
                onClick={() => onApprove(false)}
                disabled={approving}
                className="flex items-center gap-2 bg-white text-red-600 border border-red-200 px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-red-50 disabled:opacity-50 transition-colors"
              >
                <ThumbsDown size={14} />
                Reject
              </button>
            </div>
          </CardBody>
        </Card>
      )}

      {/* Diff */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Code2 size={14} className="text-slate-500" />
            <p className="text-sm font-semibold text-slate-700">Proposed Changes</p>
          </div>
        </CardHeader>
        <CardBody>
          <DiffViewer patches={r.patches} />
        </CardBody>
      </Card>

      {/* Regression test */}
      {r.regression_test && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <TestTube2 size={14} className="text-slate-500" />
              <p className="text-sm font-semibold text-slate-700">Generated Regression Test</p>
              {r.regression_test_file && (
                <code className="text-xs text-slate-400 font-mono ml-2">{r.regression_test_file}</code>
              )}
            </div>
          </CardHeader>
          <CardBody>
            <pre className="text-xs font-mono bg-slate-950 text-green-300 rounded-lg p-4 overflow-x-auto leading-relaxed max-h-80 overflow-y-auto">
              {r.regression_test}
            </pre>
          </CardBody>
        </Card>
      )}
    </div>
  );
}

function VerificationTab({ inv }: { inv: Investigation }) {
  if (!inv.verification) {
    return <p className="text-sm text-slate-500">Verification not yet run.</p>;
  }
  return (
    <div className="max-w-xl">
      <Card>
        <CardHeader><p className="text-sm font-semibold text-slate-700">Verification Results</p></CardHeader>
        <CardBody>
          <VerificationPanel result={inv.verification} />
        </CardBody>
      </Card>
    </div>
  );
}

function TimelineTab({ inv }: { inv: Investigation }) {
  return (
    <Card>
      <CardHeader><p className="text-sm font-semibold text-slate-700">Investigation Timeline</p></CardHeader>
      <CardBody>
        <div className="relative">
          <div className="absolute left-4 top-0 bottom-0 w-px bg-slate-200" />
          <div className="space-y-4">
            {inv.timeline.map((ev, i) => (
              <div key={i} className="flex items-start gap-4 pl-10 relative">
                <span className="absolute left-3 w-2.5 h-2.5 rounded-full bg-white border-2 border-blue-400 mt-1 shrink-0 -translate-x-1/2" />
                <div>
                  <p className="text-sm font-medium text-slate-700">{ev.event}</p>
                  {ev.detail && (
                    <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{ev.detail}</p>
                  )}
                  <p className="text-xs text-slate-300 mt-1">
                    {new Date(ev.timestamp).toLocaleTimeString()} · {ev.actor}
                  </p>
                </div>
              </div>
            ))}
            {inv.timeline.length === 0 && (
              <p className="text-sm text-slate-400 pl-10">No events yet.</p>
            )}
          </div>
        </div>
      </CardBody>
    </Card>
  );
}

function BeforeAfterTab({ inv }: { inv: Investigation }) {
  return (
    <div className="space-y-5 max-w-2xl">
      <div>
        <p className="text-sm font-semibold text-slate-700 mb-1">Investigation Comparison</p>
        <p className="text-xs text-slate-400 mb-4">
          Comparison based on this demo scenario. Measurements are from the demonstration, not independently verified benchmarks.
        </p>
      </div>
      <BeforeAfterPanel investigation={inv} />
    </div>
  );
}

function SeverityBadgeInline({ severity }: { severity: string }) {
  return <SeverityBadge severity={severity as any} />;
}
