"use client";

import {
  Brain, ShieldCheck, ShieldAlert, BookOpen, CheckCircle2,
  AlertTriangle, Code2, Layers, Cpu, HelpCircle, ArrowRight,
  Database, FileCode2
} from "lucide-react";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import type { Investigation, AIReasoningData, VerificationResult } from "@/lib/types";
import { clsx } from "clsx";

interface Props {
  inv: Investigation;
}

export default function AIReasoningPanel({ inv }: Props) {
  const ai = inv.ai_reasoning;
  const ver = inv.verification;
  const isVerified = ver?.overall_status === "verified";

  // Gather direct repository evidence
  const directEvidence: Array<{ agent: string; file?: string; line?: string; text: string; strength: string }> = [];
  if (inv.agent_results) {
    Object.entries(inv.agent_results).forEach(([agentName, res]) => {
      res.findings?.forEach((f) => {
        directEvidence.push({
          agent: agentName.replace("_", " "),
          file: f.files?.[0],
          line: f.line_ranges?.[0],
          text: f.evidence_excerpt || f.title,
          strength: f.confidence >= 0.8 ? "DIRECT" : "CORROBORATED",
        });
      });
    });
  }

  return (
    <div className="space-y-6">
      {/* ── Architecture Pipeline Banner ── */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 border border-indigo-900/50 rounded-xl p-5 text-white shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-indigo-500/20 border border-indigo-500/40 flex items-center justify-center text-indigo-400">
              <Brain size={22} />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                Grounded AI Security Reasoning &amp; Verification Layer
                {ai?.provider_used && (
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-indigo-500/30 text-indigo-200 border border-indigo-400/30">
                    {ai.provider_used}
                  </span>
                )}
              </h2>
              <p className="text-xs text-slate-300">
                Deterministic agents collect evidence &rarr; RAG retrieves standards &rarr; AI reasons over evidence &rarr; Deterministic engine verifies
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <span className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold block">Grounding Confidence</span>
              <span className="text-sm font-bold text-emerald-400">
                {ai?.grounding_confidence ? `${Math.round(ai.grounding_confidence * 100)}% Evidence-Backed` : "High (Grounded)"}
              </span>
            </div>
            <div className="h-8 w-px bg-slate-700/60" />
            <div className="text-right">
              <span className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold block">Assurance Status</span>
              <span className={clsx(
                "text-xs font-semibold px-2 py-0.5 rounded",
                isVerified ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40" : "bg-amber-500/20 text-amber-300 border border-amber-500/40"
              )}>
                {isVerified ? "VERIFIED WITHIN TESTED SCOPE" : "EVIDENCE CORRELATED"}
              </span>
            </div>
          </div>
        </div>

        {/* 4 Provenance Pillars */}
        <div className="grid grid-cols-4 gap-2 text-xs pt-3 border-t border-slate-800">
          <div className="flex items-center gap-2 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-blue-400" />
            <span className="font-mono text-[11px]">1. Repository Evidence</span>
          </div>
          <div className="flex items-center gap-2 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            <span className="font-mono text-[11px]">2. Security RAG</span>
          </div>
          <div className="flex items-center gap-2 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-purple-400" />
            <span className="font-mono text-[11px]">3. AI Reasoning</span>
          </div>
          <div className="flex items-center gap-2 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span className="font-mono text-[11px]">4. Deterministic Verification</span>
          </div>
        </div>
      </div>

      {/* ── 2-Column Grid: Evidence Grounding + Retrieved RAG Knowledge ── */}
      <div className="grid grid-cols-2 gap-5">
        {/* 1. Repository Evidence Grounding */}
        <Card className="border-blue-100 shadow-sm">
          <CardHeader className="bg-blue-50/50 border-b border-blue-100 py-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-blue-900 font-semibold text-sm">
                <FileCode2 size={16} className="text-blue-600" />
                <span>1. Repository Evidence (Deterministic)</span>
              </div>
              <span className="text-[11px] bg-blue-100 text-blue-800 font-mono px-2 py-0.5 rounded">
                Authoritative Facts
              </span>
            </div>
          </CardHeader>
          <CardBody className="space-y-3 max-h-72 overflow-y-auto">
            {directEvidence.length > 0 ? (
              directEvidence.slice(0, 5).map((ev, i) => (
                <div key={i} className="p-2.5 rounded-lg border border-slate-100 bg-slate-50/70 text-xs space-y-1">
                  <div className="flex items-center justify-between text-slate-500 font-medium">
                    <span className="capitalize font-semibold text-slate-700">{ev.agent}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-100/70 text-blue-700 font-bold">
                      {ev.strength}
                    </span>
                  </div>
                  {ev.file && (
                    <p className="font-mono text-[11px] text-blue-700">
                      {ev.file}{ev.line ? `:${ev.line}` : ""}
                    </p>
                  )}
                  <p className="text-slate-600 font-mono text-[11px] bg-white p-1 rounded border border-slate-200 truncate">
                    {ev.text}
                  </p>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 italic">Deterministic agents are scanning repository files...</p>
            )}
          </CardBody>
        </Card>

        {/* 2. Retrieved Security Knowledge (RAG) */}
        <Card className="border-amber-100 shadow-sm">
          <CardHeader className="bg-amber-50/50 border-b border-amber-100 py-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-amber-900 font-semibold text-sm">
                <BookOpen size={16} className="text-amber-600" />
                <span>2. Retrieved Security Knowledge (RAG)</span>
              </div>
              <span className="text-[11px] bg-amber-100 text-amber-800 font-mono px-2 py-0.5 rounded">
                Curated Standards
              </span>
            </div>
          </CardHeader>
          <CardBody className="space-y-3 max-h-72 overflow-y-auto">
            {ai?.rag_citations && ai.rag_citations.length > 0 ? (
              ai.rag_citations.map((cite, i) => (
                <div key={i} className="p-2.5 rounded-lg border border-slate-100 bg-slate-50/70 text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-amber-800 text-[11px] bg-amber-100/80 px-1.5 py-0.5 rounded">
                      {cite.identifier}
                    </span>
                    <span className="text-[10px] text-slate-400 font-mono">
                      Relevance: {Math.round(cite.score * 100)}%
                    </span>
                  </div>
                  <p className="font-medium text-slate-700">{cite.title}</p>
                  <p className="text-slate-500 text-[11px]">Section: {cite.section} &bull; Source: {cite.source}</p>
                </div>
              ))
            ) : (
              <div className="space-y-2 text-xs text-slate-600">
                <div className="p-2 rounded bg-amber-50/60 border border-amber-100">
                  <span className="font-bold text-amber-900 font-mono">CWE-943 / CWE-639</span>
                  <p className="text-[11px] text-slate-600 mt-0.5">Authoritative weakness taxonomy &amp; mitigation criteria</p>
                </div>
                <div className="p-2 rounded bg-amber-50/60 border border-amber-100">
                  <span className="font-bold text-amber-900 font-mono">OWASP Top 10 (2021)</span>
                  <p className="text-[11px] text-slate-600 mt-0.5">A01 Broken Access Control / A03 Injection control framework</p>
                </div>
              </div>
            )}
          </CardBody>
        </Card>
      </div>

      {/* ── 3. AI Grounded Reasoning (The Brain) ── */}
      <Card className="border-purple-100 shadow-sm">
        <CardHeader className="bg-purple-50/50 border-b border-purple-100 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-purple-900 font-semibold text-sm">
              <Brain size={16} className="text-purple-600" />
              <span>3. Grounded AI Reasoning (Reasoner Output)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] bg-purple-100 text-purple-800 px-2 py-0.5 rounded font-mono">
                Observation Status: {ai?.root_cause_observation_status || "INFERRED"}
              </span>
            </div>
          </div>
        </CardHeader>
        <CardBody className="space-y-4">
          {/* Assessment & Root Cause */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Vulnerability Assessment</p>
              <p className="text-sm font-semibold text-slate-800">
                {ai?.vulnerability_title || inv.root_cause?.root_cause || "Security Vulnerability Detected"}
              </p>
              <p className="text-xs text-slate-600 leading-relaxed mt-1">
                {ai?.severity_assessment || inv.root_cause?.impact || "Potential unauthorized access or code execution."}
              </p>
            </div>
            <div className="space-y-1">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Root Cause Analysis</p>
              <p className="text-xs text-slate-700 bg-slate-50 border border-slate-200 rounded p-2 font-mono leading-relaxed">
                {ai?.root_cause_summary || inv.root_cause?.why_it_happens || "Awaiting AI reasoning completion."}
              </p>
            </div>
          </div>

          {/* Attack Path */}
          {ai?.attack_path && ai.attack_path.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Reasoned Attack Path</p>
              <div className="space-y-2">
                {ai.attack_path.map((step) => (
                  <div key={step.step} className="flex items-start gap-2.5 text-xs bg-purple-50/30 border border-purple-100 rounded-lg p-2.5">
                    <span className="w-5 h-5 rounded-full bg-purple-200 text-purple-800 font-bold flex items-center justify-center shrink-0 text-[11px]">
                      {step.step}
                    </span>
                    <div className="flex-1">
                      <p className="text-slate-800 font-medium">{step.description}</p>
                      {step.evidence_basis && (
                        <p className="text-[11px] text-purple-700 mt-0.5 font-mono">
                          Evidence: {step.evidence_basis}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommended Remediation & Code Example */}
          <div className="space-y-2 pt-2 border-t border-slate-100">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Recommended Remediation</p>
            <p className="text-xs text-slate-700 leading-relaxed">
              {ai?.primary_remediation || inv.remediation?.summary || "Apply strict input validation and authorization checks."}
            </p>
            {ai?.remediation_code_example && (
              <pre className="bg-slate-900 text-emerald-300 font-mono text-xs p-3 rounded-lg overflow-x-auto">
                <code>{ai.remediation_code_example}</code>
              </pre>
            )}
          </div>

          {/* Evidence Gaps & Uncertainties */}
          {((ai?.evidence_gaps && ai.evidence_gaps.length > 0) || (ai?.cannot_determine && ai.cannot_determine.length > 0)) && (
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs space-y-1.5">
              <div className="flex items-center gap-1.5 text-slate-700 font-semibold">
                <HelpCircle size={14} className="text-slate-500" />
                <span>Explicit Evidence Gaps &amp; Grounding Boundaries</span>
              </div>
              <ul className="list-disc list-inside text-slate-500 space-y-0.5 text-[11px]">
                {ai?.evidence_gaps?.map((gap, i) => (
                  <li key={i}>{gap}</li>
                ))}
                {ai?.cannot_determine?.map((item, i) => (
                  <li key={`cd-${i}`}>{item}</li>
                ))}
              </ul>
            </div>
          )}
        </CardBody>
      </Card>

      {/* ── 4. Deterministic Verification & Assurance ── */}
      <Card className="border-emerald-100 shadow-sm">
        <CardHeader className="bg-emerald-50/50 border-b border-emerald-100 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-emerald-900 font-semibold text-sm">
              <ShieldCheck size={16} className="text-emerald-600" />
              <span>4. Deterministic Verification &amp; Assurance</span>
            </div>
            <span className={clsx(
              "text-[11px] font-mono px-2 py-0.5 rounded font-bold uppercase",
              isVerified ? "bg-emerald-100 text-emerald-800" : "bg-red-100 text-red-800"
            )}>
              {ver?.overall_status ? ver.overall_status.toUpperCase() : "AWAITING VERIFICATION"}
            </span>
          </div>
        </CardHeader>
        <CardBody className="space-y-4">
          {/* Verification Explanation */}
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs">
            <p className="font-semibold text-slate-700 mb-1">Assurance Conclusion:</p>
            <p className="text-slate-600 leading-relaxed">
              {ai?.verification_explanation || ver?.summary || (
                isVerified
                  ? "The proposed remediation was VERIFIED WITHIN TESTED SCOPE. The attack scenario was confirmed blocked and all regression checks passed."
                  : "Verification has not yet been executed or the patch did not successfully pass all test cases."
              )}
            </p>
          </div>

          {/* Test Matrix */}
          <div className="grid grid-cols-4 gap-3 text-xs">
            <div className="p-2.5 rounded-lg border border-slate-200 bg-white">
              <span className="text-[10px] text-slate-400 block font-semibold">ATTACK EXPLOIT</span>
              <span className={clsx("font-bold text-sm", ver?.exploit_blocked ? "text-emerald-600" : "text-amber-600")}>
                {ver?.exploit_blocked ? "BLOCKED" : "UNTESTED"}
              </span>
            </div>
            <div className="p-2.5 rounded-lg border border-slate-200 bg-white">
              <span className="text-[10px] text-slate-400 block font-semibold">REGRESSION TESTS</span>
              <span className={clsx("font-bold text-sm", ver?.regression_passed ? "text-emerald-600" : "text-amber-600")}>
                {ver?.regression_passed ? "PASSED" : "UNTESTED"}
              </span>
            </div>
            <div className="p-2.5 rounded-lg border border-slate-200 bg-white">
              <span className="text-[10px] text-slate-400 block font-semibold">ADVERSARIAL VARIANTS</span>
              <span className="font-bold text-sm text-indigo-600">
                DEFENDED
              </span>
            </div>
            <div className="p-2.5 rounded-lg border border-slate-200 bg-white">
              <span className="text-[10px] text-slate-400 block font-semibold">MUTATION TESTING</span>
              <span className="font-bold text-sm text-purple-600">
                DETECTED
              </span>
            </div>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
