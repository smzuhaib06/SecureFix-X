"use client";

import { useState } from "react";
import Link from "next/link";
import {
  ShieldX, ShieldCheck, Play, ArrowRight,
  Terminal, User, Lock, AlertTriangle, CheckCircle2,
} from "lucide-react";
import Sidebar from "@/components/layout/Sidebar";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { api } from "@/lib/api";
import { clsx } from "clsx";

const DEMO_API = "http://localhost:8001";

interface ExploitResult {
  status: number;
  body: unknown;
  exploitWorked: boolean;
}

export default function DemoPage() {
  const [step, setStep] = useState<number>(0);
  const [token, setToken] = useState<string>("");
  const [loginLoading, setLoginLoading] = useState(false);
  const [exploitResult, setExploitResult] = useState<ExploitResult | null>(null);
  const [exploitLoading, setExploitLoading] = useState(false);
  const [launchingInv, setLaunchingInv] = useState(false);
  const [invId, setInvId] = useState<string>("");
  const [loginError, setLoginError] = useState("");
  const [postExploitResult, setPostExploitResult] = useState<ExploitResult | null>(null);
  const [retesting, setRetesting] = useState(false);

  // Step 1: Login as Alice
  const handleLogin = async () => {
    setLoginLoading(true);
    setLoginError("");
    try {
      const resp = await fetch(`${DEMO_API}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "alice", password: "alice123" }),
      });
      if (!resp.ok) throw new Error(`Login failed: ${resp.status}`);
      const data = await resp.json();
      setToken(data.access_token);
      setStep(1);
    } catch (e: unknown) {
      setLoginError(e instanceof Error ? e.message : "Login failed — is the demo app running on port 8001?");
    } finally {
      setLoginLoading(false);
    }
  };

  // Step 2: Exploit — Alice accesses Bob's account
  const handleExploit = async () => {
    if (!token) return;
    setExploitLoading(true);
    try {
      const resp = await fetch(`${DEMO_API}/api/accounts/2`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const body = await resp.json();
      setExploitResult({
        status: resp.status,
        body,
        exploitWorked: resp.status === 200,
      });
      setStep(2);
    } catch (e: unknown) {
      setExploitResult({
        status: 0,
        body: { error: e instanceof Error ? e.message : "Network error" },
        exploitWorked: false,
      });
    } finally {
      setExploitLoading(false);
    }
  };

  // Step 3: Launch SECUREFIX investigation
  const handleLaunchInvestigation = async () => {
    setLaunchingInv(true);
    try {
      const inv = await api.createDemoInvestigation();
      setInvId(inv.id);
      setStep(3);
    } catch (e: unknown) {
      console.error(e);
    } finally {
      setLaunchingInv(false);
    }
  };

  // Step 4: Re-test exploit after patch application
  const handlePostFixTest = async () => {
    if (!token) return;
    setRetesting(true);
    try {
      const resp = await fetch(`${DEMO_API}/api/accounts/2`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const body = await resp.json().catch(() => ({}));
      setPostExploitResult({
        status: resp.status,
        body,
        exploitWorked: resp.status === 200,
      });
      setStep(4);
    } catch (e: unknown) {
      setPostExploitResult({
        status: 0,
        body: { error: e instanceof Error ? e.message : "Network error" },
        exploitWorked: false,
      });
    } finally {
      setRetesting(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <header className="bg-white border-b border-slate-200 px-8 py-5">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-xl font-bold text-slate-900">Live Demo</h1>
              <p className="text-sm text-slate-500 mt-0.5">
                Walk through the SECUREFIX demonstration scenario step by step
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs font-medium text-blue-700 bg-blue-50 border border-blue-200 px-3 py-1.5 rounded-lg">
              IBM Bob 2.0 Hackathon
            </div>
          </div>
        </header>

        <main className="flex-1 px-8 py-6 space-y-5 max-w-3xl">
          {/* Step progress */}
          <StepProgress current={step} />

          {/* Step 1: Login */}
          <DemoCard
            stepNum={1}
            title="Login as Alice"
            desc="Authenticate with the SecureBank demo app as Alice (user_id=1)."
            active={step === 0}
            done={step > 0}
          >
            {step === 0 && (
              <div className="space-y-3">
                <CredRow label="Username" value="alice" />
                <CredRow label="Password" value="alice123" />
                <CredRow label="Target"   value={`${DEMO_API}/api/auth/login`} mono />
                {loginError && (
                  <p className="text-xs text-red-600 bg-red-50 border border-red-100 rounded px-3 py-2">
                    {loginError}
                  </p>
                )}
                <button
                  onClick={handleLogin}
                  disabled={loginLoading}
                  className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-blue-700 disabled:opacity-50 transition-colors"
                >
                  <Lock size={13} />
                  {loginLoading ? "Logging in…" : "Login as Alice"}
                </button>
              </div>
            )}
            {step > 0 && (
              <p className="text-sm text-green-700 flex items-center gap-2">
                <CheckCircle2 size={15} className="text-green-500" />
                Authenticated as Alice — JWT token received
              </p>
            )}
          </DemoCard>

          {/* Step 2: Exploit */}
          <DemoCard
            stepNum={2}
            title="Exploit: Alice accesses Bob's account"
            desc={
              <>
                Alice sends <code className="bg-slate-100 px-1 rounded text-xs font-mono">GET /api/accounts/2</code> with her own JWT.
                Bob's account is account_id=2. Alice owns account_id=1.
              </>
            }
            active={step === 1}
            done={step > 1}
          >
            {step === 1 && (
              <div className="space-y-3">
                <div className="bg-slate-900 rounded-lg px-4 py-3 font-mono text-xs text-green-300">
                  <span className="text-slate-500">GET </span>
                  {DEMO_API}/api/accounts/<span className="text-yellow-300 font-bold">2</span>
                  <br />
                  <span className="text-slate-500">Authorization: </span>Bearer alice_token
                </div>
                <button
                  onClick={handleExploit}
                  disabled={exploitLoading}
                  className="flex items-center gap-2 bg-red-600 text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-red-700 disabled:opacity-50 transition-colors"
                >
                  <ShieldX size={13} />
                  {exploitLoading ? "Sending request…" : "Execute Exploit"}
                </button>
              </div>
            )}
            {step > 1 && exploitResult && (
              <div className="space-y-3">
                <div className={clsx(
                  "flex items-start gap-3 px-4 py-3 rounded-lg border",
                  exploitResult.exploitWorked
                    ? "bg-red-50 border-red-200"
                    : "bg-green-50 border-green-200",
                )}>
                  {exploitResult.exploitWorked
                    ? <ShieldX size={18} className="text-red-500 shrink-0 mt-0.5" />
                    : <ShieldCheck size={18} className="text-green-600 shrink-0 mt-0.5" />}
                  <div>
                    <p className={clsx(
                      "text-sm font-bold",
                      exploitResult.exploitWorked ? "text-red-800" : "text-green-800",
                    )}>
                      HTTP {exploitResult.status}{" "}
                      {exploitResult.exploitWorked
                        ? "— VULNERABILITY CONFIRMED"
                        : "— Access Blocked"}
                    </p>
                    <p className="text-xs mt-0.5 text-slate-600">
                      {exploitResult.exploitWorked
                        ? "Alice successfully read Bob's account data without owning it."
                        : "Authorization check blocked the request — fix is working."}
                    </p>
                  </div>
                </div>
                <pre className="text-xs bg-slate-950 text-green-300 rounded-lg p-3 overflow-x-auto max-h-32 overflow-y-auto font-mono">
                  {JSON.stringify(exploitResult.body, null, 2)}
                </pre>
              </div>
            )}
          </DemoCard>

          {/* Step 3: Launch SECUREFIX */}
          <DemoCard
            stepNum={3}
            title="Launch SECUREFIX Investigation"
            desc="Submit the security finding to SECUREFIX. 7 agents will analyze the repository in parallel."
            active={step === 2}
            done={step > 2}
          >
            {step === 2 && (
              <div className="space-y-3">
                <div className="bg-blue-50 border border-blue-100 rounded-lg px-4 py-3 text-xs text-blue-700">
                  <p className="font-semibold mb-1">Issue description:</p>
                  <p className="italic">
                    "Authenticated users may be able to access another user's account data
                    by modifying account_id in GET /api/accounts/&#123;account_id&#125;."
                  </p>
                </div>
                <button
                  onClick={handleLaunchInvestigation}
                  disabled={launchingInv}
                  className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-blue-700 disabled:opacity-50 transition-colors"
                >
                  <Play size={13} />
                  {launchingInv ? "Launching…" : "Start SECUREFIX Investigation"}
                </button>
              </div>
            )}
            {step > 2 && invId && (
              <div className="flex items-center gap-3">
                <CheckCircle2 size={15} className="text-green-500 shrink-0" />
                <div>
                  <p className="text-sm text-green-700 font-medium">
                    Investigation {invId} created
                  </p>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Agents are analyzing the repository…
                  </p>
                </div>
                <Link
                  href={`/investigations/${invId}`}
                  className="ml-auto flex items-center gap-1.5 bg-blue-600 text-white px-4 py-2 rounded-lg text-xs font-semibold hover:bg-blue-700 transition-colors shrink-0"
                >
                  View Investigation
                  <ArrowRight size={12} />
                </Link>
              </div>
            )}
          </DemoCard>

          {/* Step 4: Post-Remediation Verification */}
          {step >= 3 && (
            <DemoCard
              stepNum={4}
              title="Post-Fix Verification: Re-Run Exploit"
              desc="After approving and applying the patch in SECUREFIX, test whether Alice can still access Bob's account."
              active={step === 3}
              done={postExploitResult !== null && postExploitResult.status === 403}
            >
              <div className="space-y-3">
                <p className="text-xs text-slate-600">
                  Sends the exact same request (<code className="bg-slate-100 px-1 rounded font-mono">GET /api/accounts/2</code> with Alice's JWT token) to confirm the ownership check blocks unauthorized access.
                </p>
                <div className="flex items-center gap-3">
                  <button
                    onClick={handlePostFixTest}
                    disabled={retesting}
                    className="flex items-center gap-2 bg-slate-900 text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-slate-800 disabled:opacity-50 transition-colors"
                  >
                    <Play size={13} />
                    {retesting ? "Testing…" : "Re-Test Exploit (Post-Fix)"}
                  </button>
                  {invId && (
                    <Link
                      href={`/investigations/${invId}`}
                      className="text-xs text-blue-600 hover:underline flex items-center gap-1"
                    >
                      View Investigation {invId} <ArrowRight size={11} />
                    </Link>
                  )}
                </div>

                {postExploitResult && (
                  <div className="space-y-2 mt-2">
                    <div className={clsx(
                      "flex items-start gap-3 px-4 py-3 rounded-lg border",
                      postExploitResult.status === 403
                        ? "bg-green-50 border-green-200"
                        : "bg-red-50 border-red-200",
                    )}>
                      {postExploitResult.status === 403
                        ? <ShieldCheck size={18} className="text-green-600 shrink-0 mt-0.5" />
                        : <ShieldX size={18} className="text-red-500 shrink-0 mt-0.5" />}
                      <div>
                        <p className={clsx(
                          "text-sm font-bold",
                          postExploitResult.status === 403 ? "text-green-800" : "text-red-800",
                        )}>
                          HTTP {postExploitResult.status}{" "}
                          {postExploitResult.status === 403
                            ? "— EXPLOIT BLOCKED (FIX CONFIRMED)"
                            : "— VULNERABLE (PATCH NOT APPLIED YET)"}
                        </p>
                        <p className="text-xs mt-0.5 text-slate-600">
                          {postExploitResult.status === 403
                            ? "Alice's unauthorized request was rejected with 403 Forbidden. The BOLA vulnerability is verified remediated."
                            : "Exploit succeeded or patch not yet approved/applied. Go to the investigation detail page to approve the patch."}
                        </p>
                      </div>
                    </div>
                    <pre className="text-xs bg-slate-950 text-green-300 rounded-lg p-3 overflow-x-auto max-h-32 overflow-y-auto font-mono">
                      {JSON.stringify(postExploitResult.body, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </DemoCard>
          )}

          {/* What happens next */}
          {step >= 3 && (
            <Card className="border-blue-200 bg-blue-50">
              <CardBody>
                <p className="text-sm font-semibold text-blue-900 mb-3">What SECUREFIX does next</p>
                <div className="space-y-2">
                  {[
                    { label: "7 agents analyze in parallel", done: true },
                    { label: "Evidence correlated across all signals", done: true },
                    { label: "Root cause identified with confidence score", done: false },
                    { label: "Minimal patch proposed — you approve", done: false },
                    { label: "Regression test auto-generated", done: false },
                    { label: "Tests run — exploit verified blocked", done: false },
                  ].map((item, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs text-blue-800">
                      <div className={clsx(
                        "w-4 h-4 rounded-full flex items-center justify-center shrink-0",
                        item.done ? "bg-green-100" : "bg-blue-100",
                      )}>
                        {item.done
                          ? <CheckCircle2 size={10} className="text-green-600" />
                          : <span className="text-blue-400 text-xs">›</span>}
                      </div>
                      {item.label}
                    </div>
                  ))}
                </div>
              </CardBody>
            </Card>
          )}
        </main>
      </div>
    </div>
  );
}

function StepProgress({ current }: { current: number }) {
  const steps = ["Login", "Exploit", "Investigate", "Done"];
  return (
    <div className="flex items-center gap-0 mb-2">
      {steps.map((label, i) => (
        <div key={i} className="flex items-center">
          <div className={clsx(
            "flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium",
            i < current
              ? "bg-green-100 text-green-700"
              : i === current
              ? "bg-blue-600 text-white"
              : "bg-slate-100 text-slate-400",
          )}>
            {i < current && <CheckCircle2 size={11} />}
            {label}
          </div>
          {i < steps.length - 1 && (
            <div className={clsx(
              "w-8 h-0.5 mx-1",
              i < current ? "bg-green-300" : "bg-slate-200",
            )} />
          )}
        </div>
      ))}
    </div>
  );
}

function DemoCard({
  stepNum, title, desc, active, done, children,
}: {
  stepNum: number;
  title: string;
  desc: React.ReactNode;
  active: boolean;
  done: boolean;
  children?: React.ReactNode;
}) {
  return (
    <Card className={clsx(
      "transition-all",
      done && "border-green-200",
      active && "border-blue-300 shadow-md",
      !active && !done && "opacity-60",
    )}>
      <CardBody>
        <div className="flex items-start gap-3">
          <div className={clsx(
            "w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0 mt-0.5",
            done  ? "bg-green-100 text-green-700" :
            active? "bg-blue-600 text-white" :
                    "bg-slate-100 text-slate-400",
          )}>
            {done ? <CheckCircle2 size={14} /> : stepNum}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-slate-800 mb-0.5">{title}</p>
            <p className="text-xs text-slate-500 mb-3 leading-relaxed">{desc}</p>
            {children}
          </div>
        </div>
      </CardBody>
    </Card>
  );
}

function CredRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center gap-3 text-xs">
      <span className="text-slate-400 w-16 shrink-0">{label}</span>
      <code className={clsx(
        "bg-slate-100 px-2 py-0.5 rounded text-slate-700",
        mono ? "font-mono text-xs" : "font-semibold",
      )}>
        {value}
      </code>
    </div>
  );
}
