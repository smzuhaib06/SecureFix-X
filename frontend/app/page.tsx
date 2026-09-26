import Link from "next/link";
import { ShieldCheck, ArrowRight, Search, Wrench, CheckCircle2, Zap } from "lucide-react";

const steps = [
  { icon: Search,       label: "Detect",      desc: "Submit a security finding or repository URL" },
  { icon: Zap,          label: "Investigate",  desc: "6 specialized AI agents analyze in parallel" },
  { icon: ShieldCheck,  label: "Correlate",    desc: "Evidence correlated across all signals" },
  { icon: Wrench,       label: "Fix",          desc: "Minimal patch proposed with human approval" },
  { icon: CheckCircle2, label: "Verify",       desc: "Regression tests confirm exploit is blocked" },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-white flex flex-col">
      {/* Nav */}
      <header className="border-b border-slate-100 px-8 py-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded bg-blue-600 flex items-center justify-center">
            <ShieldCheck size={15} className="text-white" />
          </div>
          <span className="font-bold text-slate-900 tracking-tight">SECUREFIX</span>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/demo"
            className="flex items-center gap-1.5 text-sm text-slate-700 bg-slate-100 hover:bg-slate-200 px-3.5 py-2 rounded-lg font-medium transition-colors"
          >
            <Zap size={14} className="text-blue-600" />
            Live Demo
          </Link>
          <Link
            href="/dashboard"
            className="text-sm text-slate-600 hover:text-slate-900 font-medium transition-colors"
          >
            Dashboard
          </Link>
          <Link
            href="/investigations/new"
            className="text-sm bg-blue-600 text-white px-4 py-2 rounded-lg font-medium hover:bg-blue-700 transition-colors"
          >
            New Investigation
          </Link>
        </div>
      </header>

      {/* Hero */}
      <main className="flex-1 flex flex-col items-center justify-center px-8 py-20 text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-blue-50 rounded-full text-xs font-medium text-blue-700 mb-6 border border-blue-100">
          <Zap size={12} />
          IBM Bob 2.0 Hackathon · 2026
        </div>

        <h1 className="text-5xl font-bold text-slate-900 tracking-tight max-w-2xl leading-tight">
          From security finding to{" "}
          <span className="text-blue-600">verified fix.</span>
        </h1>

        <p className="text-xl text-slate-500 mt-5 max-w-xl leading-relaxed">
          Autonomous AI engineering for investigating, fixing, testing, and verifying
          software security failures — end to end.
        </p>

        <div className="flex items-center gap-4 mt-8 flex-wrap justify-center">
          <Link
            href="/demo"
            className="flex items-center gap-2 bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 transition-colors text-sm shadow-sm"
          >
            <Zap size={15} />
            Live Demo: SecureBank BOLA
            <ArrowRight size={15} />
          </Link>
          <Link
            href="/investigations/new"
            className="flex items-center gap-2 bg-white text-slate-700 px-6 py-3 rounded-lg font-semibold hover:bg-slate-50 transition-colors text-sm border border-slate-200"
          >
            Custom Investigation
          </Link>
          <Link
            href="/dashboard"
            className="flex items-center gap-2 text-slate-500 hover:text-slate-800 px-4 py-3 rounded-lg font-medium text-sm transition-colors"
          >
            Dashboard
          </Link>
        </div>

        {/* Workflow steps */}
        <div className="mt-20 w-full max-w-3xl">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-8">
            The complete remediation loop
          </p>
          <div className="flex items-start justify-center gap-2 flex-wrap">
            {steps.map((step, i) => (
              <div key={i} className="flex items-center gap-2">
                <div className="flex flex-col items-center text-center w-28">
                  <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center mb-2">
                    <step.icon size={18} className="text-blue-600" />
                  </div>
                  <span className="text-sm font-semibold text-slate-800">{step.label}</span>
                  <span className="text-xs text-slate-400 mt-0.5 leading-snug">{step.desc}</span>
                </div>
                {i < steps.length - 1 && (
                  <ArrowRight size={16} className="text-slate-300 mb-8 shrink-0" />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Differentiator */}
        <div className="mt-20 grid grid-cols-2 gap-6 max-w-2xl w-full">
          <div className="bg-red-50 border border-red-100 rounded-xl p-5 text-left">
            <p className="text-xs font-semibold text-red-500 uppercase tracking-wide mb-3">Traditional approach</p>
            <div className="space-y-1.5 text-sm text-slate-600">
              {["Detect", "Alert", "Manual investigation", "Manual fix", "No regression test", "Unverified"].map((s) => (
                <div key={s} className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-300 shrink-0" />
                  {s}
                </div>
              ))}
            </div>
          </div>
          <div className="bg-green-50 border border-green-100 rounded-xl p-5 text-left">
            <p className="text-xs font-semibold text-green-600 uppercase tracking-wide mb-3">SECUREFIX</p>
            <div className="space-y-1.5 text-sm text-slate-600">
              {["Detect", "Understand", "AI investigates", "Human approves fix", "Regression test generated", "Verified"].map((s) => (
                <div key={s} className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400 shrink-0" />
                  {s}
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>

      <footer className="border-t border-slate-100 px-8 py-4 text-center text-xs text-slate-400">
        SECUREFIX · IBM Bob 2.0 Hackathon · Detect. Understand. Fix. Verify.
      </footer>
    </div>
  );
}
