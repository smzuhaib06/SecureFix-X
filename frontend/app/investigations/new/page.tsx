"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldAlert, Zap, ArrowLeft } from "lucide-react";
import Link from "next/link";
import Sidebar from "@/components/layout/Sidebar";
import { Card, CardBody } from "@/components/ui/Card";
import { api } from "@/lib/api";

export default function NewInvestigationPage() {
  const router = useRouter();
  const [title, setTitle] = useState("");
  const [issue, setIssue] = useState("");
  const [repoPath, setRepoPath] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !issue.trim()) return;
    setSubmitting(true);
    setError("");
    try {
      const inv = await api.createInvestigation({
        title: title.trim(),
        issue_description: issue.trim(),
        repository_path: repoPath.trim() || undefined,
        repository_url: repoUrl.trim() || undefined,
      });
      router.push(`/investigations/${inv.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create investigation");
      setSubmitting(false);
    }
  };

  const handleDemoClick = async () => {
    setSubmitting(true);
    setError("");
    try {
      const inv = await api.createDemoInvestigation();
      router.push(`/investigations/${inv.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start demo investigation");
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <header className="bg-white border-b border-slate-200 px-8 py-5">
          <div className="flex items-center gap-3">
            <Link href="/investigations" className="text-slate-400 hover:text-slate-600 transition-colors">
              <ArrowLeft size={18} />
            </Link>
            <div>
              <h1 className="text-xl font-bold text-slate-900">New Investigation</h1>
              <p className="text-sm text-slate-500 mt-0.5">Submit a security finding to analyze</p>
            </div>
          </div>
        </header>

        <main className="flex-1 px-8 py-6 max-w-2xl">
          {/* Demo shortcut */}
          <Card className="mb-6 border-blue-200 bg-blue-50">
            <CardBody>
              <div className="flex items-start gap-4">
                <div className="w-9 h-9 bg-blue-600 rounded-lg flex items-center justify-center shrink-0">
                  <Zap size={16} className="text-white" />
                </div>
                <div className="flex-1">
                  <p className="text-sm font-semibold text-blue-900">Run Demo Investigation</p>
                  <p className="text-xs text-blue-700 mt-1">
                    Instantly analyze the SecureBank demo app for BOLA (Broken Object Level Authorization)
                    — the complete hackathon demonstration scenario.
                  </p>
                  <button
                    onClick={handleDemoClick}
                    disabled={submitting}
                    className="mt-3 inline-flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg text-xs font-semibold hover:bg-blue-700 disabled:opacity-50 transition-colors"
                  >
                    {submitting ? "Starting..." : "Start Demo Investigation"}
                  </button>
                </div>
              </div>
            </CardBody>
          </Card>

          {/* Custom form */}
          <Card>
            <CardBody>
              <p className="text-sm font-semibold text-slate-700 mb-4">Custom Investigation</p>
              <form onSubmit={handleSubmit} className="space-y-5">
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1.5">
                    Investigation Title
                  </label>
                  <input
                    type="text"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="e.g. Broken Access Control in Account API"
                    className="w-full border border-slate-200 rounded-lg px-3 py-2.5 text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent placeholder:text-slate-300"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1.5">
                    Issue / Security Finding
                  </label>
                  <textarea
                    value={issue}
                    onChange={(e) => setIssue(e.target.value)}
                    placeholder="Describe the security issue in detail. e.g. 'Authenticated users can access other users' account data by modifying the account_id in the API request.'"
                    rows={5}
                    className="w-full border border-slate-200 rounded-lg px-3 py-2.5 text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent placeholder:text-slate-300 resize-none"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1.5">
                    GitHub Repository URL{" "}
                    <span className="font-normal text-slate-400">(optional — cloned automatically)</span>
                  </label>
                  <input
                    type="url"
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo"
                    className="w-full border border-slate-200 rounded-lg px-3 py-2.5 text-sm text-slate-800 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent placeholder:text-slate-300"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1.5">
                    Local Repository Path{" "}
                    <span className="font-normal text-slate-400">(optional — overrides URL)</span>
                  </label>
                  <input
                    type="text"
                    value={repoPath}
                    onChange={(e) => setRepoPath(e.target.value)}
                    placeholder="/path/to/repository"
                    className="w-full border border-slate-200 rounded-lg px-3 py-2.5 text-sm text-slate-800 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent placeholder:text-slate-300"
                  />
                </div>

                {error && (
                  <div className="flex items-center gap-2 px-3 py-2.5 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
                    <ShieldAlert size={14} />
                    {error}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={submitting || !title.trim() || !issue.trim()}
                  className="w-full bg-slate-900 text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-slate-800 disabled:opacity-40 transition-colors"
                >
                  {submitting ? "Creating investigation..." : "Create Investigation"}
                </button>
              </form>
            </CardBody>
          </Card>
        </main>
      </div>
    </div>
  );
}
