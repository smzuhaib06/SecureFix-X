"use client";

import { useState, useEffect } from "react";
import { Settings, CheckCircle2, ExternalLink } from "lucide-react";
import Sidebar from "@/components/layout/Sidebar";
import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { api } from "@/lib/api";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const DEMO_APP_URL = "http://localhost:8001";

export default function SettingsPage() {
  const [backendStatus, setBackendStatus] = useState<"checking" | "online" | "offline">("checking");
  const [demoStatus, setDemoStatus] = useState<"checking" | "online" | "offline">("checking");

  useEffect(() => {
    fetch(`${API_BASE}/health`)
      .then((r) => setBackendStatus(r.ok ? "online" : "offline"))
      .catch(() => setBackendStatus("offline"));

    fetch(`${DEMO_APP_URL}/health`)
      .then((r) => setDemoStatus(r.ok ? "online" : "offline"))
      .catch(() => setDemoStatus("offline"));
  }, []);

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <header className="bg-white border-b border-slate-200 px-8 py-5">
          <h1 className="text-xl font-bold text-slate-900">Settings</h1>
          <p className="text-sm text-slate-500 mt-0.5">Configuration and service status</p>
        </header>

        <main className="flex-1 px-8 py-6 space-y-5 max-w-2xl">
          {/* Service status */}
          <Card>
            <CardHeader>
              <p className="text-sm font-semibold text-slate-700">Service Status</p>
            </CardHeader>
            <CardBody className="space-y-3">
              <ServiceRow
                name="SECUREFIX Backend"
                url={`${API_BASE}/docs`}
                status={backendStatus}
                detail={API_BASE}
              />
              <ServiceRow
                name="SecureBank Demo App"
                url={`${DEMO_APP_URL}/docs`}
                status={demoStatus}
                detail={DEMO_APP_URL}
              />
            </CardBody>
          </Card>

          {/* Demo credentials */}
          <Card>
            <CardHeader>
              <p className="text-sm font-semibold text-slate-700">Demo Credentials</p>
            </CardHeader>
            <CardBody>
              <p className="text-xs text-slate-500 mb-3">
                SecureBank demo users for testing the BOLA vulnerability.
              </p>
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-xs text-slate-400 uppercase tracking-wide border-b border-slate-100">
                    <th className="text-left pb-2">Username</th>
                    <th className="text-left pb-2">Password</th>
                    <th className="text-left pb-2">User ID</th>
                    <th className="text-left pb-2">Account ID</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {[
                    { user: "alice", pw: "alice123", id: 1, acc: 1 },
                    { user: "bob",   pw: "bob123",   id: 2, acc: "2, 3" },
                    { user: "carol", pw: "carol123", id: 3, acc: 4 },
                  ].map((u) => (
                    <tr key={u.user} className="text-slate-600">
                      <td className="py-2 font-mono font-medium">{u.user}</td>
                      <td className="py-2 font-mono text-slate-400">{u.pw}</td>
                      <td className="py-2 font-mono">{u.id}</td>
                      <td className="py-2 font-mono">{u.acc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardBody>
          </Card>

          {/* Demo exploit info */}
          <Card>
            <CardHeader>
              <p className="text-sm font-semibold text-slate-700">Demo Vulnerability</p>
            </CardHeader>
            <CardBody className="space-y-3">
              <div className="bg-red-50 border border-red-100 rounded-lg px-4 py-3">
                <p className="text-xs font-semibold text-red-700 uppercase tracking-wide mb-1">
                  Broken Object Level Authorization (BOLA)
                </p>
                <p className="text-xs text-red-600">
                  Login as alice → access{" "}
                  <code className="bg-red-100 px-1 py-0.5 rounded font-mono">
                    GET /api/accounts/2
                  </code>{" "}
                  → receive Bob's account data (200 OK before fix, 403 after fix)
                </p>
              </div>
              <div className="text-xs text-slate-500 space-y-1">
                <p><span className="font-medium">Vulnerable endpoint:</span> <code className="font-mono bg-slate-100 px-1 rounded">GET /api/accounts/&#123;account_id&#125;</code></p>
                <p><span className="font-medium">Root cause:</span> Authentication present, authorization absent</p>
                <p><span className="font-medium">CWE:</span> CWE-639 (Authorization Bypass Through User-Controlled Key)</p>
                <p><span className="font-medium">CVSS:</span> 8.1 (High)</p>
              </div>
            </CardBody>
          </Card>

          {/* Quick links */}
          <Card>
            <CardHeader>
              <p className="text-sm font-semibold text-slate-700">Quick Links</p>
            </CardHeader>
            <CardBody className="grid grid-cols-2 gap-2">
              {[
                { label: "Backend API Docs",   url: `${API_BASE}/docs` },
                { label: "Demo App API Docs",  url: `${DEMO_APP_URL}/docs` },
                { label: "Backend OpenAPI",    url: `${API_BASE}/openapi.json` },
                { label: "Demo App OpenAPI",   url: `${DEMO_APP_URL}/openapi.json` },
              ].map((link) => (
                <a
                  key={link.url}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-xs text-blue-600 hover:text-blue-800 hover:underline"
                >
                  <ExternalLink size={11} />
                  {link.label}
                </a>
              ))}
            </CardBody>
          </Card>

          {/* About */}
          <Card>
            <CardHeader>
              <p className="text-sm font-semibold text-slate-700">About SECUREFIX</p>
            </CardHeader>
            <CardBody className="text-xs text-slate-500 space-y-1">
              <p><span className="font-medium text-slate-600">Version:</span> 1.0.0</p>
              <p><span className="font-medium text-slate-600">Built for:</span> IBM Bob 2.0 Hackathon 2026</p>
              <p><span className="font-medium text-slate-600">Stack:</span> Next.js 14 · FastAPI · Python 3.11 · SQLite</p>
              <p><span className="font-medium text-slate-600">Tagline:</span> Detect. Understand. Fix. Verify.</p>
            </CardBody>
          </Card>
        </main>
      </div>
    </div>
  );
}

function ServiceRow({
  name, url, status, detail,
}: {
  name: string;
  url: string;
  status: "checking" | "online" | "offline";
  detail: string;
}) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm font-medium text-slate-700">{name}</p>
        <p className="text-xs text-slate-400 font-mono mt-0.5">{detail}</p>
      </div>
      <div className="flex items-center gap-2">
        {status === "checking" && (
          <span className="text-xs text-slate-400 animate-pulse">checking…</span>
        )}
        {status === "online" && (
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-xs text-green-700 bg-green-50 border border-green-200 px-2.5 py-1 rounded-lg hover:bg-green-100 transition-colors"
          >
            <CheckCircle2 size={11} />
            Online
          </a>
        )}
        {status === "offline" && (
          <span className="text-xs text-red-600 bg-red-50 border border-red-200 px-2.5 py-1 rounded-lg">
            Offline
          </span>
        )}
      </div>
    </div>
  );
}
