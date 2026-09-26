"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { clsx } from "clsx";
import {
  LayoutDashboard,
  Search,
  FileCode2,
  ShieldCheck,
  Bot,
  CheckCircle2,
  FileText,
  Settings,
  Play,
} from "lucide-react";

const nav = [
  { href: "/dashboard",       icon: LayoutDashboard, label: "Dashboard" },
  { href: "/investigations",  icon: Search,          label: "Investigations" },
  { href: "/demo",            icon: Play,            label: "Live Demo" },
  { href: "/findings",        icon: ShieldCheck,     label: "Findings" },
  { href: "/agents",          icon: Bot,             label: "Agents" },
  { href: "/verification",    icon: CheckCircle2,    label: "Verification" },
  { href: "/reports",         icon: FileText,        label: "Reports" },
  { href: "/settings",        icon: Settings,        label: "Settings" },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-56 shrink-0 bg-white border-r border-slate-200 flex flex-col min-h-screen">
      {/* Brand */}
      <div className="px-5 py-5 border-b border-slate-100">
        <Link href="/" className="flex items-center gap-2 group">
          <div className="w-7 h-7 rounded bg-blue-600 flex items-center justify-center shrink-0">
            <ShieldCheck size={15} className="text-white" />
          </div>
          <span className="font-bold text-slate-900 text-sm tracking-tight">SECUREFIX</span>
        </Link>
        <p className="text-xs text-slate-400 mt-1 ml-9">v1.0 · IBM Bob 2.0</p>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {nav.map(({ href, icon: Icon, label }) => {
          const active = pathname === href || pathname.startsWith(href + "/");
          return (
            <Link
              key={href}
              href={href}
              className={clsx(
                "flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium transition-colors",
                active
                  ? "bg-blue-50 text-blue-700"
                  : "text-slate-600 hover:bg-slate-50 hover:text-slate-900",
              )}
            >
              <Icon size={15} className={active ? "text-blue-600" : "text-slate-400"} />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-slate-100">
        <p className="text-xs text-slate-400">IBM Bob 2.0 Hackathon</p>
        <p className="text-xs text-slate-300">Detect · Fix · Verify</p>
      </div>
    </aside>
  );
}
