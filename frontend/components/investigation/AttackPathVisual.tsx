"use client";

import { ChevronDown, ShieldX, ShieldCheck, User, Database, Globe } from "lucide-react";

interface Props {
  steps: string[];
}

const ICONS: Record<string, React.ElementType> = {
  attacker: User,
  request: Globe,
  database: Database,
  "authentication ✓": ShieldCheck,
  "authorization ✗": ShieldX,
};

function stepIcon(step: string): React.ElementType {
  const lower = step.toLowerCase();
  for (const [k, Icon] of Object.entries(ICONS)) {
    if (lower.includes(k)) return Icon;
  }
  return Globe;
}

function stepColor(step: string): string {
  const lower = step.toLowerCase();
  if (lower.includes("✗") || lower.includes("missing") || lower.includes("bypass")) {
    return "border-red-300 bg-red-50 text-red-800";
  }
  if (lower.includes("✓") || lower.includes("valid")) {
    return "border-green-300 bg-green-50 text-green-800";
  }
  if (lower.includes("attacker")) {
    return "border-orange-300 bg-orange-50 text-orange-800";
  }
  return "border-slate-200 bg-white text-slate-700";
}

export default function AttackPathVisual({ steps }: Props) {
  if (!steps?.length) return null;

  return (
    <div className="flex flex-col items-center gap-0 w-full max-w-sm mx-auto">
      {steps.map((step, i) => {
        const Icon = stepIcon(step);
        const color = stepColor(step);
        return (
          <div key={i} className="flex flex-col items-center w-full">
            <div className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border w-full text-sm font-medium ${color}`}>
              <Icon size={14} className="shrink-0" />
              <span>{step}</span>
            </div>
            {i < steps.length - 1 && (
              <ChevronDown size={16} className="text-slate-400 my-0.5" />
            )}
          </div>
        );
      })}
    </div>
  );
}
