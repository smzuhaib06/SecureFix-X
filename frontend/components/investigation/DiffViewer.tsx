"use client";

import type { FilePatch } from "@/lib/types";

interface Props {
  patches: FilePatch[];
}

export default function DiffViewer({ patches }: Props) {
  if (!patches?.length) {
    return (
      <p className="text-sm text-slate-500 italic">No code patches generated.</p>
    );
  }

  return (
    <div className="space-y-4">
      {patches.map((patch, i) => (
        <div key={i} className="rounded-lg border border-slate-200 overflow-hidden">
          {/* File header */}
          <div className="flex items-center justify-between px-4 py-2 bg-slate-50 border-b border-slate-200">
            <code className="text-xs font-mono text-slate-700">{patch.file_path}</code>
            <span className="text-xs text-slate-400">1 change</span>
          </div>

          {/* Explanation */}
          {patch.explanation && (
            <div className="px-4 py-2 bg-blue-50 border-b border-blue-100 text-xs text-blue-700">
              {patch.explanation}
            </div>
          )}

          {/* Diff */}
          <div className="overflow-x-auto">
            <pre className="text-xs font-mono leading-5 p-4">
              {patch.diff.split("\n").map((line, j) => {
                let cls = "text-slate-500";
                if (line.startsWith("+") && !line.startsWith("+++")) cls = "diff-add block";
                else if (line.startsWith("-") && !line.startsWith("---")) cls = "diff-remove block";
                else if (line.startsWith("@@")) cls = "text-blue-500";
                return (
                  <span key={j} className={cls}>
                    {line}
                    {"\n"}
                  </span>
                );
              })}
            </pre>
          </div>
        </div>
      ))}
    </div>
  );
}
