import { useState } from "react";
import type { Finding, ScanResult } from "../api/types";
import { RiskBadge, Section, SeverityBadge } from "./ui";
import { ScoreGauge } from "./charts";
import { downloadJson } from "../api/download";

const SEV_COLORS: Record<string, string> = {
  critical: "border-l-danger",
  high: "border-l-orange-500",
  medium: "border-l-amber-500",
  low: "border-l-sky-500",
};

function SeverityPill({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className="flex flex-col items-center px-4 py-2 rounded-xl bg-panel2/60 border border-line min-w-[74px]">
      <span className={`text-2xl font-extrabold ${color}`}>{count}</span>
      <span className="text-[10px] uppercase tracking-wider text-slate-500 mt-0.5">{label}</span>
    </div>
  );
}

function FindingCard({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`bg-panel2/50 border border-line border-l-[3px] ${SEV_COLORS[f.severity] ?? "border-l-slate-500"} rounded-lg`}>
      <button className="w-full flex items-center gap-3 px-4 py-3 text-left" onClick={() => setOpen(!open)}>
        <SeverityBadge severity={f.severity} />
        <span className="flex-1 text-sm text-slate-100 font-medium">{f.title}</span>
        {f.source === "ai" && <span className="badge bg-accent2/15 text-indigo-300">AI</span>}
        <span className="badge bg-panel2 text-slate-400 hidden md:inline">{f.category}</span>
        <span className="text-slate-600 text-xs">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-2.5 border-t border-line pt-3">
          {f.location && (
            <div className="text-xs font-mono text-slate-400 break-all">
              📍 {f.location}
              {f.line ? <span className="text-accent">:{f.line}</span> : null}
              {f.owasp ? <span className="ml-2 text-slate-600">· {f.owasp}</span> : null}
            </div>
          )}
          {f.evidence && (
            <pre className="text-xs bg-bg2 border border-line rounded p-2 whitespace-pre-wrap text-rose-300 overflow-x-auto">
              {f.evidence}
            </pre>
          )}
          {f.description && <p className="text-sm text-slate-300">{f.description}</p>}
          {f.recommendation && (
            <p className="text-sm text-slate-400">
              <span className="text-ok font-semibold">Fix: </span>
              {f.recommendation}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export function ScanReport({ scan, target }: { scan: ScanResult; target: string }) {
  if (scan.status === "running") {
    return (
      <div className="card p-10 text-center">
        <div className="text-accent text-lg animate-pulse">Scanning {target}…</div>
        <div className="text-xs text-slate-500 mt-2">This page updates automatically when it finishes.</div>
      </div>
    );
  }
  if (scan.status === "failed") {
    return <div className="card p-5 text-danger text-sm">Scan failed: {scan.error}</div>;
  }

  const sc = scan.severity_counts ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const findings = scan.findings ?? [];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-3 gap-4">
        <Section title="Security Score">
          <div className="flex justify-center">
            <ScoreGauge score={scan.score ?? 0} />
          </div>
          {scan.risk_level && (
            <div className="flex justify-center mt-3">
              <RiskBadge risk={scan.risk_level} />
            </div>
          )}
        </Section>
        <Section title="Findings by severity">
          <div className="grid grid-cols-2 gap-2 h-40 content-center">
            <SeverityPill label="Critical" count={sc.critical} color="text-danger" />
            <SeverityPill label="High" count={sc.high} color="text-orange-400" />
            <SeverityPill label="Medium" count={sc.medium} color="text-amber-400" />
            <SeverityPill label="Low" count={sc.low} color="text-sky-400" />
          </div>
        </Section>
        <Section title="Summary">
          <div className="flex flex-col items-center justify-center h-40 text-center">
            <span className="text-5xl font-extrabold text-white">{scan.total_findings}</span>
            <span className="text-sm text-slate-500 mt-2">total issues found</span>
            {scan.use_ai && <span className="badge bg-accent2/15 text-indigo-300 mt-3">AI review included</span>}
          </div>
        </Section>
      </div>

      <Section
        title={`Findings (${findings.length})`}
        right={
          <button
            className="text-xs text-accent hover:text-sky-300 font-medium"
            onClick={() => downloadJson(`sentinel-scan-${scan.id.slice(0, 8)}`, scan)}
          >
            ↓ Export JSON
          </button>
        }
      >
        {findings.length === 0 ? (
          <div className="text-center py-8 text-ok">✓ No issues detected. Nice and clean!</div>
        ) : (
          <div className="space-y-2">
            {findings.map((f, i) => (
              <FindingCard key={`${f.id}-${i}`} f={f} />
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}
