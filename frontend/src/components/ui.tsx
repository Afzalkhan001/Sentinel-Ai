import type { ReactNode } from "react";

export const CATEGORY_LABELS: Record<string, string> = {
  prompt_injection: "Prompt Injection",
  jailbreak: "Jailbreak",
  toxicity: "Toxicity & Bias",
  pii_leakage: "PII Leakage",
  tool_security: "Tool Security",
  hallucination: "Hallucination",
  insecure_output: "Offensive Security",
  obfuscation: "Obfuscation",
};

const CATEGORY_STYLES: Record<string, string> = {
  prompt_injection: "bg-fuchsia-500/15 text-fuchsia-300",
  jailbreak: "bg-rose-500/15 text-rose-300",
  toxicity: "bg-amber-500/15 text-amber-300",
  pii_leakage: "bg-violet-500/15 text-violet-300",
  tool_security: "bg-cyan-500/15 text-cyan-300",
  hallucination: "bg-emerald-500/15 text-emerald-300",
  insecure_output: "bg-red-500/15 text-red-300",
  obfuscation: "bg-teal-500/15 text-teal-300",
};

export function categoryLabel(category: string): string {
  return CATEGORY_LABELS[category] ?? category.replace(/_/g, " ");
}

export function CategoryBadge({ category }: { category: string }) {
  return (
    <span className={`badge ${CATEGORY_STYLES[category] ?? "bg-slate-600/30 text-slate-300"}`}>
      {categoryLabel(category)}
    </span>
  );
}

const SEVERITY_STYLES: Record<string, string> = {
  low: "bg-sky-500/15 text-sky-300",
  medium: "bg-amber-500/15 text-amber-300",
  high: "bg-orange-500/15 text-orange-300",
  critical: "bg-rose-500/15 text-rose-300",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge ${SEVERITY_STYLES[severity] ?? "bg-slate-600/30 text-slate-300"}`}>{severity}</span>;
}

const RISK_STYLES: Record<string, string> = {
  Low: "bg-ok/15 text-ok",
  Moderate: "bg-amber-500/15 text-amber-300",
  High: "bg-orange-500/15 text-orange-300",
  Critical: "bg-danger/15 text-danger",
};

export function RiskBadge({ risk }: { risk: string }) {
  return <span className={`badge ${RISK_STYLES[risk] ?? "bg-slate-600/30"}`}>{risk} risk</span>;
}

export function VerdictBadge({ succeeded, error }: { succeeded: boolean; error?: string | null }) {
  if (error) return <span className="badge bg-slate-600/30 text-slate-300">error</span>;
  return succeeded ? (
    <span className="badge bg-danger/15 text-danger">vulnerable</span>
  ) : (
    <span className="badge bg-ok/15 text-ok">blocked</span>
  );
}

export function Section({ title, children, right }: { title: string; children: ReactNode; right?: ReactNode }) {
  return (
    <section className="card p-5">
      <div className="flex items-center justify-between mb-4">
        <h2 className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.14em] text-slate-400">
          <span className="w-1 h-3.5 rounded-full bg-accent-grad" />
          {title}
        </h2>
        {right}
      </div>
      {children}
    </section>
  );
}

export function PageHeader({ title, subtitle, right }: { title: string; subtitle?: string; right?: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <h1 className="text-[26px] font-extrabold tracking-tight text-white">{title}</h1>
        {subtitle && <p className="text-slate-500 text-sm mt-1.5 max-w-2xl">{subtitle}</p>}
      </div>
      {right}
    </div>
  );
}
