import { useMemo, useState } from "react";
import { useAttacks } from "../hooks/queries";
import { CategoryBadge, PageHeader, SeverityBadge, categoryLabel } from "../components/ui";

export default function AttackLibraryPage() {
  const { data: attacks, isLoading } = useAttacks();
  const [filter, setFilter] = useState<string>("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const a of attacks ?? []) c[a.category] = (c[a.category] ?? 0) + 1;
    return c;
  }, [attacks]);

  const categories = ["all", ...Object.keys(counts)];
  const filtered = attacks?.filter((a) => filter === "all" || a.category === filter) ?? [];

  return (
    <div className="space-y-7">
      <PageHeader
        title="Attack Library"
        subtitle={`${attacks?.length ?? 0} built-in adversarial tests across ${Object.keys(counts).length} categories, mapped to the OWASP LLM Top 10.`}
      />

      <div className="flex gap-2 flex-wrap">
        {categories.map((c) => {
          const active = filter === c;
          return (
            <button
              key={c}
              onClick={() => setFilter(c)}
              className={`px-3 py-1.5 rounded-xl text-sm font-medium transition-all ${
                active
                  ? "bg-accent-grad text-slate-950 shadow-[0_6px_18px_-8px_rgba(56,189,248,0.8)]"
                  : "bg-panel2/60 border border-line text-slate-400 hover:text-slate-200 hover:border-accent/40"
              }`}
            >
              {c === "all" ? "All" : categoryLabel(c)}
              <span className={`ml-1.5 text-xs ${active ? "opacity-70" : "opacity-50"}`}>
                {c === "all" ? attacks?.length ?? 0 : counts[c]}
              </span>
            </button>
          );
        })}
      </div>

      {isLoading ? (
        <div className="text-slate-500 text-sm">Loading…</div>
      ) : (
        <div className="grid grid-cols-2 gap-4">
          {filtered.map((a, i) => (
            <div
              key={a.id}
              style={{ animationDelay: `${Math.min(i * 30, 300)}ms` }}
              className="card p-4 animate-fade-up transition-all duration-200 hover:-translate-y-0.5 hover:border-accent/40 hover:shadow-glow"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="font-semibold text-slate-100">{a.name}</div>
                  <div className="text-xs text-slate-500 mt-0.5 font-mono">{a.owasp}</div>
                </div>
                <SeverityBadge severity={a.severity} />
              </div>
              <p className="text-sm text-slate-400 mt-2 leading-relaxed">{a.description}</p>
              <button
                className="text-xs text-accent mt-3 hover:text-sky-300 font-medium"
                onClick={() => setExpanded(expanded === a.id ? null : a.id)}
              >
                {expanded === a.id ? "Hide prompt ↑" : "Show prompt ↓"}
              </button>
              {expanded === a.id && (
                <pre className="mt-2 text-xs bg-bg2 border border-line rounded-xl p-3 whitespace-pre-wrap text-slate-300 overflow-x-auto animate-fade-up">
                  {a.prompt_template}
                </pre>
              )}
              <div className="flex gap-1.5 mt-3.5 flex-wrap items-center">
                <CategoryBadge category={a.category} />
                {a.tags.map((t) => (
                  <span key={t} className="badge bg-panel2/70 text-slate-500">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
