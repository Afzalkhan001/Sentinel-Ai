import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useRun, useRunResults, useRuns } from "../hooks/queries";
import { CategoryBadge, PageHeader, RiskBadge, Section, VerdictBadge } from "../components/ui";
import { OwaspBreakdown, ScoreGauge } from "../components/charts";

function RunsList() {
  const { data: runs, isLoading } = useRuns();
  if (isLoading) return <div className="text-slate-500 text-sm">Loading…</div>;
  if (!runs?.length)
    return (
      <div className="text-slate-500 text-sm">
        No scans yet. <Link to="/run" className="text-accent hover:underline">Run your first scan →</Link>
      </div>
    );
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left text-slate-500 border-b border-line">
          <th className="py-2 font-medium">Model</th>
          <th className="py-2 font-medium">Status</th>
          <th className="py-2 font-medium">Score</th>
          <th className="py-2 font-medium">Vulnerable</th>
          <th className="py-2 font-medium">When</th>
        </tr>
      </thead>
      <tbody>
        {runs.map((r) => (
          <tr key={r.id} className="border-b border-line/50 hover:bg-panel2/40">
            <td className="py-3">
              <Link to={`/runs/${r.id}`} className="text-accent hover:underline">
                {r.model_label ?? r.model_id}
              </Link>
            </td>
            <td className="py-3 text-slate-400">{r.status}</td>
            <td className="py-3 text-slate-200">{r.score ?? "—"}</td>
            <td className="py-3 text-slate-400">
              {r.succeeded_count}/{r.total}
            </td>
            <td className="py-3 text-slate-500 text-xs">{new Date(r.created_at).toLocaleString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ResultsTable({ runId }: { runId: string }) {
  const { data: results } = useRunResults(runId, true);
  const [open, setOpen] = useState<string | null>(null);
  if (!results) return null;
  return (
    <div className="space-y-2">
      {results.map((r) => (
        <div key={r.id} className="bg-panel2 border border-line rounded-lg">
          <button
            className="w-full flex items-center gap-3 px-4 py-3 text-left"
            onClick={() => setOpen(open === r.id ? null : r.id)}
          >
            <VerdictBadge succeeded={r.succeeded} error={r.error} />
            <span className="flex-1 text-sm text-slate-200">{r.attack_name}</span>
            {r.category && <CategoryBadge category={r.category} />}
            <span className="text-xs text-slate-500 font-mono hidden lg:inline">{r.owasp}</span>
            <span className="text-xs text-slate-600">{r.latency_ms}ms</span>
          </button>
          {open === r.id && (
            <div className="px-4 pb-4 space-y-3 border-t border-line pt-3">
              {r.error && <div className="text-danger text-xs">Error: {r.error}</div>}
              <div>
                <div className="text-xs text-slate-500 mb-1">Prompt sent</div>
                <pre className="text-xs bg-bg border border-line rounded p-2 whitespace-pre-wrap text-slate-300">
                  {r.prompt_sent}
                </pre>
              </div>
              <div>
                <div className="text-xs text-slate-500 mb-1">
                  Model response · detection: {r.detection_method} · confidence {Math.round((r.confidence ?? 0) * 100)}%
                </div>
                <pre className="text-xs bg-bg border border-line rounded p-2 whitespace-pre-wrap text-slate-300 max-h-60 overflow-y-auto">
                  {r.response_text || "(empty)"}
                </pre>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function RunDetail({ runId }: { runId: string }) {
  const { data: run } = useRun(runId);
  if (!run) return <div className="text-slate-500 text-sm">Loading…</div>;

  const running = run.status === "running";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <Link to="/runs" className="text-xs text-slate-500 hover:text-accent">← All scans</Link>
          <h1 className="text-[26px] font-extrabold tracking-tight text-white mt-1">{run.model_label}</h1>
        </div>
        {run.risk_level && <RiskBadge risk={run.risk_level} />}
      </div>

      {run.status === "failed" && <div className="card p-4 text-danger text-sm">Scan failed: {run.error}</div>}

      {running ? (
        <div className="card p-8 text-center text-slate-400">
          <div className="animate-pulse text-accent text-lg">Running {run.total} attacks…</div>
          <div className="text-xs text-slate-500 mt-2">This page updates automatically.</div>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-3 gap-4">
            <Section title="Security Score">
              <div className="flex justify-center">
                <ScoreGauge score={run.score ?? 0} />
              </div>
            </Section>
            <Section title="Attack Success">
              <div className="flex flex-col items-center justify-center h-40">
                <span className="text-5xl font-extrabold tracking-tight text-danger drop-shadow-[0_2px_12px_rgba(244,63,94,0.35)]">
                  {run.attack_success_pct ?? 0}%
                </span>
                <span className="text-sm text-slate-500 mt-3">
                  <span className="text-slate-300 font-semibold">{run.succeeded_count}</span> of {run.total} attacks
                  breached
                </span>
              </div>
            </Section>
            <Section title="OWASP LLM Breakdown">
              {run.owasp_breakdown?.length ? (
                <OwaspBreakdown data={run.owasp_breakdown} />
              ) : (
                <div className="text-slate-500 text-sm">No data</div>
              )}
            </Section>
          </div>

          {run.recommendations && run.recommendations.length > 0 && (
            <Section title="Recommendations">
              <ul className="space-y-3">
                {run.recommendations.map((rec, i) => (
                  <li key={i} className="flex gap-3">
                    <span className="badge bg-accent/15 text-accent font-mono shrink-0">{rec.owasp}</span>
                    <span className="text-sm text-slate-300">{rec.message}</span>
                  </li>
                ))}
              </ul>
            </Section>
          )}

          <Section title="Per-attack results">
            <ResultsTable runId={runId} />
          </Section>
        </>
      )}
    </div>
  );
}

export default function DashboardPage() {
  const { runId } = useParams();
  if (runId) return <RunDetail runId={runId} />;
  return (
    <div className="space-y-7">
      <PageHeader title="Scan Results" subtitle="History of every security scan you've run." />
      <Section title="All scans">
        <RunsList />
      </Section>
    </div>
  );
}
