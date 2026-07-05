import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAttacks, useCreateRun, useModels } from "../hooks/queries";
import { PageHeader, Section, SeverityBadge, categoryLabel } from "../components/ui";
import type { Attack } from "../api/types";

export default function RunPage() {
  const { data: models } = useModels();
  const { data: attacks } = useAttacks();
  const createRun = useCreateRun();
  const navigate = useNavigate();

  const [modelId, setModelId] = useState<string>("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [judge, setJudge] = useState(false);
  const [samples, setSamples] = useState(1);

  useEffect(() => {
    if (!modelId && models?.length) {
      setModelId(models.find((m) => m.is_default)?.id ?? models[0].id);
    }
  }, [models, modelId]);

  useEffect(() => {
    if (attacks && selected.size === 0) setSelected(new Set(attacks.map((a) => a.id)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attacks]);

  const grouped = useMemo(() => {
    const g: Record<string, Attack[]> = {};
    for (const a of attacks ?? []) (g[a.category] ??= []).push(a);
    return g;
  }, [attacks]);

  const toggle = (id: string) => {
    const next = new Set(selected);
    next.has(id) ? next.delete(id) : next.add(id);
    setSelected(next);
  };

  const toggleCategory = (cat: string) => {
    const ids = grouped[cat].map((a) => a.id);
    const allOn = ids.every((i) => selected.has(i));
    const next = new Set(selected);
    ids.forEach((i) => (allOn ? next.delete(i) : next.add(i)));
    setSelected(next);
  };

  const allSelected = attacks && selected.size === attacks.length;
  const toggleAll = () => setSelected(allSelected ? new Set() : new Set(attacks?.map((a) => a.id)));

  const launch = async () => {
    const run = await createRun.mutateAsync({
      model_id: modelId,
      attack_ids: Array.from(selected),
      use_llm_judge: judge,
      samples,
    });
    navigate(`/runs/${run.id}`);
  };

  return (
    <div className="space-y-7">
      <PageHeader title="New Security Scan" subtitle="Pick a target model and choose which attacks to run against it." />

      <Section title="Target model">
        <select className="input" value={modelId} onChange={(e) => setModelId(e.target.value)}>
          {models?.map((m) => (
            <option key={m.id} value={m.id}>
              {m.name} — {m.model_name}
            </option>
          ))}
        </select>
      </Section>

      <Section
        title={`Attacks (${selected.size}/${attacks?.length ?? 0})`}
        right={
          <button className="text-xs text-accent hover:underline" onClick={toggleAll}>
            {allSelected ? "Deselect all" : "Select all"}
          </button>
        }
      >
        <div className="space-y-5">
          {Object.entries(grouped).map(([cat, list]) => {
            const on = list.filter((a) => selected.has(a.id)).length;
            return (
              <div key={cat}>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                    {categoryLabel(cat)} <span className="text-slate-600">({on}/{list.length})</span>
                  </span>
                  <button className="text-xs text-accent hover:underline" onClick={() => toggleCategory(cat)}>
                    toggle
                  </button>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {list.map((a) => (
                    <label
                      key={a.id}
                      className="flex items-center gap-3 px-3 py-2 rounded-lg bg-panel2 border border-line cursor-pointer hover:border-accent/50"
                    >
                      <input type="checkbox" checked={selected.has(a.id)} onChange={() => toggle(a.id)} />
                      <span className="flex-1 text-sm text-slate-200">{a.name}</span>
                      <SeverityBadge severity={a.severity} />
                    </label>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </Section>

      <Section title="Reliability">
        <div className="grid md:grid-cols-2 gap-4">
          <label className="flex items-start gap-2.5 text-sm text-slate-300 bg-panel2/40 border border-line rounded-lg p-3 cursor-pointer">
            <input type="checkbox" className="mt-0.5" checked={judge} onChange={(e) => setJudge(e.target.checked)} />
            <span>
              <b>LLM judge tie-breaker</b>
              <span className="block text-xs text-slate-500 mt-0.5">
                On ambiguous verdicts only, ask the model to judge itself. Higher accuracy, a few extra calls.
              </span>
            </span>
          </label>
          <div className="bg-panel2/40 border border-line rounded-lg p-3">
            <div className="text-sm text-slate-300 font-semibold">Samples per attack</div>
            <div className="text-xs text-slate-500 mt-0.5 mb-2">
              Run each attack N times and vote — catches intermittent breaches. More samples = more calls.
            </div>
            <div className="flex gap-2">
              {[1, 3, 5].map((n) => (
                <button
                  key={n}
                  onClick={() => setSamples(n)}
                  className={`px-3 py-1 rounded-lg text-sm ${
                    samples === n ? "bg-accent text-slate-950 font-semibold" : "bg-bg2 border border-line text-slate-400"
                  }`}
                >
                  {n}×
                </button>
              ))}
            </div>
          </div>
        </div>
      </Section>

      <div className="flex items-center justify-end">
        <button
          className="btn-primary text-base px-6 py-2.5"
          disabled={!modelId || selected.size === 0 || createRun.isPending}
          onClick={launch}
        >
          {createRun.isPending ? "Starting…" : `Run ${selected.size} attacks →`}
        </button>
      </div>
      {createRun.isError && <div className="text-danger text-sm">{(createRun.error as Error).message}</div>}
    </div>
  );
}
