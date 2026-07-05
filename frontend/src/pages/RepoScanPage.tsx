import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useCreateRepoScan, useModels, useRepoScan, useRepoScans } from "../hooks/queries";
import { PageHeader, RiskBadge, Section } from "../components/ui";
import { ScanReport } from "../components/ScanReport";

function LaunchForm() {
  const create = useCreateRepoScan();
  const { data: models } = useModels();
  const navigate = useNavigate();
  const [url, setUrl] = useState("");
  const [useAi, setUseAi] = useState(false);
  const [reviewer, setReviewer] = useState("");

  const launch = async () => {
    const s = await create.mutateAsync({
      repo_url: url.trim(),
      use_ai: useAi,
      reviewer_model_id: reviewer || undefined,
    });
    navigate(`/repo/${s.id}`);
  };

  return (
    <Section title="Scan a GitHub repository">
      <div className="space-y-4">
        <div>
          <label className="text-xs text-slate-400">Public repository URL</label>
          <input
            className="input mt-1 font-mono text-sm"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://github.com/user/repo.git"
          />
        </div>
        <div className="flex items-center justify-between flex-wrap gap-3">
          <label className="flex items-center gap-2 text-sm text-slate-400">
            <input type="checkbox" checked={useAi} onChange={(e) => setUseAi(e.target.checked)} />
            Add AI deep review
          </label>
          {useAi && (
            <select className="input max-w-xs" value={reviewer} onChange={(e) => setReviewer(e.target.value)}>
              <option value="">Default reviewer model</option>
              {models?.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name} — {m.model_name}
                </option>
              ))}
            </select>
          )}
          <button className="btn-primary" disabled={!url.trim() || create.isPending} onClick={launch}>
            {create.isPending ? "Starting…" : "Scan repo →"}
          </button>
        </div>
        <p className="text-xs text-slate-600">
          Clones the repo (read-only) and checks for hardcoded secrets, dangerous code patterns, and config
          hygiene. AI review sends a summary to your selected model for extra findings.
        </p>
        {create.isError && <div className="text-danger text-sm">{(create.error as Error).message}</div>}
      </div>
    </Section>
  );
}

function History() {
  const { data: scans } = useRepoScans();
  if (!scans?.length) return <div className="text-slate-500 text-sm">No repo scans yet.</div>;
  return (
    <div className="space-y-2">
      {scans.map((s) => (
        <Link
          key={s.id}
          to={`/repo/${s.id}`}
          className="flex items-center gap-3 px-4 py-3 rounded-lg bg-panel2/50 border border-line hover:border-accent/50"
        >
          <span className="flex-1 text-sm text-slate-200 font-mono truncate">{s.repo_url}</span>
          {s.status === "running" ? (
            <span className="badge bg-accent/15 text-accent">scanning…</span>
          ) : s.risk_level ? (
            <RiskBadge risk={s.risk_level} />
          ) : null}
          <span className="text-xs text-slate-500">{s.total_findings} issues</span>
          <span className="text-xs text-slate-600">score {s.score ?? "—"}</span>
        </Link>
      ))}
    </div>
  );
}

function Detail({ id }: { id: string }) {
  const { data: scan } = useRepoScan(id);
  if (!scan) return <div className="text-slate-500 text-sm">Loading…</div>;
  return (
    <div className="space-y-6">
      <div>
        <Link to="/repo" className="text-xs text-slate-500 hover:text-accent">← All repo scans</Link>
        <h1 className="text-[26px] font-extrabold tracking-tight text-white mt-1 font-mono break-all">{scan.repo_url}</h1>
        <p className="text-slate-500 text-xs mt-1">
          {(scan.stats as { files?: number })?.files ?? "?"} files scanned
        </p>
      </div>
      <ScanReport scan={scan} target={scan.repo_url ?? "repository"} />
    </div>
  );
}

export default function RepoScanPage() {
  const { scanId } = useParams();
  if (scanId) return <Detail id={scanId} />;
  return (
    <div className="space-y-7">
      <PageHeader
        title="Repo Scanner"
        subtitle="Point it at a GitHub repo — it finds hardcoded secrets, insecure code patterns, and config weaknesses."
      />
      <LaunchForm />
      <Section title="Scan history">
        <History />
      </Section>
    </div>
  );
}
