import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useCreateWebScan, useModels, useWebScan, useWebScans } from "../hooks/queries";
import { PageHeader, RiskBadge, Section } from "../components/ui";
import { ScanReport } from "../components/ScanReport";

function LaunchForm() {
  const create = useCreateWebScan();
  const { data: models } = useModels();
  const navigate = useNavigate();
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [useAi, setUseAi] = useState(false);
  const [reviewer, setReviewer] = useState("");

  const launch = async () => {
    const s = await create.mutateAsync({
      target_url: url.trim(),
      authorized,
      use_ai: useAi,
      reviewer_model_id: reviewer || undefined,
    });
    navigate(`/web/${s.id}`);
  };

  return (
    <Section title="Scan a website">
      <div className="space-y-4">
        <div>
          <label className="text-xs text-slate-400">Target URL</label>
          <input
            className="input mt-1 font-mono text-sm"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/page?id=1"
          />
        </div>

        <label className="flex items-start gap-2.5 text-sm text-slate-300 bg-warn/5 border border-warn/30 rounded-lg p-3">
          <input type="checkbox" className="mt-0.5" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
          <span>
            <b className="text-warn">I am authorized to test this site.</b> Enables safe, non-destructive active
            probes (one reflected-XSS canary and one SQL-error check per URL parameter). Without this, only passive
            checks run. Never test sites you don't own or have permission for.
          </span>
        </label>

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
            {create.isPending ? "Starting…" : "Scan website →"}
          </button>
        </div>
        <p className="text-xs text-slate-600">
          Passive checks always run: security headers, HTTPS/TLS, cookie flags, version disclosure, and exposed
          files (/.git, /.env, …). Mapped to the OWASP Web Top 10.
        </p>
        {create.isError && <div className="text-danger text-sm">{(create.error as Error).message}</div>}
      </div>
    </Section>
  );
}

function History() {
  const { data: scans } = useWebScans();
  if (!scans?.length) return <div className="text-slate-500 text-sm">No website scans yet.</div>;
  return (
    <div className="space-y-2">
      {scans.map((s) => (
        <Link
          key={s.id}
          to={`/web/${s.id}`}
          className="flex items-center gap-3 px-4 py-3 rounded-lg bg-panel2/50 border border-line hover:border-accent/50"
        >
          <span className="flex-1 text-sm text-slate-200 font-mono truncate">{s.target_url}</span>
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
  const { data: scan } = useWebScan(id);
  if (!scan) return <div className="text-slate-500 text-sm">Loading…</div>;
  return (
    <div className="space-y-6">
      <div>
        <Link to="/web" className="text-xs text-slate-500 hover:text-accent">← All website scans</Link>
        <h1 className="text-[26px] font-extrabold tracking-tight text-white mt-1 font-mono break-all">{scan.target_url}</h1>
        <p className="text-slate-500 text-xs mt-1">
          {scan.authorized ? "Active probes enabled" : "Passive checks only"}
          {(scan.stats as { server?: string })?.server ? ` · server: ${(scan.stats as { server?: string }).server}` : ""}
        </p>
      </div>
      <ScanReport scan={scan} target={scan.target_url ?? "website"} />
    </div>
  );
}

export default function WebScanPage() {
  const { scanId } = useParams();
  if (scanId) return <Detail id={scanId} />;
  return (
    <div className="space-y-7">
      <PageHeader
        title="Website Scanner"
        subtitle="Point it at a URL — it checks security headers, TLS, exposed files, and (when authorized) safely probes for XSS and SQL injection."
      />
      <LaunchForm />
      <Section title="Scan history">
        <History />
      </Section>
    </div>
  );
}
