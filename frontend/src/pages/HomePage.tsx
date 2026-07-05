import { Link } from "react-router-dom";
import { useAttacks, useModels, useRedTeamSessions, useRepoScans, useRuns, useWebScans } from "../hooks/queries";
import { RiskBadge } from "../components/ui";
import { GlobeIcon, RepoIcon, ScanIcon } from "../components/icons";

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="card p-4">
      <div className="text-[11px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className="text-3xl font-extrabold text-white mt-1">{value}</div>
      {sub && <div className="text-xs text-slate-500 mt-0.5">{sub}</div>}
    </div>
  );
}

function ScannerCard({ to, icon, title, desc, cta }: { to: string; icon: React.ReactNode; title: string; desc: string; cta: string }) {
  return (
    <Link
      to={to}
      className="card p-5 group transition-all duration-200 hover:-translate-y-0.5 hover:border-accent/40 hover:shadow-glow"
    >
      <div className="w-10 h-10 rounded-xl bg-accent/10 text-accent grid place-items-center mb-3 group-hover:bg-accent/20">
        {icon}
      </div>
      <div className="font-bold text-white">{title}</div>
      <p className="text-sm text-slate-400 mt-1 leading-relaxed">{desc}</p>
      <div className="text-sm text-accent mt-3 font-medium">{cta} →</div>
    </Link>
  );
}

export default function HomePage() {
  const { data: models } = useModels();
  const { data: attacks } = useAttacks();
  const { data: runs } = useRuns();
  const { data: repoScans } = useRepoScans();
  const { data: webScans } = useWebScans();
  const { data: redteam } = useRedTeamSessions();

  const recent = [
    ...(runs ?? []).map((r) => ({ kind: "Model", to: `/runs/${r.id}`, target: r.model_label ?? r.model_id, score: r.score, risk: r.risk_level, at: r.created_at })),
    ...(repoScans ?? []).map((s) => ({ kind: "Repo", to: `/repo/${s.id}`, target: s.repo_url ?? "", score: s.score, risk: s.risk_level, at: s.created_at })),
    ...(webScans ?? []).map((s) => ({ kind: "Web", to: `/web/${s.id}`, target: s.target_url ?? "", score: s.score, risk: s.risk_level, at: s.created_at })),
  ]
    .sort((a, b) => (a.at < b.at ? 1 : -1))
    .slice(0, 8);

  const totalScans = (runs?.length ?? 0) + (repoScans?.length ?? 0) + (webScans?.length ?? 0) + (redteam?.length ?? 0);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-extrabold tracking-tight text-white">
          Welcome to <span className="text-gradient">Sentinel AI</span>
        </h1>
        <p className="text-slate-500 mt-2 max-w-2xl">
          One platform to security-test your AI models, code repositories, and live websites. Pick a target below to start.
        </p>
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        <ScannerCard to="/run" icon={<ScanIcon className="w-5 h-5" />} title="Test an AI Model"
          desc="Run 51 adversarial attacks — prompt injection, jailbreaks, PII, toxicity — against any LLM or your app endpoint." cta="New model scan" />
        <ScannerCard to="/repo" icon={<RepoIcon className="w-5 h-5" />} title="Scan a GitHub Repo"
          desc="Find hardcoded secrets, dangerous code patterns, and vulnerable dependencies (live CVE checks)." cta="New repo scan" />
        <ScannerCard to="/web" icon={<GlobeIcon className="w-5 h-5" />} title="Scan a Website"
          desc="Check security headers, TLS, exposed files, and safely probe for XSS & SQL injection." cta="New website scan" />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Models" value={models?.length ?? 0} sub="registered" />
        <StatCard label="Attacks" value={attacks?.length ?? 0} sub="across 8 categories" />
        <StatCard label="Total scans" value={totalScans} sub="all types" />
        <StatCard label="Red-team runs" value={redteam?.length ?? 0} sub="autonomous" />
      </div>

      <div className="card p-5">
        <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.14em] text-slate-400 mb-4">
          <span className="w-1 h-3.5 rounded-full bg-accent-grad" /> Recent activity
        </div>
        {recent.length === 0 ? (
          <div className="text-slate-500 text-sm">No scans yet — start one above.</div>
        ) : (
          <div className="space-y-2">
            {recent.map((r, i) => (
              <Link key={i} to={r.to} className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-panel2/40 border border-line hover:border-accent/50">
                <span className="badge bg-accent/10 text-accent w-14 justify-center">{r.kind}</span>
                <span className="flex-1 text-sm text-slate-200 font-mono truncate">{r.target}</span>
                {r.risk ? <RiskBadge risk={r.risk} /> : <span className="badge bg-slate-600/30 text-slate-400">running</span>}
                <span className="text-xs text-slate-500 w-16 text-right">score {r.score ?? "—"}</span>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
