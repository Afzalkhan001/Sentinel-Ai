import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import ModelsPage from "./pages/ModelsPage";
import AttackLibraryPage from "./pages/AttackLibraryPage";
import RunPage from "./pages/RunPage";
import DashboardPage from "./pages/DashboardPage";
import RedTeamPage from "./pages/RedTeamPage";
import RepoScanPage from "./pages/RepoScanPage";
import WebScanPage from "./pages/WebScanPage";
import { GlobeIcon, LibraryIcon, ModelsIcon, RedTeamIcon, RepoIcon, ResultsIcon, ScanIcon, ShieldIcon } from "./components/icons";
import type { ReactNode } from "react";

type NavItem = { to: string; label: string; icon: ReactNode };

const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "AI Models",
    items: [
      { to: "/models", label: "Models", icon: <ModelsIcon /> },
      { to: "/attacks", label: "Attack Library", icon: <LibraryIcon /> },
      { to: "/run", label: "Model Scan", icon: <ScanIcon /> },
      { to: "/runs", label: "Results", icon: <ResultsIcon /> },
      { to: "/redteam", label: "Red Team Agent", icon: <RedTeamIcon /> },
    ],
  },
  {
    label: "Code & Web",
    items: [
      { to: "/repo", label: "Repo Scanner", icon: <RepoIcon /> },
      { to: "/web", label: "Website Scanner", icon: <GlobeIcon /> },
    ],
  },
];

function NavRow({ item }: { item: NavItem }) {
  return (
    <NavLink to={item.to} className="nav-link group">
      {({ isActive }) => (
        <>
          {isActive && (
            <span className="absolute left-0 top-1/2 -translate-y-1/2 h-6 w-1 rounded-r-full bg-accent-grad shadow-[0_0_12px_rgba(56,189,248,0.8)]" />
          )}
          <span className={`transition-colors ${isActive ? "text-accent" : "text-slate-500 group-hover:text-slate-300"}`}>
            {item.icon}
          </span>
          <span className={`transition-colors ${isActive ? "text-white" : "text-slate-400 group-hover:text-slate-200"}`}>
            {item.label}
          </span>
          {isActive && <span className="absolute inset-0 rounded-xl bg-accent/[0.07] ring-1 ring-inset ring-accent/20 -z-10" />}
        </>
      )}
    </NavLink>
  );
}

function Sidebar() {
  return (
    <aside className="w-64 shrink-0 border-r border-line/70 bg-panel/40 backdrop-blur-xl px-4 py-6 flex flex-col">
      <div className="px-2 mb-8">
        <div className="flex items-center gap-2.5">
          <div className="grid place-items-center w-9 h-9 rounded-xl bg-accent-grad text-slate-950 shadow-[0_6px_18px_-4px_rgba(56,189,248,0.7)]">
            <ShieldIcon className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[15px] font-extrabold text-white leading-none tracking-tight">Sentinel AI</div>
            <div className="text-[11px] text-slate-500 mt-1">Security Testing</div>
          </div>
        </div>
      </div>

      <nav className="flex flex-col gap-4">
        {NAV_GROUPS.map((g) => (
          <div key={g.label} className="flex flex-col gap-1">
            <div className="px-3 text-[10px] font-bold uppercase tracking-[0.14em] text-slate-600 mb-1">{g.label}</div>
            {g.items.map((item) => (
              <NavRow key={item.to} item={item} />
            ))}
          </div>
        ))}
      </nav>

      <div className="mt-auto">
        <div className="rounded-xl border border-line/70 bg-bg2/50 p-3">
          <div className="flex items-center gap-2 text-[11px] text-slate-400">
            <span className="w-1.5 h-1.5 rounded-full bg-ok animate-pulse-glow shadow-[0_0_8px_#22c55e]" />
            Engine online
          </div>
          <div className="text-[11px] text-slate-600 mt-1.5">Models · Repos · Websites</div>
        </div>
      </div>
    </aside>
  );
}

const TITLES: Record<string, string> = {
  "/models": "Models",
  "/attacks": "Attack Library",
  "/run": "Model Scan",
  "/runs": "Results",
  "/redteam": "Red Team Agent",
  "/repo": "Repo Scanner",
  "/web": "Website Scanner",
};

function Topbar() {
  const { pathname } = useLocation();
  const key = Object.keys(TITLES).find((k) => pathname.startsWith(k)) ?? "/models";
  return (
    <header className="sticky top-0 z-10 h-14 border-b border-line/60 bg-bg/60 backdrop-blur-xl flex items-center px-8">
      <div className="text-xs text-slate-500">
        Sentinel <span className="text-slate-700">/</span> <span className="text-slate-300">{TITLES[key]}</span>
      </div>
      <div className="ml-auto flex items-center gap-2 text-[11px] text-slate-500">
        <span className="badge bg-accent/10 text-accent">AI Security Platform</span>
      </div>
    </header>
  );
}

export default function App() {
  const { pathname } = useLocation();
  return (
    <div className="flex h-full">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <Topbar />
        <div key={pathname} className="max-w-6xl mx-auto px-8 py-8 animate-fade-up">
          <Routes>
            <Route path="/" element={<Navigate to="/models" replace />} />
            <Route path="/models" element={<ModelsPage />} />
            <Route path="/attacks" element={<AttackLibraryPage />} />
            <Route path="/run" element={<RunPage />} />
            <Route path="/runs" element={<DashboardPage />} />
            <Route path="/runs/:runId" element={<DashboardPage />} />
            <Route path="/redteam" element={<RedTeamPage />} />
            <Route path="/redteam/:sessionId" element={<RedTeamPage />} />
            <Route path="/repo" element={<RepoScanPage />} />
            <Route path="/repo/:scanId" element={<RepoScanPage />} />
            <Route path="/web" element={<WebScanPage />} />
            <Route path="/web/:scanId" element={<WebScanPage />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}
