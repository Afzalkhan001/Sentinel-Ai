import { Bar, BarChart, Cell, ResponsiveContainer, XAxis, YAxis } from "recharts";
import type { OwaspBucket } from "../api/types";

function scoreColor(score: number) {
  if (score >= 90) return "#22c55e";
  if (score >= 70) return "#f59e0b";
  if (score >= 40) return "#f97316";
  return "#f43f5e";
}

export function ScoreGauge({ score }: { score: number }) {
  const color = scoreColor(score);
  const r = 54;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);
  return (
    <div className="relative w-40 h-40">
      <svg viewBox="0 0 140 140" className="w-full h-full -rotate-90">
        <defs>
          <linearGradient id="gaugeGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.7" />
            <stop offset="100%" stopColor={color} />
          </linearGradient>
          <filter id="gaugeGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <circle cx="70" cy="70" r={r} fill="none" stroke="#1a2436" strokeWidth="12" />
        <circle
          cx="70"
          cy="70"
          r={r}
          fill="none"
          stroke="url(#gaugeGrad)"
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          filter="url(#gaugeGlow)"
          style={{ transition: "stroke-dashoffset 1s cubic-bezier(0.22,1,0.36,1)" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-5xl font-extrabold tracking-tight" style={{ color }}>
          {score}
        </span>
        <span className="text-[11px] uppercase tracking-widest text-slate-500 mt-0.5">/ 100</span>
      </div>
    </div>
  );
}

export function OwaspBreakdown({ data }: { data: OwaspBucket[] }) {
  const chart = data.map((d) => ({ name: d.category.replace("LLM01:", ""), pct: d.success_pct }));
  return (
    <ResponsiveContainer width="100%" height={Math.max(80, chart.length * 56)}>
      <BarChart data={chart} layout="vertical" margin={{ left: 8, right: 24 }}>
        <XAxis type="number" domain={[0, 100]} hide />
        <YAxis type="category" dataKey="name" width={130} tick={{ fill: "#94a3b8", fontSize: 12 }} />
        <Bar dataKey="pct" radius={[0, 6, 6, 0]} label={{ position: "right", fill: "#94a3b8", fontSize: 12, formatter: (v: number) => `${v}%` }}>
          {chart.map((d, i) => (
            <Cell key={i} fill={d.pct > 0 ? "#f43f5e" : "#22c55e"} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
