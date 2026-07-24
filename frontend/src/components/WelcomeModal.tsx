import { useState } from "react";
import { useCreateModel, useTestModel } from "../hooks/queries";
import { ShieldIcon } from "./icons";

const PROVIDERS: { id: string; label: string; model: string; keyHint: string; url?: string }[] = [
  { id: "openai", label: "OpenAI", model: "gpt-4o-mini", keyHint: "sk-…", url: "https://platform.openai.com/api-keys" },
  { id: "groq", label: "Groq (free)", model: "llama-3.1-8b-instant", keyHint: "gsk_…", url: "https://console.groq.com/keys" },
  { id: "anthropic", label: "Anthropic Claude", model: "claude-3-5-haiku-20241022", keyHint: "sk-ant-…", url: "https://console.anthropic.com/settings/keys" },
  { id: "gemini", label: "Google Gemini", model: "gemini-1.5-flash", keyHint: "AIza…", url: "https://aistudio.google.com/apikey" },
  { id: "openrouter", label: "OpenRouter", model: "meta-llama/llama-3.1-8b-instruct:free", keyHint: "sk-or-…", url: "https://openrouter.ai/keys" },
  { id: "deepseek", label: "DeepSeek", model: "deepseek-chat", keyHint: "sk-…", url: "https://platform.deepseek.com/api_keys" },
];

export function WelcomeModal({ onClose }: { onClose: () => void }) {
  const [providerId, setProviderId] = useState("openai");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const create = useCreateModel();
  const test = useTestModel();
  const provider = PROVIDERS.find((p) => p.id === providerId)!;

  const addKey = async () => {
    setStatus(null);
    try {
      const created = await create.mutateAsync({
        name: `${provider.label} model`,
        provider: providerId,
        model_name: model || provider.model,
        api_key: apiKey.trim(),
      });
      const result = await test.mutateAsync(created.id);
      if (result.ok) {
        localStorage.setItem("sentinel_welcomed", "1");
        onClose();
      } else {
        setStatus(`Key added but the test failed: ${result.error?.slice(0, 80) ?? "check the key"}`);
      }
    } catch (e) {
      setStatus((e as Error).message);
    }
  };

  const skip = () => {
    localStorage.setItem("sentinel_welcomed", "1");
    onClose();
  };

  const busy = create.isPending || test.isPending;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
      onClick={skip}
    >
      <div className="card relative w-full max-w-lg p-6 animate-fade-up" onClick={(e) => e.stopPropagation()}>
        <button
          onClick={skip}
          aria-label="Close"
          title="Close"
          className="absolute top-3 right-3 w-8 h-8 grid place-items-center rounded-lg text-slate-500 hover:text-white hover:bg-panel2 transition-colors"
        >
          <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M6 6l12 12M18 6L6 18" />
          </svg>
        </button>
        <div className="flex items-center gap-3 mb-1 pr-8">
          <div className="grid place-items-center w-10 h-10 rounded-xl bg-accent-grad text-slate-950">
            <ShieldIcon className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white">Welcome to Sentinel AI</h2>
            <p className="text-xs text-slate-500">Let's get you set up in 30 seconds.</p>
          </div>
        </div>

        <p className="text-sm text-slate-400 mt-3">
          To test an AI model you need one <b>API key</b> from a provider. Repo &amp; website scans work
          without a key — but a key unlocks model testing and the Red Team agent. Your key is kept in memory only,
          never written to disk.
        </p>

        <div className="mt-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-slate-400">Provider</label>
              <select
                className="input mt-1"
                value={providerId}
                onChange={(e) => {
                  setProviderId(e.target.value);
                  setModel("");
                }}
              >
                {PROVIDERS.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-400">Model</label>
              <input className="input mt-1" value={model} onChange={(e) => setModel(e.target.value)} placeholder={provider.model} />
            </div>
          </div>
          <div>
            <label className="text-xs text-slate-400 flex items-center justify-between">
              <span>API key</span>
              {provider.url && (
                <a href={provider.url} target="_blank" rel="noreferrer" className="text-accent hover:underline">
                  Get a {provider.label} key ↗
                </a>
              )}
            </label>
            <input
              className="input mt-1"
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={provider.keyHint}
            />
          </div>
        </div>

        {status && <div className="text-danger text-sm mt-3">{status}</div>}

        <div className="flex items-center justify-between mt-5">
          <button className="text-sm text-slate-500 hover:text-slate-300" onClick={skip}>
            Skip for now
          </button>
          <button className="btn-primary" disabled={!apiKey.trim() || busy} onClick={addKey}>
            {busy ? "Verifying…" : "Add key & start →"}
          </button>
        </div>

        <div className="mt-4 pt-4 border-t border-line text-xs text-slate-600">
          Tip: <b className="text-slate-400">Groq</b> offers a generous free tier — great for trying Sentinel at no cost.
        </div>
      </div>
    </div>
  );
}
