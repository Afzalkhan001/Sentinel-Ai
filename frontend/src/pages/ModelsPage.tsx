import { useState } from "react";
import { useCreateModel, useDeleteModel, useModels, useTestModel } from "../hooks/queries";
import { PageHeader, Section } from "../components/ui";
import type { ModelTestResult } from "../api/types";

const PROVIDERS = ["openai", "groq", "openrouter", "deepseek", "ollama", "gemini", "anthropic", "huggingface", "custom"];

const PLACEHOLDER_MODEL: Record<string, string> = {
  groq: "llama-3.1-8b-instant",
  openrouter: "meta-llama/llama-3.1-8b-instruct:free",
  openai: "gpt-4o-mini",
  deepseek: "deepseek-chat",
  ollama: "llama3",
  gemini: "gemini-1.5-flash",
  anthropic: "claude-3-5-haiku-20241022",
  huggingface: "mistralai/Mistral-7B-Instruct-v0.2",
  custom: "custom-endpoint",
};

const CUSTOM_DEFAULT_BODY = '{"messages":[{"role":"user","content":"{{prompt}}"}]}';

function AddModelForm({ onDone }: { onDone: () => void }) {
  const [provider, setProvider] = useState("openai");
  const [name, setName] = useState("");
  const [modelName, setModelName] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  // Custom-endpoint fields
  const [headers, setHeaders] = useState('{"Authorization": "Bearer {{api_key}}"}');
  const [bodyTemplate, setBodyTemplate] = useState(CUSTOM_DEFAULT_BODY);
  const [responsePath, setResponsePath] = useState("choices.0.message.content");
  const [formError, setFormError] = useState<string | null>(null);

  const create = useCreateModel();
  const isCustom = provider === "custom";

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    try {
      const body: import("../api/types").ModelCreate = {
        name: name || `${provider} model`,
        provider,
        model_name: modelName || PLACEHOLDER_MODEL[provider],
        api_key: apiKey || undefined,
        base_url: baseUrl || undefined,
      };
      if (isCustom) {
        let parsedHeaders: Record<string, string> = {};
        if (headers.trim()) parsedHeaders = JSON.parse(headers);
        body.request_config = {
          method: "POST",
          headers: parsedHeaders,
          body_template: bodyTemplate,
          response_path: responsePath,
        };
      }
      await create.mutateAsync(body);
      onDone();
    } catch (err) {
      setFormError(err instanceof SyntaxError ? "Headers must be valid JSON." : (err as Error).message);
    }
  };

  return (
    <form onSubmit={submit} className="grid grid-cols-2 gap-4">
      <div>
        <label className="text-xs text-slate-400">Provider</label>
        <select className="input mt-1" value={provider} onChange={(e) => setProvider(e.target.value)}>
          {PROVIDERS.map((p) => (
            <option key={p} value={p}>
              {p === "custom" ? "custom (your app endpoint)" : p}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label className="text-xs text-slate-400">Display name</label>
        <input className="input mt-1" value={name} onChange={(e) => setName(e.target.value)} placeholder="My model" />
      </div>

      {!isCustom && (
        <div>
          <label className="text-xs text-slate-400">Model name</label>
          <input
            className="input mt-1"
            value={modelName}
            onChange={(e) => setModelName(e.target.value)}
            placeholder={PLACEHOLDER_MODEL[provider]}
          />
        </div>
      )}
      <div className={isCustom ? "col-span-2" : ""}>
        <label className="text-xs text-slate-400">
          {isCustom ? "Secret / token (injected as {{api_key}})" : "API key"}{" "}
          {provider === "ollama" && <span className="text-slate-600">(not needed)</span>}
        </label>
        <input
          className="input mt-1"
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder={isCustom ? "your bearer token / api key" : "sk-..."}
        />
      </div>

      {!isCustom && (
        <div className="col-span-2">
          <label className="text-xs text-slate-400">Base URL (optional override)</label>
          <input
            className="input mt-1"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="leave blank for provider default"
          />
        </div>
      )}

      {isCustom && (
        <>
          <div className="col-span-2 text-xs text-slate-500 bg-panel2 border border-line rounded-lg p-3">
            Point Sentinel at <b>your deployed chatbot / LLM app endpoint</b>. Use{" "}
            <code className="text-accent">{"{{prompt}}"}</code> where the attack text goes and{" "}
            <code className="text-accent">{"{{api_key}}"}</code> for your secret.
          </div>
          <div className="col-span-2">
            <label className="text-xs text-slate-400">Endpoint URL</label>
            <input
              className="input mt-1"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://your-app.com/api/chat"
            />
          </div>
          <div className="col-span-2">
            <label className="text-xs text-slate-400">Headers (JSON)</label>
            <textarea className="input mt-1 h-16 font-mono text-xs" value={headers} onChange={(e) => setHeaders(e.target.value)} />
          </div>
          <div className="col-span-2">
            <label className="text-xs text-slate-400">Request body template (JSON, must contain {"{{prompt}}"})</label>
            <textarea
              className="input mt-1 h-16 font-mono text-xs"
              value={bodyTemplate}
              onChange={(e) => setBodyTemplate(e.target.value)}
            />
          </div>
          <div className="col-span-2">
            <label className="text-xs text-slate-400">Response path (dot-notation to the answer text)</label>
            <input
              className="input mt-1 font-mono text-xs"
              value={responsePath}
              onChange={(e) => setResponsePath(e.target.value)}
              placeholder="choices.0.message.content"
            />
          </div>
        </>
      )}

      {(formError || create.isError) && (
        <div className="col-span-2 text-danger text-sm">{formError ?? (create.error as Error).message}</div>
      )}
      <div className="col-span-2 flex gap-3">
        <button className="btn-primary" disabled={create.isPending}>
          {create.isPending ? "Saving…" : "Register model"}
        </button>
        <button type="button" className="btn-ghost" onClick={onDone}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function TestButton({ id }: { id: string }) {
  const test = useTestModel();
  const [result, setResult] = useState<ModelTestResult | null>(null);
  return (
    <div className="flex items-center gap-2">
      <button
        className="btn-ghost !py-1 !px-3 text-xs"
        onClick={async () => setResult(await test.mutateAsync(id))}
        disabled={test.isPending}
      >
        {test.isPending ? "Testing…" : "Test"}
      </button>
      {result && (
        <span className={`text-xs ${result.ok ? "text-ok" : "text-danger"}`}>
          {result.ok ? `ok · ${result.latency_ms}ms` : result.error?.slice(0, 40) ?? "failed"}
        </span>
      )}
    </div>
  );
}

export default function ModelsPage() {
  const { data: models, isLoading } = useModels();
  const del = useDeleteModel();
  const [adding, setAdding] = useState(false);

  return (
    <div className="space-y-7">
      <PageHeader
        title="Models"
        subtitle="Register the LLMs — or your own deployed app endpoint — that you want to security-test."
        right={
          !adding ? (
            <button className="btn-primary" onClick={() => setAdding(true)}>
              + Add Model
            </button>
          ) : undefined
        }
      />

      {adding && (
        <Section title="Register a model">
          <AddModelForm onDone={() => setAdding(false)} />
        </Section>
      )}

      <Section title="Registered models">
        {isLoading ? (
          <div className="text-slate-500 text-sm">Loading…</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wider text-slate-500 border-b border-line">
                <th className="py-2.5 font-semibold">Name</th>
                <th className="py-2.5 font-semibold">Provider</th>
                <th className="py-2.5 font-semibold">Model</th>
                <th className="py-2.5 font-semibold">Key</th>
                <th className="py-2.5 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {models?.map((m) => (
                <tr key={m.id} className="border-b border-line/40 hover:bg-panel2/30 transition-colors">
                  <td className="py-3.5 text-slate-100 font-medium">
                    {m.name}
                    {m.is_default && <span className="badge bg-accent/15 text-accent ml-2">default</span>}
                    {m.provider === "custom" && <span className="badge bg-red-500/15 text-red-300 ml-2">endpoint</span>}
                  </td>
                  <td className="py-3.5 text-slate-400">{m.provider}</td>
                  <td className="py-3.5 text-slate-400 font-mono text-xs">{m.model_name}</td>
                  <td className="py-3.5 text-slate-500 font-mono text-xs">{m.key_last4 ? `••••${m.key_last4}` : "—"}</td>
                  <td className="py-3.5">
                    <div className="flex items-center justify-end gap-3">
                      <TestButton id={m.id} />
                      {!m.is_default && (
                        <button
                          className="text-xs text-slate-500 hover:text-danger transition-colors"
                          onClick={() => del.mutate(m.id)}
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </div>
  );
}
