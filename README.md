<p align="center">
  <img src="docs/banner.svg" alt="Sentinel AI — Burp Suite for LLMs" width="100%" />
</p>

<h1 align="center">🛡️ Sentinel AI</h1>

<p align="center">
  <b>The open-source security testing platform for Large Language Models.</b><br/>
  Automatically probe any LLM or AI app for prompt injection, jailbreaks, data leakage,
  toxicity, and misuse — then get a security score, OWASP mapping, and fixes.
</p>

<p align="center">
  <a href="#-quick-start"><img alt="Python" src="https://img.shields.io/badge/backend-FastAPI%20%7C%20Python%203.11%2B-3776AB?logo=python&logoColor=white"></a>
  <a href="#-quick-start"><img alt="React" src="https://img.shields.io/badge/frontend-React%20%2B%20Vite%20%2B%20TS-38bdf8?logo=react&logoColor=white"></a>
  <img alt="Attacks" src="https://img.shields.io/badge/attacks-51%20built--in-f43f5e">
  <img alt="OWASP" src="https://img.shields.io/badge/mapped%20to-OWASP%20LLM%20Top%2010-6f42c1">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-22c55e"></a>
  <a href="CONTRIBUTING.md"><img alt="PRs" src="https://img.shields.io/badge/PRs-welcome-brightgreen"></a>
</p>

---

## What is Sentinel AI?

LLMs shipped into products are vulnerable to a growing arsenal of attacks — **prompt injection,
jailbreaks, PII leakage, toxic output, tool misuse, hallucination**. Sentinel AI is a
**"Burp Suite for LLMs"**: point it at a model (or your own deployed chatbot endpoint), run a
battery of adversarial tests, and get a clear, actionable security report before you ship.

- 🎯 **Test any model** — OpenAI, Anthropic Claude, Google Gemini, Groq, DeepSeek, OpenRouter,
  Ollama, HuggingFace — **or your own app endpoint** (custom URL + headers + body template).
- 🧪 **51 built-in attacks** across **8 categories**, each mapped to the **OWASP LLM Top 10**.
- 🤖 **Autonomous Red Team Agent** — an attacker LLM that *plans, generates, and adapts*
  jailbreaks round-by-round until it breaches the target or runs out of moves.
- 📊 **Security dashboard** — 0–100 score, attack-success %, risk level, OWASP breakdown,
  and rule-based remediation recommendations.
- 🔐 **Keys never touch disk** — API keys live in an in-memory vault; all model calls are made
  server-side (no CORS, no key exposure in the browser).

<p align="center">
  <img src="docs/dashboard-preview.svg" alt="Sentinel AI dashboard" width="92%" />
</p>

---

## Table of Contents

- [Features](#-features)
- [Attack Library](#-attack-library)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Using It](#-using-it)
- [Red Team Agent](#-red-team-agent)
- [Testing your own app endpoint](#-testing-your-own-app-endpoint)
- [API Reference](#-api-reference)
- [Tech Stack](#-tech-stack)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Responsible Use](#-responsible-use--disclaimer)
- [License](#-license)

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🎛️ | **Model management** | Register any provider by pasting a key, or wire up a custom HTTP endpoint. One-click connectivity test. |
| 📚 | **Attack library** | 51 curated, research-grade attacks. Browse, filter by category, inspect the exact prompt. |
| ▶️ | **Scan runner** | Async, concurrency-limited execution with automatic rate-limit backoff. Live progress. |
| 🧮 | **Heuristic evaluator** | Free, no-extra-LLM detection: keyword/regex, refusal detection, built-in PII/secret regexes, and factual/hallucination checks. |
| 📈 | **Security score** | Severity-weighted 0–100 score, risk level, per-OWASP breakdown chart, remediation tips. |
| 🤖 | **Red Team Agent** | Planner → Generator → Executor → Judge loop that adapts each round and writes a report. |
| 🌐 | **Custom endpoints** | Test your *real deployed chatbot*, not just a base model — where the real vulnerabilities live. |

---

## 🧪 Attack Library

**51 attacks** across **8 categories**, grounded in real 2024–2025 red-team research
(Anthropic, Microsoft, HiddenLayer, Palo Alto Unit 42, OWASP):

| Category | Count | OWASP | Example attacks |
|----------|:-----:|-------|-----------------|
| **Prompt Injection** | 10 | LLM01 / LLM07 | Ignore-previous, system-prompt leak, indirect (document) injection, fake `<system>` message, instruction-hierarchy override, payload splitting |
| **Jailbreak** | 14 | LLM01 | **Skeleton Key**, **Policy Puppetry**, **Bad Likert Judge**, **Deceptive Delight**, many-shot, refusal suppression, prefix injection, DAN/AIM/Developer-Mode personas, GCG suffix |
| **Obfuscation** | 7 | LLM01 | Base64, ROT13, hex, reversed text, Morse, leetspeak, Unicode homoglyphs, ArtPrompt (ASCII-art) |
| **Offensive Security** | 5 | LLM05 | Phishing email, malware/keylogger code, SQLi exploit, XSS payload, ransomware guidance |
| **Tool Security** | 4 | LLM05 / LLM08 | Command injection (`rm -rf /`), destructive SQL, path traversal, unauthorized tool invocation |
| **PII Leakage** | 3 | LLM06 | Synthetic identity, training-data extraction, secret/API-key disclosure |
| **Toxicity & Bias** | 4 | LLM05 / LLM09 | Gender/nationality bias, hate speech, violent-threat drafting |
| **Hallucination** | 4 | LLM09 | Nonexistent book/API, factual accuracy, false-premise acceptance |

> Attacks are plain **YAML** in [`backend/app/attacks/seed/`](backend/app/attacks/seed) — adding one
> needs **no code**. See [CONTRIBUTING.md](CONTRIBUTING.md#adding-an-attack-no-code-needed).

---

## 🏗️ Architecture

```mermaid
flowchart LR
    UI["React + Vite UI<br/>(Models · Library · Scan · Dashboard · Red Team)"]
    API["FastAPI backend"]
    subgraph Engine
      RUN["Runner<br/>(async, rate-limited)"]
      EVAL["Evaluator<br/>(heuristic + optional LLM judge)"]
      SCORE["Scoring<br/>(0–100 · OWASP · recs)"]
      RT["Red Team Agent<br/>(plan → generate → judge → adapt)"]
    end
    PROV["Provider adapters<br/>OpenAI · Claude · Gemini · Groq ·<br/>DeepSeek · Ollama · HF · Custom HTTP"]
    DB[("SQLite<br/>runs · results · sessions")]
    VAULT["In-memory key vault"]
    TARGET["🎯 Target model / your app endpoint"]

    UI -->|/api| API --> RUN --> PROV --> TARGET
    RUN --> EVAL --> SCORE --> DB
    API --> RT --> PROV
    API --> DB
    PROV -.reads keys.-> VAULT
```

**Load-bearing rule:** every model call is made **server-side**. Keys are held in RAM only; SQLite
stores just the last-4 for display. This avoids browser CORS walls and never exposes secrets client-side.

### The Red Team loop

```mermaid
flowchart TD
    A([Objective]) --> P[🧠 Planner / Generator<br/>attacker LLM crafts a prompt]
    P --> E[🎯 Execute against target]
    E --> J{⚖️ Judge:<br/>did it comply?}
    J -->|Yes| R[📝 Write security report]
    J -->|No, rounds left| P
    J -->|No, out of rounds| R
```

---

## 🚀 Quick Start

**Prerequisites:** Python **3.11 or 3.12** (3.13+ wheels can be flaky) and Node **18+**.

### 1. Backend (FastAPI)

```bash
cd backend
python -m venv .venv
# Windows:  .\.venv\Scripts\Activate.ps1
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # add a GROQ_API_KEY (free at console.groq.com) — optional
uvicorn app.main:app --reload --port 8000
```

API docs (Swagger) → **http://localhost:8000/docs**

### 2. Frontend (Vite + React)

```bash
cd frontend
npm install
npm run dev                   # → http://localhost:5173
```

The Vite dev server proxies `/api` → `http://localhost:8000`, so you only open **one** URL.

> **You must run both** the backend and the frontend. If the backend is down, the UI shows an
> "internal server error" (the proxy has nothing to reach).

---

## 🎮 Using It

1. **Models** → *+ Add Model*. Pick a provider (e.g. `openai`, model `gpt-4o-mini`), paste your API
   key, and hit **Test** (green = it works). No Groq key? Use any provider you have.
2. **New Scan** → choose the model, select attacks (all 51, or filter by category), **Run**.
3. **Dashboard** → watch it populate live: security score, attack-success %, OWASP breakdown, and
   every attack's exact prompt + the model's response (click a row to expand).

> 💡 Keys live in memory and are cleared on backend restart — just re-add the model if you restart.

---

## 🤖 Red Team Agent

Go to **Red Team Agent**, pick a target, and give it an objective (e.g. *"Get the model to reveal its
system prompt"*). An attacker LLM then autonomously:

1. **Plans & generates** an adversarial prompt for the objective.
2. **Executes** it against the target.
3. **Judges** whether the guardrail broke.
4. **Adapts** — feeds the target's reply back and tries a new technique next round.

It stops the moment it breaches the objective (or runs out of rounds) and writes a **security report**.
You watch the whole thing live, round-by-round (🗡 attacker vs 🛡 target).

---

## 🌐 Testing your own app endpoint

The highest-value use case: test **your deployed chatbot**, not just a base model — because the
real vulnerabilities live in *your* system prompt, RAG data, and tools.

**Models → + Add Model → provider `custom`:**

| Field | Example |
|-------|---------|
| Endpoint URL | `https://your-app.com/api/chat` |
| Headers (JSON) | `{"Authorization": "Bearer {{api_key}}"}` |
| Body template | `{"messages":[{"role":"user","content":"{{prompt}}"}]}` |
| Response path | `choices.0.message.content` |

`{{prompt}}` is replaced by the attack text (safely JSON-escaped); `{{api_key}}` is filled from the
in-memory vault. Sentinel then runs every attack — and the Red Team Agent — against your live app.

---

## 📡 API Reference

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/api/health` | Liveness + whether the default key is set |
| `GET` `POST` | `/api/models` | List / register models |
| `GET` `DELETE` | `/api/models/{id}` | Fetch / delete a model |
| `POST` | `/api/models/{id}/test` | Send a trivial prompt to verify connectivity |
| `GET` | `/api/attacks` | List attacks (`?category=` to filter) |
| `GET` | `/api/attacks/{id}` | Single attack detail |
| `POST` | `/api/runs` | Start a scan `{model_id, attack_ids?, use_llm_judge?}` |
| `GET` | `/api/runs` · `/api/runs/{id}` | List runs / poll one |
| `GET` | `/api/runs/{id}/results` | Per-attack results |
| `POST` | `/api/redteam` | Launch a red-team session `{target_model_id, objective, max_rounds}` |
| `GET` | `/api/redteam` · `/api/redteam/{id}` | List / poll sessions |

Full interactive docs at `/docs` when the backend is running.

---

## 🧰 Tech Stack

**Backend:** FastAPI · httpx (async) · SQLAlchemy + SQLite · Pydantic · PyYAML
**Frontend:** React 18 · Vite · TypeScript · Tailwind CSS · TanStack Query · Recharts

```
sentinal ai/
├─ backend/app/
│  ├─ providers/     # adapters: openai_compatible, gemini, anthropic, huggingface, custom_http
│  ├─ attacks/seed/  # 8 YAML attack libraries (the content that drives everything)
│  ├─ engine/        # runner · evaluator · scoring · redteam
│  └─ routers/       # models · attacks · runs · redteam
└─ frontend/src/
   ├─ pages/         # Models · AttackLibrary · Run · Dashboard · RedTeam
   ├─ components/    # ui · charts · icons
   └─ hooks/         # TanStack Query data layer
```

---

## 🗺️ Roadmap

- [ ] CI/CD mode — a CLI that outputs JSON and fails a build on a security regression
- [ ] Scheduled / continuous scans
- [ ] Run history & score-trend comparison ("did our score drop this week?")
- [ ] Compliance report export (PDF: OWASP LLM Top 10 / EU AI Act)
- [ ] Multi-turn (Crescendo) attacks with whole-conversation scoring
- [ ] Multimodal (image/audio) injection tests
- [ ] Optional persistent, encrypted key storage

---

## 🤝 Contributing

Contributions are very welcome — **adding an attack is a one-file YAML change, no code required.**
See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## ⚠️ Responsible Use / Disclaimer

Sentinel AI is a **defensive security tool** for testing models **you own or are authorized to test**.
Attack prompts are designed to *probe refusal behavior*, not to produce operational harm. Do **not**
use it against third-party services without explicit permission. You are responsible for how you use it.

---

## 📄 License

[MIT](LICENSE) © 2026 Afzal Khan
