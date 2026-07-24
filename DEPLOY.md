# Deploying Sentinel AI

Sentinel is a **static frontend + a Python backend**. The backend runs background scans,
`git clone`, and a database — so it needs a real server (not serverless). The recommended
setup is **Vercel for the frontend + a container host for the backend**.

> ⚠️ **Vercel alone can't run the backend.** Its serverless functions can't run the
> post-response background scans / Red Team loop, have no `git` binary, and no persistent
> disk for SQLite or the in-memory key vault. Put the backend on Render/Railway/Fly instead.

---

## Step 1 — Deploy the backend (Render, free)

1. Push this repo to GitHub (already done).
2. Go to <https://render.com> → **New → Web Service** → connect the repo.
3. Settings:
   - **Runtime:** Docker (Render auto-detects the root `Dockerfile`)
   - **Instance type:** Free
   - **Environment variables** (optional): `GROQ_API_KEY` = your free Groq key.
   - (For persistent history) add a **Disk** mounted at `/app/data` and set
     `DATABASE_URL=sqlite:////app/data/sentinel.db`.
4. Deploy. You'll get a URL like `https://sentinel-ai-xxxx.onrender.com`.
5. Verify: open `https://<your-url>/api/health` → should return `{"status":"ok"}`.

> Alternatives: **Railway** (`railway up`, detects the Dockerfile) or **Fly.io** (`fly launch`).
> The single-container image already serves the whole app, so a backend host alone is a
> complete deployment — Vercel just gives the frontend a fast CDN + your own domain.

## Step 2 — Deploy the frontend (Vercel)

1. Edit [`frontend/vercel.json`](frontend/vercel.json) and replace
   `https://YOUR-BACKEND-URL.onrender.com` with your **actual backend URL** from Step 1
   (keep the trailing `/api/:path*`).
2. Go to <https://vercel.com> → **Add New → Project** → import this repo.
3. Settings:
   - **Root Directory:** `frontend`
   - Framework preset **Vite**, build `npm run build`, output `dist` (auto-filled by `vercel.json`).
4. Deploy. Vercel proxies `/api/*` to your backend, so the app works with **no CORS setup**.

Open your Vercel URL — the welcome popup will prompt for an API key and you're live. 🎉

---

## Simpler: backend host only (skip Vercel)

Because the Docker image serves the UI *and* API together, deploying just the backend to
Render/Railway/Fly gives you a fully working app at one URL — no Vercel needed. Use Vercel
only if you specifically want its CDN/domain for the frontend.

```bash
# local one-command run of the same production image
GROQ_API_KEY=your_key docker compose up --build   # → http://localhost:8000
```
