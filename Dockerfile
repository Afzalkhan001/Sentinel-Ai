# ---------- Stage 1: build the React frontend ----------
FROM node:20-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: Python backend that also serves the frontend ----------
FROM python:3.12-slim
WORKDIR /app

# git is required by the repo scanner
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./
# drop the built SPA where FastAPI serves it (app/static)
COPY --from=frontend /app/frontend/dist ./app/static

ENV PORT=8000 \
    FRONTEND_ORIGIN=* \
    PYTHONUNBUFFERED=1
EXPOSE 8000

# one process serves both the API (/api/*) and the SPA (everything else)
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
