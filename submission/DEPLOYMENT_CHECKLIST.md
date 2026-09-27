# SECUREFIX X — Deployment Checklist

Follow this checklist when deploying SECUREFIX X to production environments.

---

## 1. Backend Service Deployment (Render / Fly.io / AWS ECS)
- [ ] Ensure Python 3.10+ runtime with `git` binary installed in container.
- [ ] Set `PORT=8000` (or host assigned port).
- [ ] Mount persistent volume for SQLite `securefix.db` (if persistence across restarts is desired).
- [ ] Provide write access to `/tmp` for ephemeral Git sandbox cloning.
- [ ] Set optional LLM keys if live AI is desired (`GOOGLE_API_KEY` or `OPENAI_API_KEY`).
- [ ] Verify health endpoint: `GET https://your-backend-domain/health` -> `{"status":"healthy"}`.

---

## 2. Frontend Web App Deployment (Vercel)
- [ ] Connect GitHub repository: `smzuhaib06/SecureFix-X`.
- [ ] Set Root Directory to `frontend`.
- [ ] Set Framework Preset to **Next.js**.
- [ ] Add Environment Variable:
  - Key: `NEXT_PUBLIC_API_URL`
  - Value: `https://your-backend-domain` (without trailing slash)
- [ ] Build Command: `next build --no-lint` (or `npm run build`).
- [ ] Deploy and verify all 14 routes load statically.
- [ ] Test live Server-Sent Events (SSE) stream from `/investigations/[id]`.
