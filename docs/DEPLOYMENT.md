# SECUREFIX X — Production Deployment Architecture

This document specifies the deployment guidelines for SECUREFIX X across production and cloud environments.

---

## 1. Architecture Overview

```text
┌────────────────────────────────────────────────────────┐
│                   Vercel Platform                      │
│            Next.js 14 App Router Frontend              │
│       https://securefix.vercel.app (Public UI)         │
└───────────────────────────┬────────────────────────────┘
                            │ HTTPS / SSE
                            ▼
┌────────────────────────────────────────────────────────┐
│          Backend Cloud Host (Render / Fly.io / EC2)    │
│        FastAPI REST API + Git Sandboxing Service       │
│           https://api.securefix.app (:8000)            │
├────────────────────────────────────────────────────────┤
│  • 7 Deterministic Security Evidence Agents            │
│  • Local RAG Vector Knowledge Base (TF-IDF/BM25)       │
│  • AI Security Reasoner (Google Gemini / OpenAI / Fallback) │
│  • Git Sandbox Runner (Clones public GitHub repos)     │
│  • Verification & Mutation Assurance Engines           │
│  • SQLite Persistent Investigation Store               │
└────────────────────────────────────────────────────────┘
```

---

## 2. Frontend Deployment (Vercel)

### Platform Details
- **Platform:** Vercel (Optimized for Next.js 14)
- **Framework Preset:** Next.js
- **Root Directory:** `frontend`
- **Build Command:** `next build --no-lint` (or `npm run build`)
- **Output Directory:** `frontend/.next`
- **Node.js Version:** 18.x or 20.x

### Required Environment Variables
| Variable | Description | Example |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | Public URL of the deployed FastAPI backend API | `https://api.securefix.app` |

### Step-by-Step Vercel Deployment
1. Import the repository into Vercel from GitHub (`smzuhaib06/SecureFix-X`).
2. In **Project Settings**:
   - Set **Root Directory** to `frontend`.
   - Set **Build Command** to `npm run build`.
   - Add Environment Variable: `NEXT_PUBLIC_API_URL` = `https://<your-backend-domain>`.
3. Click **Deploy**. Vercel will prerender all 14 routes statically.

---

## 3. Backend Deployment (Render / Fly.io / AWS ECS)

### Deployment Requirements
The SECUREFIX X backend requires:
1. **Python 3.10+** (tested on 3.11/3.14).
2. **Git binary installed** (`git` in `$PATH` for repository cloning and sandboxing).
3. **Filesystem write access** to `/tmp` (ephemeral sandbox directories for repo cloning and patch simulation).
4. **Persistent disk or SQLite storage** for `securefix.db`.

*Note on Vercel Serverless Functions:* Do NOT deploy the FastAPI backend to Vercel Serverless Functions. Vercel Serverless environments restrict child-process execution (`git clone`), execution timeouts (max 10-60s), and read-only filesystems. Deploy the backend to a long-running container service (Render, Fly.io, Railway, AWS ECS, or DigitalOcean App Platform).

### Required Environment Variables
| Variable | Description | Default / Example |
|---|---|---|
| `PORT` | Listening HTTP port | `8000` |
| `DATABASE_URL` | SQLite database URI | `sqlite:///./backend/securefix.db` |
| `DEMO_REPO_PATH` | Path for default fallback demo repo | `demo-app` |
| `GOOGLE_API_KEY` | Optional: Google Gemini API key | `AIzaSy...` (optional) |
| `OPENAI_API_KEY` | Optional: OpenAI API key | `sk-...` (optional) |

### Backend Dockerfile Deployment
The repository includes a production Dockerfile in `backend/Dockerfile`:
```bash
# Build and run with Docker
docker build -t securefix-backend -f backend/Dockerfile .
docker run -p 8000:8000 -e PORT=8000 securefix-backend
```

### CORS Configuration
In `backend/app/main.py`:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits Vercel frontend domain to query API & stream SSE
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## 4. Local Full-Stack Deployment (Quick Start)

To run the complete system locally:

```bash
# 1. Clone the repository
git clone https://github.com/smzuhaib06/SecureFix-X.git
cd SecureFix-X

# 2. Setup backend virtualenv
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Start backend service
uvicorn app.main:app --host 0.0.0.0 --port 8000 &

# 4. Start frontend service
cd ../frontend
npm install
npm run dev
# Frontend live at http://localhost:3000
```
