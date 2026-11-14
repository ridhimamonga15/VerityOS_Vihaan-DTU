# VerityOS — A Trust-Aware Autonomous AI Operating System

## Overview

VerityOS is a multi-agent AI platform that researches information, extracts claims, verifies them against evidence, evaluates trust using six dimensions, and applies a policy decision (PASS / REVIEW / REJECT) — all displayed on a transparent dashboard with sources and audit trails.

## Architecture

```
User Query → Backend API (Member 3)
               → execute_pipeline() (Member 1 — Orchestrator)
                   → Research Agent → evidence
                   → Data Agent → claims + evidence links
                   → Verification Agent → verification results
                   → Trust Engine (Member 2) → trust evaluation + policy decision
               → Structured JSON response
           → Frontend Dashboard (Member 4)
```

## Team Ownership

| Folder | Owner | Responsibility |
|---|---|---|
| `agents/` | Member 1 | Research, Data, Verification agents + Orchestrator |
| `trust_engine/` | Member 2 | Trust dimensions, scoring, policy engine |
| `backend/` | Member 3 | FastAPI app, routes, validation, CORS |
| `frontend/` | Member 4 | Next.js UI, dashboard, claim inspector |
| `tests/` | Shared | Unit + integration tests |

## Quick Start

### 1. Install dependencies

```bash
cd VerityOS_Vihaan_DTU
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your settings
```

### 3. Start the backend

```bash
uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`.

- **Swagger docs:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

### 4. Run tests

```bash
python -m unittest discover tests
```

## API Endpoints

### Authentication Endpoints (Member 3)

#### `POST /api/auth/signup`
Register a new user account.

**Request:**
```json
{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "password": "SecurePassword123!",
  "confirm_password": "SecurePassword123!"
}
```

**Response (201 Created):**
```json
{
  "message": "User registered successfully",
  "token": "4v_...",
  "token_type": "bearer",
  "user": {
    "id": "user_a1b2c3d4e5f6",
    "name": "Jane Doe",
    "email": "jane@example.com",
    "created_at": "2026-11-14T18:30:00+00:00"
  }
}
```

#### `POST /api/auth/login`
Authenticate email and password to receive a bearer token.

**Request:**
```json
{
  "email": "jane@example.com",
  "password": "SecurePassword123!"
}
```

**Response (200 OK):**
```json
{
  "message": "Login successful",
  "token": "4v_...",
  "token_type": "bearer",
  "user": {
    "id": "user_a1b2c3d4e5f6",
    "name": "Jane Doe",
    "email": "jane@example.com",
    "created_at": "2026-11-14T18:30:00+00:00"
  }
}
```

#### `GET /api/auth/me`
Retrieve the authenticated user's profile.

**Headers:**
```
Authorization: Bearer <your_token>
```

**Response (200 OK):**
```json
{
  "id": "user_a1b2c3d4e5f6",
  "name": "Jane Doe",
  "email": "jane@example.com",
  "created_at": "2026-11-14T18:30:00+00:00"
}
```

#### `POST /api/auth/logout`
Invalidate the current bearer token.

**Headers:**
```
Authorization: Bearer <your_token>
```

**Response (200 OK):**
```json
{
  "message": "Logged out successfully"
}
```

### Core Pipeline Endpoints

### `GET /api/health`

Health check.

**Response:**
```json
{
  "status": "healthy",
  "service": "verityos-backend",
  "version": "0.1.0"
}
```

### `POST /api/analyze`

Submit a query for analysis.

**Request:**
```json
{
  "query": "Prepare a short market research report about Company X.",
  "options": {
    "mode": "collaborative"
  }
}
```

**Response (success):**
```json
{
  "task_id": "task-abc123def456",
  "status": "SUCCESS",
  "query": "Prepare a short market research report about Company X.",
  "decision": "APPROVED",
  "trust_score": 72.5,
  "trust_grade": "B",
  "claims": [...],
  "evidence": [...],
  "verification_results": [...],
  "trust_evaluation": {
    "overall_score": 72.5,
    "grade": "B",
    "policy_decision": "PASS",
    "dimension_scores": {...},
    "per_claim_evaluations": [...]
  },
  "provenance": {
    "pipeline_stages": ["research", "data", "verification", "trust"],
    "timestamps": {...},
    "mock_mode": true
  },
  "limitations": [...],
  "errors": []
}
```

### Decision Mapping

| Trust Engine | Product State | Meaning |
|---|---|---|
| `PASS` | `APPROVED` | Evidence passed trust policy |
| `REVIEW` | `QUARANTINED` | Needs human review |
| `REJECT` | `REJECTED` | Failed trust policy |
| `EMPTY` | `INSUFFICIENT_DATA` | Not enough evidence |
| `ERROR` | `ERROR` | Pipeline failure |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BACKEND_HOST` | `0.0.0.0` | Server bind host |
| `BACKEND_PORT` | `8000` | Server bind port |
| `BACKEND_DEBUG` | `false` | Enable debug logging and hot-reload |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |
| `USE_MOCK_PIPELINE` | `true` | Use mock pipeline (set `false` for real agents) |
| `AUTH_DB_PATH` | `backend/data/auth.db` | Path to SQLite authentication database |
| `AUTH_TOKEN_EXPIRE_HOURS` | `24` | Session token validity duration in hours |
| `AUTH_SECRET_KEY` | `...` | Secret key for auth hashing/tokens |
| `REQUIRE_AUTH_FOR_ANALYZE` | `false` | When `true`, `/api/analyze` requires a valid Bearer token |

## Mock Mode

When `USE_MOCK_PIPELINE=true` (default), the backend returns synthetic data that matches the agreed schema. **Mock output is always labelled** — `provenance.mock_mode` is `true` and limitations list the mock status.

Set `USE_MOCK_PIPELINE=false` to use Member 1's real `agents.orchestrator.execute_pipeline()`.

## Frontend Integration (Member 4)

Base URL: `http://localhost:8000`

```javascript
// Example fetch call
const response = await fetch('http://localhost:8000/api/analyze', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    query: "Prepare a market research report about Company X",
    options: { mode: "collaborative" }
  })
});
const data = await response.json();
```

CORS is enabled for `http://localhost:3000` by default.

## Project Status

- [x] Architecture and integration plan
- [x] Backend API (Member 3)
- [ ] Agents & Orchestrator (Member 1)
- [ ] Trust Engine completion (Member 2)
- [ ] Frontend dashboard (Member 4)
- [ ] End-to-end integration
