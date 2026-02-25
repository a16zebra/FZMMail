# FozamiMail

A local-first autonomous email processing agent.  Connects to Gmail via IMAP,
analyses each unread email with a local Ollama LLM, and stores structured
results in a SQLite database.  No cloud services.  No auto-replies.

---

## Requirements

| Component | Minimum version |
|-----------|----------------|
| Python    | 3.11            |
| Ollama    | any recent      |
| Gmail     | account with IMAP enabled + App Password |

---

## Quick-start

### 1. Install Ollama and pull a model

```bash
# Install Ollama from https://ollama.com/download
ollama pull llama3.2
```

Verify it works:

```bash
ollama run llama3.2 "Reply with only valid JSON: {\"ok\": true}"
```

### 2. Enable Gmail IMAP and create an App Password

1. Go to **Gmail → Settings → See all settings → Forwarding and POP/IMAP**
   and enable IMAP.
2. On your Google Account page → **Security → 2-Step Verification** (enable it).
3. **Security → App Passwords** → create a password for "Mail / Windows Computer".
4. Copy the 16-character code.

### 3. Clone / set up the project

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

### 4. Configure credentials

```bash
cp .env.example .env
```

Edit `.env`:

```
GMAIL_USER=your.address@gmail.com
GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
OLLAMA_MODEL=llama3.2
```

All other values have sensible defaults.

### 5. Run

```bash
# Process all unread emails once and exit:
python agent.py --once

# Continuous agent loop (polls every 5 minutes):
python agent.py

# Review what was processed:
python agent.py --list
python agent.py --list --limit 25
```

---

## Configuration reference

All settings live in `.env`.  See `.env.example` for documentation of every
variable.

| Variable | Default | Description |
|----------|---------|-------------|
| `GMAIL_USER` | — | Gmail address |
| `GMAIL_APP_PASSWORD` | — | Google App Password |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `mistral` | Model name (must be pulled) |
| `OLLAMA_TIMEOUT` | `120` | Request timeout in seconds |
| `POLL_INTERVAL_SECONDS` | `300` | Seconds between Gmail polls |
| `MAX_BODY_CHARS` | `4000` | Max email body chars sent to LLM |
| `DB_PATH` | `email_agent.db` | SQLite file path |

---

## Architecture

```
agent.py            CLI entry point + agent loop
  │
  ├── gmail_client.py    IMAP connection; fetches + parses emails
  │                      yields { message_id, subject, sender,
  │                               received_at, body }
  │
  ├── llm_processor.py   POST to Ollama /api/chat; parses + validates JSON
  │                      returns { category, urgency, summary,
  │                                requires_action, importance_score }
  │
  ├── database.py        SQLite layer
  │                      tables: emails, analyses
  │                      dedup key: Message-ID header (or SHA-256 fallback)
  │
  └── config.py          Reads .env; exposes typed constants
```

### SQLite schema

```sql
-- Raw email data
CREATE TABLE emails (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id  TEXT    UNIQUE NOT NULL,
    subject     TEXT,
    sender      TEXT,
    received_at TEXT,
    body        TEXT,
    stored_at   TEXT    NOT NULL
);

-- LLM analysis
CREATE TABLE analyses (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id       TEXT    UNIQUE NOT NULL,
    category         TEXT,
    urgency          TEXT,          -- low | medium | high | critical
    summary          TEXT,
    requires_action  INTEGER,       -- 0 or 1
    importance_score REAL,          -- 0.0 – 10.0
    raw_response     TEXT,          -- raw model output (for debugging)
    created_at       TEXT    NOT NULL,
    FOREIGN KEY (message_id) REFERENCES emails (message_id)
);
```

---

## Troubleshooting

**`Gmail IMAP login failed`**
: Check that IMAP is enabled in Gmail settings and that the App Password is correct.

**`Cannot connect to Ollama`**
: Run `ollama serve` in a separate terminal, or check that port 11434 is open.

**`No valid JSON found in model response`**
: Try a more capable model (`ollama pull mistral` then set `OLLAMA_MODEL=mistral`).
  The agent will skip the email and continue rather than crash.

**Agent marks emails as unread but re-processes them**
: The agent opens the mailbox in readonly mode — it never marks messages as read.
  Deduplication is handled entirely by the local SQLite database.

---

## Extending

- **New output fields** — add columns to `analyses`, update `llm_processor.py`
  schema, update `database.py`.
- **Different email providers** — replace `gmail_client.py`; the rest is unchanged.
- **Different LLM** — replace `llm_processor.py`; keep the same return signature.
- **Web dashboard** — query `database.get_recent_analyses()` from a Flask/FastAPI app.
