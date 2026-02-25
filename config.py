"""
config.py — centralised configuration for FozamiMail.

All values are read from environment variables.  Create a .env file in
this directory (copy .env.example) and fill in your credentials.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the same directory as this file, if it exists.
_env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=_env_path)

# ── Gmail IMAP ─────────────────────────────────────────────────────────────
GMAIL_USER: str = os.getenv("GMAIL_USER", "")
GMAIL_APP_PASSWORD: str = os.getenv("GMAIL_APP_PASSWORD", "")
IMAP_SERVER: str = "imap.gmail.com"
IMAP_PORT: int = 993

# ── Ollama ─────────────────────────────────────────────────────────────────
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "120"))

# ── Agent behaviour ────────────────────────────────────────────────────────
# How often (seconds) the loop checks for new emails.
POLL_INTERVAL_SECONDS: int = int(os.getenv("POLL_INTERVAL_SECONDS", "300"))

# Maximum characters of email body sent to the LLM.
# Keeps prompt size predictable; longer bodies are truncated.
MAX_BODY_CHARS: int = int(os.getenv("MAX_BODY_CHARS", "4000"))

# ── Storage ────────────────────────────────────────────────────────────────
# Path to the SQLite database file.  Relative paths are resolved from the
# email_agent/ directory.
DB_PATH: str = os.getenv("DB_PATH", str(Path(__file__).parent / "email_agent.db"))
