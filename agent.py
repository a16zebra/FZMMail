#!/usr/bin/env python3
"""
agent.py — FozamiMail: local-first autonomous email processing agent.

Usage
-----
    python agent.py              # continuous polling loop (default)
    python agent.py --once       # fetch & process once, then exit
    python agent.py --list       # show recently processed emails, then exit
    python agent.py --list --limit 20
    python agent.py --help
"""

import argparse
import logging
import sys
import time

import config
import database
from gmail_client import GmailClient
from llm_processor import analyze_email

# ── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("fozamimail")

# ── Gmail label names ──────────────────────────────────────────────────────

_LABEL_ACTION       = "Needs-Action"
_LABEL_VERIFICATION = "Needs-Verification"

# ── ANSI colour helpers ────────────────────────────────────────────────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_CYAN   = "\033[96m"   # verification tag
_URGENCY_COLOUR = {
    "low":      "\033[90m",   # dark grey
    "medium":   "\033[93m",   # yellow
    "high":     "\033[91m",   # red
    "critical": "\033[95m",   # magenta
}


def _colour(urgency: str, text: str) -> str:
    return f"{_URGENCY_COLOUR.get(urgency, '')}{text}{_RESET}"


# ── Display helpers ────────────────────────────────────────────────────────

def _status_tag(analysis: dict) -> str:
    """Return a coloured status tag string, or empty string if none applies."""
    if analysis.get("requires_verification"):
        return f"  {_CYAN}{_BOLD}[VERIFY ACTIVITY]{_RESET}"
    if analysis.get("requires_action"):
        return f"  {_BOLD}[ACTION REQUIRED]{_RESET}"
    return ""


def _print_analysis(email_data: dict, analysis: dict) -> None:
    """Print a formatted card for one processed email."""
    urgency = analysis["urgency"]
    score = analysis["importance_score"]

    print(f"\n{'─' * 64}")
    print(f"{_BOLD}From    {_RESET} {email_data['sender']}")
    print(f"{_BOLD}Subject {_RESET} {email_data['subject']}")
    print(f"{_BOLD}Date    {_RESET} {email_data['received_at']}")
    print(f"{_BOLD}Category{_RESET} {analysis['category']}")
    print(
        f"{_BOLD}Urgency {_RESET} {_colour(urgency, urgency.upper())}{_status_tag(analysis)}"
    )
    print(f"{_BOLD}Score   {_RESET} {score:.1f} / 10")
    print(f"{_BOLD}Summary {_RESET} {analysis['summary']}")
    print(f"{'─' * 64}")


def _print_recent(limit: int) -> None:
    """Print a compact table of recently processed emails."""
    rows = database.get_recent_analyses(limit)
    if not rows:
        print("No processed emails in the database yet.")
        return

    print(f"\n{_BOLD}Recent processed emails ({len(rows)} shown){_RESET}")
    print(f"{_DIM}  A = needs action   V = needs verification{_RESET}\n")
    header = (
        f"{'URGENCY':10} {'SCORE':5}  {'CATEGORY':12}  "
        f"{'':2}{'SUBJECT':40}  SENDER"
    )
    print(f"{_DIM}{header}{_RESET}")
    print("─" * 102)

    for row in rows:
        urgency = row["urgency"]
        if row.get("requires_verification"):
            status = f"{_CYAN}V{_RESET}"
        elif row.get("requires_action"):
            status = f"{_BOLD}A{_RESET}"
        else:
            status = " "
        subject = (row["subject"] or "")[:38]
        sender  = (row["sender"]  or "")[:30]
        line = (
            f"{_colour(urgency, urgency.upper()):10} "
            f"{row['importance_score']:5.1f}  "
            f"{row['category']:12}  "
            f"{status} "
            f"{subject:<40}  "
            f"{sender}"
        )
        print(line)


# ── Core processing logic ──────────────────────────────────────────────────

def process_new_emails() -> int:
    """
    Connect to Gmail, fetch unread emails, analyse unseen ones with Ollama,
    and persist results to SQLite.

    Returns the number of newly processed emails.
    Exits the process on fatal errors (bad credentials, Ollama unreachable).
    """
    processed = 0

    try:
        with GmailClient() as client:
            # Ensure both labels exist in Gmail before the processing loop.
            client.ensure_label_exists(_LABEL_ACTION)
            client.ensure_label_exists(_LABEL_VERIFICATION)

            for email_data in client.fetch_unread_emails():
                mid = email_data["message_id"]
                uid = email_data["imap_uid"]

                if database.is_processed(mid):
                    logger.debug("Already processed — skipping: %s", mid)
                    continue

                logger.info(
                    "Analysing: %r from %s",
                    email_data["subject"],
                    email_data["sender"],
                )

                try:
                    analysis, raw = analyze_email(
                        subject    = email_data["subject"],
                        sender     = email_data["sender"],
                        received_at= email_data["received_at"],
                        body       = email_data["body"],
                    )
                except RuntimeError as exc:
                    # Fatal — Ollama is down or unreachable.
                    logger.error("LLM error: %s", exc)
                    sys.exit(1)
                except ValueError as exc:
                    # Non-fatal — bad JSON from model; skip this email.
                    logger.warning("Parse error for %s: %s — skipping.", mid, exc)
                    continue

                # ── Gmail actions ──────────────────────────────────────
                if analysis["category"] == "spam":
                    client.mark_as_spam(uid)
                else:
                    if analysis["requires_action"]:
                        client.apply_label(uid, _LABEL_ACTION)
                    if analysis["requires_verification"]:
                        client.apply_label(uid, _LABEL_VERIFICATION)

                database.save_email(
                    message_id  = mid,
                    imap_uid    = uid,
                    subject     = email_data["subject"],
                    sender      = email_data["sender"],
                    received_at = email_data["received_at"],
                    body        = email_data["body"],
                )
                database.save_analysis(
                    message_id           = mid,
                    category             = analysis["category"],
                    urgency              = analysis["urgency"],
                    summary              = analysis["summary"],
                    requires_action      = analysis["requires_action"],
                    requires_verification= analysis["requires_verification"],
                    importance_score     = analysis["importance_score"],
                    raw_response         = raw,
                )

                _print_analysis(email_data, analysis)
                processed += 1

    except RuntimeError as exc:
        # Gmail connection / login failure.
        logger.error("%s", exc)
        sys.exit(1)

    return processed


# ── Agent loop ─────────────────────────────────────────────────────────────

def run_loop() -> None:
    """Poll Gmail repeatedly until interrupted with Ctrl-C."""
    interval = config.POLL_INTERVAL_SECONDS
    print(
        f"{_BOLD}FozamiMail agent running{_RESET}  "
        f"| model: {config.OLLAMA_MODEL}  "
        f"| poll: every {interval}s  "
        f"| Ctrl-C to stop"
    )

    while True:
        try:
            count = process_new_emails()
        except SystemExit:
            raise
        except KeyboardInterrupt:
            break
        except Exception as exc:
            logger.error("Unexpected error: %s", exc, exc_info=True)
        else:
            if count:
                logger.info("Processed %d new email(s).", count)
            else:
                logger.info("No new emails.")

        try:
            logger.info("Sleeping %ds until next poll...", interval)
            time.sleep(interval)
        except KeyboardInterrupt:
            break

    print("\nAgent stopped.")


# ── CLI ────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent.py",
        description="FozamiMail — local-first autonomous email processing agent",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--once",
        action="store_true",
        help="Process unread emails once and exit.",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="Show recently processed emails and exit.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        metavar="N",
        help="Number of emails to show with --list (default: 10).",
    )
    return parser


def main() -> None:
    database.init_db()

    parser = _build_parser()
    args = parser.parse_args()

    if args.list:
        _print_recent(args.limit)
        return

    if args.once:
        count = process_new_emails()
        print(f"\nDone. Processed {count} new email(s).")
        return

    run_loop()


if __name__ == "__main__":
    main()
