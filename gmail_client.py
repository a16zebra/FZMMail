"""
gmail_client.py — Gmail IMAP client for FozamiMail.

Connects via SSL to imap.gmail.com using an App Password, fetches all
UNSEEN messages from the INBOX, and yields them as plain dicts.

Requirements
------------
Gmail account must have:
  1. 2-Step Verification enabled
  2. An App Password generated (Google Account → Security → App Passwords)
  3. IMAP access enabled (Gmail Settings → See all settings → Forwarding and POP/IMAP)

The Message-ID header is used as the stable dedup key.  If an email has
no Message-ID (rare but valid), a SHA-256 hash of sender+date+subject is
used as a fallback so we never silently skip or re-process messages.
"""

import email
import email.header
import email.utils
import hashlib
import imaplib
import logging
from email.message import Message
from types import TracebackType
from typing import Generator

import config

logger = logging.getLogger(__name__)


# ── Header / body helpers ──────────────────────────────────────────────────

def _decode_header(raw_value: str | None) -> str:
    """Decode an RFC 2047 encoded email header into a plain Unicode string."""
    if not raw_value:
        return ""
    parts = email.header.decode_header(raw_value)
    decoded: list[str] = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            decoded.append(chunk.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(chunk)
    return " ".join(decoded).strip()


def _extract_text_body(msg: Message) -> str:
    """
    Return the plain-text body from an email.Message.

    For multipart messages, only text/plain parts that are not attachments
    are collected.  Falls back to whatever payload is available.
    """
    parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() != "text/plain":
                continue
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition.lower():
                continue
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                parts.append(payload.decode(charset, errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            parts.append(payload.decode(charset, errors="replace"))

    return "\n".join(parts).strip()


def _stable_message_id(msg: Message, subject: str, sender: str, date_str: str) -> str:
    """
    Return the email's Message-ID header, or a deterministic fallback hash
    so every email gets a unique, stable identifier.
    """
    mid = msg.get("Message-ID", "").strip()
    if mid:
        return mid
    # Fallback: hash of stable fields
    fingerprint = f"{sender}|{date_str}|{subject}"
    return "hash:" + hashlib.sha256(fingerprint.encode()).hexdigest()


# ── Client class ───────────────────────────────────────────────────────────

class GmailClient:
    """
    Context-manager wrapper around imaplib.IMAP4_SSL.

    Usage::

        with GmailClient() as client:
            for email_data in client.fetch_unread_emails():
                process(email_data)
    """

    def __init__(self) -> None:
        self._imap: imaplib.IMAP4_SSL | None = None

    # ── connection ────────────────────────────────────────────────────────

    def connect(self) -> None:
        if not config.GMAIL_USER or not config.GMAIL_APP_PASSWORD:
            raise ValueError(
                "GMAIL_USER and GMAIL_APP_PASSWORD must be set. "
                "Copy .env.example → .env and fill in your credentials."
            )
        self._imap = imaplib.IMAP4_SSL(config.IMAP_SERVER, config.IMAP_PORT)
        try:
            self._imap.login(config.GMAIL_USER, config.GMAIL_APP_PASSWORD)
        except imaplib.IMAP4.error as exc:
            raise RuntimeError(
                f"Gmail IMAP login failed for {config.GMAIL_USER!r}. "
                "Check your App Password and that IMAP is enabled in Gmail settings."
            ) from exc
        logger.info("Connected to Gmail IMAP as %s", config.GMAIL_USER)

    def disconnect(self) -> None:
        if self._imap:
            try:
                self._imap.logout()
            except Exception:
                pass
            self._imap = None
            logger.debug("Disconnected from Gmail IMAP.")

    # ── context manager ───────────────────────────────────────────────────

    def __enter__(self) -> "GmailClient":
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.disconnect()

    # ── main API ──────────────────────────────────────────────────────────

    def fetch_unread_emails(self) -> Generator[dict, None, None]:
        """
        Yield unread emails from the INBOX as dicts::

            {
                "imap_uid":   str,   # IMAP UID — use for apply_label / mark_as_spam
                "message_id": str,   # stable dedup key (Message-ID header or hash)
                "subject":    str,
                "sender":     str,
                "received_at": str,  # ISO-8601 UTC string, or raw Date header
                "body":       str,   # plain-text, truncated to MAX_BODY_CHARS
            }

        Opens the mailbox read-write so that action methods work.
        Skips messages that cannot be fetched or parsed, logging a warning.
        """
        if self._imap is None:
            raise RuntimeError("Not connected. Call connect() or use as a context manager.")

        # read-write: required for apply_label / mark_as_spam
        self._imap.select("INBOX")

        status, data = self._imap.uid("SEARCH", None, "UNSEEN")
        if status != "OK":
            logger.error("UID SEARCH failed: %s", status)
            return

        uid_list: list[str] = data[0].decode().split() if data[0] else []
        logger.info("Found %d unread message(s) in INBOX.", len(uid_list))

        for uid in uid_list:
            try:
                yield self._fetch_one_by_uid(uid)
            except Exception as exc:
                logger.warning("Skipping UID %s — %s", uid, exc)
                continue

    def ensure_label_exists(self, label: str) -> None:
        """
        Create a Gmail label if it doesn't already exist.

        Silently succeeds if the label is already present.
        Logs a warning (but does not raise) on unexpected failures.
        """
        if self._imap is None:
            raise RuntimeError("Not connected.")
        status, response = self._imap.create(label)
        if status == "OK":
            logger.info("Created Gmail label: %r", label)
        else:
            resp = (response[0] if response else b"").decode("utf-8", errors="replace")
            if "ALREADYEXISTS" in resp or "exists" in resp.lower():
                logger.debug("Label already exists: %r", label)
            else:
                logger.warning("Could not create label %r: %s", label, resp)

    def apply_label(self, uid: str, label: str) -> None:
        """
        Add a Gmail label to a message.

        The message remains in the INBOX — this only adds the label tag,
        equivalent to Gmail's "label" action.
        """
        if self._imap is None:
            raise RuntimeError("Not connected.")
        status, response = self._imap.uid("COPY", uid, label)
        if status != "OK":
            logger.warning("Could not apply label %r to UID %s: %s", label, uid, response)
        else:
            logger.debug("Applied label %r to UID %s.", label, uid)

    def mark_as_spam(self, uid: str) -> None:
        """
        Move a message to Gmail's Spam folder.

        Copies to [Gmail]/Spam, flags the original as deleted, then expunges.
        """
        if self._imap is None:
            raise RuntimeError("Not connected.")
        status, _ = self._imap.uid("COPY", uid, "[Gmail]/Spam")
        if status != "OK":
            logger.warning("Could not copy UID %s to Spam — skipping.", uid)
            return
        self._imap.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        self._imap.expunge()
        logger.info("Moved UID %s to Spam.", uid)

    # ── internals ─────────────────────────────────────────────────────────

    def _fetch_one_by_uid(self, uid: str) -> dict:
        """Fetch a single message by IMAP UID and return a data dict."""
        status, raw_data = self._imap.uid("FETCH", uid, "(RFC822)")
        if status != "OK" or not raw_data or raw_data[0] is None:
            raise ValueError(f"UID FETCH returned status={status!r}")

        raw_bytes: bytes = raw_data[0][1]  # type: ignore[index]
        msg: Message = email.message_from_bytes(raw_bytes)

        subject = _decode_header(msg.get("Subject"))
        sender = _decode_header(msg.get("From"))
        date_str = msg.get("Date", "")

        # Parse Date header into a proper ISO string; keep raw on failure.
        received_at = date_str
        if date_str:
            try:
                received_at = email.utils.parsedate_to_datetime(date_str).isoformat()
            except Exception:
                pass  # leave as the raw string

        body = _extract_text_body(msg)
        message_id = _stable_message_id(msg, subject, sender, date_str)

        return {
            "imap_uid": uid,
            "message_id": message_id,
            "subject": subject or "(no subject)",
            "sender": sender or "unknown",
            "received_at": received_at,
            "body": body[: config.MAX_BODY_CHARS],
        }
