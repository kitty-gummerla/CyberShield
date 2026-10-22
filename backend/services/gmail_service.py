"""
Gmail Integration Service — OAuth2 Authentication & Safe Read-Only Retrieval
Uses official Google Client Libraries (google-auth, google-api-python-client).
Enforces strict read-only access (https://www.googleapis.com/auth/gmail.readonly).

College Project / Single-User SOC Scope Note:
- Credentials and OAuth state tokens are maintained in-memory within the server process.
- State tokens provide single-use CSRF mitigation for the callback exchange.
- PKCE code_verifier is preserved in server memory alongside the state to satisfy RFC 7636.
- In this local single-user architecture, state tokens are not bound to browser session cookies.
- For a multi-user production system, encrypted session cookies and persistent secret vaults would be required.
"""

import os
import time
import base64
import secrets
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from dotenv import load_dotenv

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from requests.exceptions import RequestException

from models.schemas import InboxEmailSummary

logger = logging.getLogger(__name__)

# Ensure Google OAuth scope changes/expansions do not raise unhandled Warning exceptions
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

# Ensure .env is loaded from backend directory if running in environments where CWD is root
_backend_env = Path(__file__).resolve().parent.parent / ".env"
if _backend_env.exists():
    load_dotenv(dotenv_path=_backend_env)

# Enforce strict read-only access; write/modify/delete/send scopes are never requested
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
STATE_TTL_SECONDS = 600  # 10 minutes


class GmailService:
    """
    Manages OAuth2 lifecycle and transient, on-demand Gmail API interactions.
    Does NOT download or store mailbox collections; strictly fetches metadata or single selected messages.
    """

    def __init__(self):
        self.client_id = os.getenv("GMAIL_CLIENT_ID")
        self.client_secret = os.getenv("GMAIL_CLIENT_SECRET")
        self.redirect_uri = os.getenv("GMAIL_REDIRECT_URI", "http://127.0.0.1:8000/auth/gmail/callback")
        
        # Module-level in-memory credential storage for single-user local runtime
        self._credentials: Optional[Credentials] = None
        self._connected_email: Optional[str] = None
        
        # In-memory single-use state storage: {state_token: {"created_at": float, "code_verifier": str}}
        self._oauth_states: Dict[str, Dict[str, Any]] = {}

    def is_configured(self) -> bool:
        """Returns True if client credentials exist in environment variables."""
        return bool(self.client_id and self.client_secret and self.redirect_uri)

    def _purge_expired_states(self) -> None:
        """Removes expired OAuth state tokens exceeding STATE_TTL_SECONDS."""
        now = time.time()
        expired = [
            token for token, data in self._oauth_states.items()
            if (now - data.get("created_at", 0)) > STATE_TTL_SECONDS
        ]
        for token in expired:
            self._oauth_states.pop(token, None)

    def get_authorization_url(self) -> Tuple[str, str]:
        """
        Creates an OAuth2 authorization URL with a cryptographically random, single-use state.
        Preserves the PKCE code_verifier server-side for the callback exchange.
        Never logs authorization URLs, codes, verifiers, or secrets.
        """
        if not self.is_configured():
            raise ValueError("Gmail OAuth credentials are not fully configured in environment variables.")

        self._purge_expired_states()
        
        # Generate cryptographically secure state
        state = secrets.token_urlsafe(32)

        client_config = {
            "web": {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [self.redirect_uri],
            }
        }

        flow = Flow.from_client_config(
            client_config,
            scopes=GMAIL_SCOPES,
            redirect_uri=self.redirect_uri
        )

        authorization_url, _ = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
            state=state
        )

        # Securely associate the generated PKCE code_verifier with this single-use state
        self._oauth_states[state] = {
            "created_at": time.time(),
            "code_verifier": flow.code_verifier
        }

        logger.info("Generated Gmail OAuth authorization URL.")
        return authorization_url, state

    def exchange_code(self, code: str, state: str) -> Dict[str, Any]:
        """
        Validates state against single-use in-memory store (immediately consuming it).
        Attaches the matching PKCE code_verifier to complete token exchange.
        Stores credentials in-memory and retrieves authenticated user email address.
        Maintains generic error logging without logging codes, tokens, or exceptions.
        """
        self._purge_expired_states()
        
        # Immediately pop state to enforce single-use requirement
        state_data = self._oauth_states.pop(state, None)
        if not state_data or not isinstance(state_data, dict):
            logger.warning("OAuth state validation failed: invalid, replayed, or unrecognized state.")
            return {"connected": False, "error": "Invalid or already consumed OAuth state parameter."}

        created_at = state_data.get("created_at", 0)
        code_verifier = state_data.get("code_verifier")

        if (time.time() - created_at) > STATE_TTL_SECONDS:
            logger.warning("OAuth state validation failed: state token expired.")
            return {"connected": False, "error": "OAuth state parameter has expired."}

        if not code_verifier:
            logger.warning("OAuth state validation failed: missing PKCE code verifier.")
            return {"connected": False, "error": "Missing PKCE code verifier for OAuth state."}

        try:
            client_config = {
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [self.redirect_uri],
                }
            }

            flow = Flow.from_client_config(
                client_config,
                scopes=GMAIL_SCOPES,
                redirect_uri=self.redirect_uri,
                code_verifier=code_verifier,
                autogenerate_code_verifier=False
            )

            # Re-attach the PKCE code_verifier corresponding to the original authorization request
            flow.code_verifier = code_verifier

            flow.fetch_token(code=code)
            self._credentials = flow.credentials
            logger.info("Successfully completed Gmail OAuth token exchange.")

            # Best-effort retrieval of user email (does not fail OAuth if profile API call encounters an error)
            self._connected_email = "connected_user"
            try:
                client = self._get_gmail_client()
                if client:
                    profile = client.users().getProfile(userId="me").execute()
                    self._connected_email = profile.get("emailAddress", "connected_user")
            except Exception as profile_err:
                logger.warning("Could not fetch user profile (%s). Using fallback identifier.", type(profile_err).__name__)

            return {"connected": True, "email": self._connected_email}

        except Exception as exc:
            # Safe classification of OAuth failure without exposing secrets, tokens, codes, or verifiers
            safe_error_category = "unknown_error"
            if isinstance(exc, Warning) and "Scope has changed" in str(exc):
                safe_error_category = "scope_changed"
            elif isinstance(exc, OAuth2Error):
                safe_error_category = getattr(exc, "error", None) or type(exc).__name__
            elif isinstance(exc, RequestException):
                safe_error_category = f"network_transport_error ({type(exc).__name__})"
            elif isinstance(exc, HttpError):
                status_code = getattr(exc.resp, "status", None)
                safe_error_category = f"http_error_{status_code}"
            else:
                safe_error_category = type(exc).__name__

            if safe_error_category == "invalid_client":
                logger.error("OAuth token exchange failed: category=invalid_client (Google rejected client credentials: 'The provided client secret is invalid'). Please verify GMAIL_CLIENT_SECRET in backend/.env matches the secret in Google Cloud Console.")
            else:
                logger.error("OAuth token exchange failed: category=%s", safe_error_category)

            self._credentials = None
            self._connected_email = None
            return {"connected": False, "error": f"Failed to exchange authorization code: {safe_error_category}"}

    def get_connection_status(self) -> Dict[str, Any]:
        """
        Returns connection state: {'connected': bool, 'email': Optional[str]}.
        Access and refresh tokens are strictly withheld from the response.
        """
        if not self._credentials:
            return {"connected": False, "email": None}

        if self._credentials.expired:
            if not self._refresh_if_expired():
                return {"connected": False, "email": None}

        return {"connected": True, "email": self._connected_email}

    def disconnect(self) -> Dict[str, Any]:
        """
        Clears CyberShield's in-memory credentials, connected email, and pending OAuth states.
        
        Intentional Semantics:
        - Clears local authentication state from server memory.
        - Does NOT revoke the user's authorization on Google's authorization servers.
        - Suitable for single-user local projects to avoid requiring re-consent each session.
        """
        self._credentials = None
        self._connected_email = None
        self._oauth_states.clear()
        logger.info("Gmail credentials cleared from memory.")
        return {"connected": False, "disconnected": True}

    def _refresh_if_expired(self) -> bool:
        """Auto-refreshes credentials using the refresh token if expired."""
        if not self._credentials:
            return False

        if self._credentials.expired and self._credentials.refresh_token:
            try:
                self._credentials.refresh(Request())
                logger.info("Refreshed expired Gmail OAuth access token.")
                return True
            except RefreshError:
                logger.warning("Gmail refresh token expired or revoked. Resetting credentials.")
                self.disconnect()
                return False
            except Exception:
                logger.error("Failed to refresh Gmail access token.")
                return False

        return self._credentials.valid

    def _get_gmail_client(self):
        """Constructs an authorized Google API service instance, auto-refreshing if expired."""
        if not self._credentials:
            return None

        if self._credentials.expired:
            if not self._refresh_if_expired():
                return None

        return build("gmail", "v1", credentials=self._credentials, cache_discovery=False)

    def list_inbox_messages(self, max_results: int = 15) -> List[InboxEmailSummary]:
        """
        Fetches metadata summaries of up to `max_results` inbox emails.
        Uses `format='metadata'` to retrieve only headers and snippets.
        NEVER downloads message bodies or attachment bytes.
        """
        client = self._get_gmail_client()
        if not client:
            logger.warning("Cannot list Gmail messages: client not authenticated.")
            return []

        try:
            results = client.users().messages().list(
                userId="me",
                maxResults=min(max_results, 50),
                q="label:INBOX"
            ).execute()

            messages_meta = results.get("messages", [])
            summaries: List[InboxEmailSummary] = []

            for msg_ref in messages_meta:
                msg_id = msg_ref.get("id")
                if not msg_id:
                    continue

                msg_data = client.users().messages().get(
                    userId="me",
                    id=msg_id,
                    format="metadata",
                    metadataHeaders=["From", "Subject", "Date"]
                ).execute()

                headers = {h.get("name", ""): h.get("value", "") for h in msg_data.get("payload", {}).get("headers", [])}
                sender = headers.get("From", "Unknown Sender")
                subject = headers.get("Subject", "(No Subject)")
                date_str = headers.get("Date", "")
                snippet = msg_data.get("snippet", "")
                labels = msg_data.get("labelIds", [])

                # Check if parts contain filenames indicating attachments
                has_attachments = False
                payload_parts = msg_data.get("payload", {}).get("parts", [])
                for part in payload_parts:
                    if part.get("filename"):
                        has_attachments = True
                        break

                summaries.append(
                    InboxEmailSummary(
                        id=msg_id,
                        sender=sender,
                        subject=subject,
                        snippet=snippet,
                        received_at=date_str,
                        has_attachments=has_attachments,
                        is_unread="UNREAD" in labels
                    )
                )

            return summaries

        except Exception as exc:
            if isinstance(exc, HttpError) and getattr(exc.resp, "status", None) == 403:
                logger.error("Failed to list Gmail inbox messages: 403 Forbidden. Ensure the 'Gmail API' is enabled in your Google Cloud Console project.")
            else:
                logger.error("Failed to list Gmail inbox messages (%s).", type(exc).__name__)
            return []

    def fetch_email_content(self, message_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetches full content ONLY for the explicitly requested message_id via
        users.messages.get(format='full').

        - Extracts message body.
        - Extracts attachment metadata only (filename, mimeType, size, attachmentId).
          NEVER calls Gmail attachments.get or downloads attachment bytes.
        - Preserves all headers in RFC 822 format (including Authentication-Results,
          Received-SPF, DKIM-Signature) for the header analyzer.

        Returns standard CyberShield email dict or None.
        """
        if not message_id:
            logger.warning("fetch_email_content called without message_id.")
            return None

        client = self._get_gmail_client()
        if not client:
            logger.warning("Cannot fetch Gmail message: client not authenticated.")
            return None

        try:
            msg = client.users().messages().get(
                userId="me",
                id=message_id,
                format="full"
            ).execute()

            payload = msg.get("payload", {})
            headers_list = payload.get("headers", [])

            # Extract sender & subject
            headers_map = {h.get("name", ""): h.get("value", "") for h in headers_list}
            sender = headers_map.get("From", "Unknown Sender")
            subject = headers_map.get("Subject", "(No Subject)")

            # Reconstruct complete RFC 822 headers string preserving authentication headers
            raw_headers = self._reconstruct_raw_headers(headers_list)

            # Parse MIME payload for body and attachment metadata
            body_text, attachments = self._parse_mime_payload(payload)

            return {
                "sender": sender,
                "subject": subject,
                "body": body_text,
                "raw_headers": raw_headers,
                "attachments": attachments
            }

        except Exception as exc:
            logger.error("Failed to fetch Gmail message content (%s).", type(exc).__name__)
            return None

    def _parse_mime_payload(self, payload: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Recursively inspects MIME payload.
        - Decodes plain-text (or fallback HTML) body.
        - Extracts attachment metadata only.
        - NEVER calls attachments.get or downloads attachment bytes.
        """
        body_parts: List[str] = []
        html_parts: List[str] = []
        attachments: List[Dict[str, Any]] = []

        def walk_parts(part: Dict[str, Any]):
            filename = part.get("filename", "")
            mime_type = part.get("mimeType", "")
            body = part.get("body", {})

            # If part has a filename, treat as attachment metadata only
            if filename:
                attachments.append({
                    "filename": filename,
                    "content_type": mime_type or "application/octet-stream",
                    "file_size_bytes": body.get("size", 0),
                    "attachment_id": body.get("attachmentId")
                })
                # Do not parse attachment body as email text
                return

            # Extract message text
            data = body.get("data")
            if data:
                try:
                    decoded = base64.urlsafe_b64decode(data.encode("ASCII")).decode("utf-8", errors="replace")
                    if mime_type == "text/plain":
                        body_parts.append(decoded)
                    elif mime_type == "text/html":
                        html_parts.append(decoded)
                except Exception:
                    pass

            # Recursively walk child parts (e.g. multipart/mixed, multipart/alternative)
            for child in part.get("parts", []):
                walk_parts(child)

        walk_parts(payload)

        # Prioritize plain text body; fallback to HTML if plain text unavailable
        full_body = "\n\n".join(body_parts).strip()
        if not full_body and html_parts:
            full_body = "\n\n".join(html_parts).strip()

        return full_body, attachments

    def _reconstruct_raw_headers(self, headers_list: List[Dict[str, str]]) -> str:
        """
        Preserves original header names and values in RFC 822 format.
        Preserves Authentication-Results, Received-SPF, DKIM-Signature, ARC, and standard routing headers.
        """
        lines = []
        for h in headers_list:
            name = h.get("name", "").strip()
            value = h.get("value", "").strip()
            if name:
                lines.append(f"{name}: {value}")
        return "\r\n".join(lines)


# Global Service Instance
gmail_service = GmailService()
