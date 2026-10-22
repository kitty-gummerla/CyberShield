"""
Gmail OAuth Authentication Routes

Provides endpoints for:
1. GET  /auth/gmail/connect    -> Initiates OAuth flow, redirects browser to Google
2. GET  /auth/gmail/callback   -> Handles Google OAuth callback, exchanges code, redirects to frontend
3. GET  /auth/gmail/status     -> Returns safe connection status (connected: bool, email: str | None)
4. POST /auth/gmail/disconnect -> Clears in-memory credentials
"""

import os
import logging
from typing import Dict, Any, Optional

from fastapi import APIRouter, Query, status
from fastapi.responses import RedirectResponse

from services.gmail_service import gmail_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")


@router.get(
    "/gmail/connect",
    summary="Initiate Gmail OAuth connection",
    description="Generates an authorization URL with a single-use CSRF state and redirects the browser to Google consent.",
    response_class=RedirectResponse,
    status_code=status.HTTP_307_TEMPORARY_REDIRECT
)
async def connect_gmail():
    """
    Initiates the Gmail OAuth2 flow.
    Redirects directly to Google's consent screen.
    Does not log or expose the authorization URL or state parameter.
    """
    if not gmail_service.is_configured():
        logger.warning("Gmail OAuth connect rejected: client credentials not configured.")
        return RedirectResponse(
            url=f"{FRONTEND_URL}/analyzer?gmail=error",
            status_code=status.HTTP_307_TEMPORARY_REDIRECT
        )

    try:
        auth_url, _ = gmail_service.get_authorization_url()
        return RedirectResponse(
            url=auth_url,
            status_code=status.HTTP_307_TEMPORARY_REDIRECT
        )
    except Exception:
        logger.error("Failed to generate Gmail authorization URL.")
        return RedirectResponse(
            url=f"{FRONTEND_URL}/analyzer?gmail=error",
            status_code=status.HTTP_307_TEMPORARY_REDIRECT
        )


@router.get(
    "/gmail/callback",
    summary="Handle Gmail OAuth callback",
    description="Receives authorization code from Google, verifies state, exchanges for tokens, and redirects back to frontend.",
    response_class=RedirectResponse,
    status_code=status.HTTP_307_TEMPORARY_REDIRECT
)
async def gmail_oauth_callback(
    code: Optional[str] = Query(None, description="One-time authorization code from Google"),
    state: Optional[str] = Query(None, description="Cryptographic CSRF state token"),
    error: Optional[str] = Query(None, description="Google OAuth error reason if rejected")
):
    """
    Handles the redirect from Google.
    Exchanges code for credentials in-memory and redirects back to the React UI.
    Never logs authorization codes, state values, or credentials.
    Never passes tokens or sensitive information in redirect query strings.
    """
    # Handle user cancellation, denial, or missing query parameters
    if error or not code or not state:
        logger.warning("Gmail OAuth callback received with error or missing parameters.")
        return RedirectResponse(
            url=f"{FRONTEND_URL}/analyzer?gmail=error",
            status_code=status.HTTP_307_TEMPORARY_REDIRECT
        )

    try:
        exchange_result = gmail_service.exchange_code(code=code, state=state)
        if exchange_result.get("connected"):
            logger.info("Gmail OAuth authentication successful.")
            return RedirectResponse(
                url=f"{FRONTEND_URL}/analyzer?gmail=connected",
                status_code=status.HTTP_307_TEMPORARY_REDIRECT
            )
        else:
            logger.warning("Gmail OAuth code exchange rejected.")
            return RedirectResponse(
                url=f"{FRONTEND_URL}/analyzer?gmail=error",
                status_code=status.HTTP_307_TEMPORARY_REDIRECT
            )
    except Exception:
        logger.error("Unexpected error in Gmail OAuth callback handler.")
        return RedirectResponse(
            url=f"{FRONTEND_URL}/analyzer?gmail=error",
            status_code=status.HTTP_307_TEMPORARY_REDIRECT
        )


@router.get(
    "/gmail/status",
    summary="Check Gmail connection status",
    description="Returns whether Gmail is currently connected in-memory and the associated email address.",
    response_model=Dict[str, Any]
)
async def get_gmail_status():
    """
    Provides safe connection status for UI polling and state detection.
    Never returns credentials, access tokens, or refresh tokens.
    """
    return gmail_service.get_connection_status()


@router.post(
    "/gmail/disconnect",
    summary="Disconnect Gmail session",
    description="Clears in-memory credentials and resets connection state in CyberShield without revoking Google account authorization.",
    response_model=Dict[str, Any]
)
async def disconnect_gmail():
    """
    Clears stored credentials from memory.
    Does not revoke Google authorization on Google servers at this stage.
    """
    return gmail_service.disconnect()
