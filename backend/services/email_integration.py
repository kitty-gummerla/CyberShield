"""
Email Inbox Integration Service

Provides safe, user-driven inbox connectivity.
Includes:
1. Base EmailProvider interface
2. Simulated Security Inbox Provider (Preloaded with realistic threat & safe test cases)
3. Production IMAP / OAuth abstraction ready for Gmail & Outlook API credentials
"""

import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from models.schemas import InboxEmailSummary, AttachmentMetadata
from services.gmail_service import gmail_service

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# PRE-LOADED REALISTIC SIMULATED INBOX
# ═══════════════════════════════════════════════════════════════════
# These realistic test cases allow instant, flawless demonstration
# without requiring live external OAuth verification during testing/viva.

SIMULATED_INBOX_EMAILS: Dict[str, Dict[str, Any]] = {
    "sim_msg_001": {
        "id": "sim_msg_001",
        "sender": "security-alert@paypal-update.xyz",
        "subject": "URGENT: Unauthorized Account Access Detected",
        "snippet": "We detected suspicious login activity from Russia. Your account will be permanently locked...",
        "received_at": "10 minutes ago",
        "has_attachments": False,
        "is_unread": True,
        "body": "Dear Customer, We detected an unauthorized login attempt from IP 185.220.101.5. Your account has been temporarily restricted. Click the secure verification portal below and confirm your password and 6-digit OTP immediately: http://paypal-verification.fake-security.xyz/login?user=auth",
        "attachments": [],
        "raw_headers": "From: \"PayPal Security Team\" <security-alert@paypal.com>\nReturn-Path: <bounce@attacker-vps.xyz>\nReply-To: <stealer@phish-inbox.com>\nReceived-SPF: fail (ip 185.220.101.5 is not authorized)\nAuthentication-Results: mx.google.com; dkim=fail; dmarc=fail (p=REJECT)"
    },
    "sim_msg_002": {
        "id": "sim_msg_002",
        "sender": "payroll-update@company-services.com",
        "subject": "Q3 Salary Adjustment & Bonus Calculation",
        "snippet": "Please find attached the updated salary adjustment document for all active employees...",
        "received_at": "2 hours ago",
        "has_attachments": True,
        "is_unread": True,
        "body": "Hello Team, Please review the attached corporate spreadsheet regarding updated Q3 salary structures and bonus incentives. Enable macros when prompted to generate your personalized tax projection.",
        "attachments": [
            {
                "filename": "Q3_Salary_Breakdown.xlsm",
                "file_size_bytes": 84500,
                "content_type": "application/vnd.ms-excel.sheet.macroEnabled.12"
            }
        ],
        "raw_headers": "From: \"Corporate HR\" <payroll-update@company-services.com>\nReturn-Path: <bounce@external-relay.com>\nReceived-SPF: softfail\nAuthentication-Results: dkim=none; dmarc=none"
    },
    "sim_msg_003": {
        "id": "sim_msg_003",
        "sender": "billing-support@fake-quickbooks.net",
        "subject": "Overdue Invoice Notice — Final Demand",
        "snippet": "Your overdue invoice of $1,450.00 is attached. Legal proceedings will initiate within 24 hours...",
        "received_at": "Yesterday",
        "has_attachments": True,
        "is_unread": False,
        "body": "ATTENTION: This is your final demand notice. Failure to settle the outstanding balance immediately will result in collections action. View the attached PDF invoice for remittance instructions.",
        "attachments": [
            {
                "filename": "Invoice_98412_Overdue.pdf.exe",
                "file_size_bytes": 182000,
                "content_type": "application/x-msdownload"
            }
        ],
        "raw_headers": "From: \"QuickBooks Billing\" <billing@quickbooks.com>\nReturn-Path: <attacker@darknet-node.top>\nReceived-SPF: fail\nAuthentication-Results: dkim=fail; dmarc=fail"
    },
    "sim_msg_004": {
        "id": "sim_msg_004",
        "sender": "registrar@university.edu",
        "subject": "Fall Semester Final Examination Schedule",
        "snippet": "Dear Students, The official examination timetable for the upcoming Fall Semester is now published...",
        "received_at": "3 days ago",
        "has_attachments": False,
        "is_unread": False,
        "body": "Dear Students, The final examination schedule has been officially released on the university student portal. Please review your exam hall allocations and timetable as usual. Best regards, Office of the Registrar.",
        "attachments": [],
        "raw_headers": "From: \"University Registrar\" <registrar@university.edu>\nReturn-Path: <registrar@university.edu>\nReceived-SPF: pass (domain of registrar@university.edu designates 192.0.2.1 as permitted sender)\nAuthentication-Results: mx.google.com; dkim=pass; dmarc=pass"
    }
}


class EmailIntegrationService:
    """
    Manages email inbox connections and message retrieval.
    """

    def __init__(self):
        self.gmail_configured = bool(os.getenv("GMAIL_CLIENT_ID") and os.getenv("GMAIL_CLIENT_SECRET"))
        self.outlook_configured = bool(os.getenv("OUTLOOK_CLIENT_ID") and os.getenv("OUTLOOK_CLIENT_SECRET"))

    def get_provider_status(self) -> Dict[str, Any]:
        """Returns the readiness status of all supported email providers."""
        gmail_status = gmail_service.get_connection_status()
        is_gmail_connected = gmail_status.get("connected", False)

        return {
            "simulated_inbox": {
                "name": "Simulated Threat Lab Inbox",
                "status": "connected",
                "is_ready": True,
                "description": "Preloaded with realistic attack vectors and safe university notices for testing and demonstration."
            },
            "gmail_oauth": {
                "name": "Google Workspace / Gmail",
                "status": "connected" if is_gmail_connected else ("configured" if self.gmail_configured else "ready_for_credentials"),
                "is_ready": is_gmail_connected,
                "connected_email": gmail_status.get("email"),
                "description": "Connects to Gmail API via OAuth2 to fetch selected user emails."
            },
            "outlook_oauth": {
                "name": "Microsoft 365 / Outlook",
                "status": "configured" if self.outlook_configured else "ready_for_credentials",
                "is_ready": self.outlook_configured,
                "description": "Connects to Microsoft Graph API to inspect user-selected emails."
            }
        }

    def list_inbox_messages(self, provider: str = "simulated") -> List[InboxEmailSummary]:
        """
        Retrieves top recent email summaries from the selected provider.
        Does NOT download full email bodies or attachments.
        """
        if provider == "simulated":
            summaries = []
            for msg in SIMULATED_INBOX_EMAILS.values():
                summaries.append(InboxEmailSummary(
                    id=msg["id"],
                    sender=msg["sender"],
                    subject=msg["subject"],
                    snippet=msg["snippet"],
                    received_at=msg["received_at"],
                    has_attachments=msg["has_attachments"],
                    is_unread=msg["is_unread"]
                ))
            return summaries

        if provider == "gmail":
            return gmail_service.list_inbox_messages()

        # For production Outlook or unsupported providers
        logger.info(f"Listing messages for unsupported provider '{provider}'...")
        return []

    def fetch_email_content(self, message_id: str, provider: str = "simulated") -> Optional[Dict[str, Any]]:
        """
        Fetches the FULL body, attachment metadata, and raw headers for ONE user-selected email.
        """
        if provider == "simulated":
            if message_id in SIMULATED_INBOX_EMAILS:
                return SIMULATED_INBOX_EMAILS[message_id]
            return None

        if provider == "gmail":
            return gmail_service.fetch_email_content(message_id)

        # Unsupported provider message retrieval
        logger.info(f"Fetching full message '{message_id}' from unsupported provider '{provider}'...")
        return None


# ═══════════════════════════════════════════════════════════════════
# Global Integration Service Instance
# ═══════════════════════════════════════════════════════════════════
email_service = EmailIntegrationService()