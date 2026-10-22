"""
Pydantic Schemas — Data Shapes for the API

Defines request/response data models for validation and OpenAPI docs.
Supports Email Threat Analysis, Standalone Scanners, Integrations, and Threat Investigation Dossiers.
"""

from pydantic import BaseModel, Field
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime


# ─────────────────────────────────────────────
# ATTACHMENT MODELS
# ─────────────────────────────────────────────

class AttachmentMetadata(BaseModel):
    filename: str = Field(..., description="Full filename with extension", example="invoice_2026.pdf.exe")
    file_size_bytes: Optional[int] = Field(None, description="Size in bytes", example=154200)
    content_type: Optional[str] = Field(None, description="MIME type if available", example="application/x-msdownload")


class AttachmentAnalysisDetail(BaseModel):
    filename: str
    detected_extension: str
    is_suspicious: bool
    risk_level: str
    threat_category: str
    reasons: List[str] = []
    score_contribution: int = 0


# ─────────────────────────────────────────────
# HEADER ANALYSIS MODELS
# ─────────────────────────────────────────────

class HopDetail(BaseModel):
    hop_number: int
    by_server: Optional[str] = None
    from_server: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: Optional[str] = None


class HeaderAnalysisDetail(BaseModel):
    from_header: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    spf_status: str = Field(default="neutral", description="pass / fail / softfail / neutral / none")
    dkim_status: str = Field(default="neutral", description="pass / fail / none")
    dmarc_status: str = Field(default="neutral", description="pass / fail / none")
    has_sender_mismatch: bool = False
    has_reply_to_mismatch: bool = False
    hops_count: int = 0
    hops: List[HopDetail] = []
    is_suspicious: bool = False
    risk_level: str = "low"
    reasons: List[str] = []
    score_contribution: int = 0


# ─────────────────────────────────────────────
# EMAIL ANALYSIS MODELS
# ─────────────────────────────────────────────

class IndicatorDetail(BaseModel):
    indicator: str
    description: str
    severity: str
    evidence: List[str] = []
    score_contribution: int


class URLAnalysisDetail(BaseModel):
    url: str
    is_suspicious: bool
    reasons: List[str] = []
    risk_level: str
    score_contribution: int = 0


class ScoreBreakdown(BaseModel):
    content_score: int
    sender_score: int
    url_score: int
    attachment_score: int = 0
    header_score: int = 0
    base_score: int
    compound_multiplier: float
    final_score: int
    applied_compound_rules: List[str] = []


class EmailAnalysisRequest(BaseModel):
    sender: str = Field(..., description="Sender's email address", example="security-alert@fakebank-example.com")
    subject: str = Field(..., description="Email subject line", example="URGENT! Verify your account immediately")
    body: str = Field(..., description="Email body text", example="Your account will be suspended today. Click here to verify.")
    attachments: Optional[List[AttachmentMetadata]] = Field(default=[], description="Attachment metadata")
    raw_headers: Optional[str] = Field(None, description="Optional raw RFC 822 email headers string")


class EmailAnalysisResponse(BaseModel):
    sender: str
    subject: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str
    verdict: str
    indicators: List[IndicatorDetail] = []
    urls_found: List[str] = []
    url_analysis: List[URLAnalysisDetail] = []
    attachments_found: List[str] = []
    attachment_analysis: List[AttachmentAnalysisDetail] = []
    header_analysis: Optional[HeaderAnalysisDetail] = None
    score_breakdown: Optional[ScoreBreakdown] = None
    ai_explanation: Optional[str] = None
    recommendations: List[str] = []
    analysis_id: Optional[str] = None
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)


# ─────────────────────────────────────────────
# STANDALONE SCANNER SCHEMAS
# ─────────────────────────────────────────────

class URLScanRequest(BaseModel):
    url: str = Field(..., description="The URL to scan statically", example="http://paypal-security-verification.xyz/login?user=auth")


class URLScanResponse(BaseModel):
    url: str
    is_suspicious: bool
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str
    verdict: str
    reasons: List[str]
    details: URLAnalysisDetail
    scanned_at: datetime = Field(default_factory=datetime.utcnow)


class AttachmentScanRequest(BaseModel):
    filename: str = Field(..., description="Filename to scan", example="urgent_payroll_update.docm")
    file_size_bytes: Optional[int] = Field(None, example=85400)
    content_type: Optional[str] = Field(None, example="application/vnd.ms-word.document.macroEnabled.12")


class AttachmentScanResponse(BaseModel):
    filename: str
    is_suspicious: bool
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str
    verdict: str
    threat_category: str
    reasons: List[str]
    details: AttachmentAnalysisDetail
    scanned_at: datetime = Field(default_factory=datetime.utcnow)


class HeaderScanRequest(BaseModel):
    raw_headers: str = Field(..., description="Raw RFC 822 email header text")


class HeaderScanResponse(BaseModel):
    is_suspicious: bool
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str
    verdict: str
    spf_status: str
    dkim_status: str
    dmarc_status: str
    sender_alignment: Dict[str, Any]
    reasons: List[str]
    details: HeaderAnalysisDetail
    scanned_at: datetime = Field(default_factory=datetime.utcnow)


# ─────────────────────────────────────────────
# EMAIL INBOX INTEGRATION SCHEMAS
# ─────────────────────────────────────────────

class InboxEmailSummary(BaseModel):
    id: str = Field(..., description="Unique message ID")
    sender: str
    subject: str
    snippet: str
    received_at: str
    has_attachments: bool = False
    is_unread: bool = True


class InboxListResponse(BaseModel):
    provider: str
    total_messages: int
    messages: List[InboxEmailSummary]


class AnalyzeSelectedEmailRequest(BaseModel):
    message_id: str = Field(..., description="Message ID to analyze", example="sim_msg_001")
    provider: str = Field(default="simulated", description="'simulated', 'gmail', or 'outlook'")


# ─────────────────────────────────────────────
# THREAT INVESTIGATION SCHEMAS (Milestone 11)
# ─────────────────────────────────────────────

class RemediationStep(BaseModel):
    """Actionable step for incident response."""
    step_number: int
    category: str = Field(..., description="e.g. Network, Identity, Endpoint, Email")
    action: str = Field(..., description="Specific containment command or procedure")
    priority: str = Field(..., description="Immediate / High / Recommended")


class ForensicArtifactSummary(BaseModel):
    """Grouped security artifacts discovered during investigation."""
    sender_identity: Dict[str, Any]
    extracted_urls: List[Dict[str, Any]]
    attached_files: List[Dict[str, Any]]
    authentication_status: Dict[str, Any]


class ThreatInvestigationDossier(BaseModel):
    """Complete Security Operations Center (SOC) investigation report."""
    investigation_id: str
    incident_timestamp: datetime
    subject: str
    sender: str
    overall_threat_level: str
    risk_score: int
    executive_summary: str
    attack_chain_breakdown: Dict[str, int]
    evidence_matrix: List[Dict[str, Any]]
    forensic_artifacts: ForensicArtifactSummary
    compound_risk_amplifiers: List[str]
    remediation_playbook: List[RemediationStep]
    correlated_threats: Optional["IncidentCorrelationReport"] = None


# ─────────────────────────────────────────────
# THREAT CORRELATION & CAMPAIGN SCHEMAS (Milestone 12)
# ─────────────────────────────────────────────

class CorrelatedIncidentSummary(BaseModel):
    """Details of a single historically correlated incident."""
    analysis_id: str
    incident_timestamp: Optional[datetime] = None
    sender: str
    subject: str
    risk_score: int
    risk_level: str
    verdict: str
    correlation_score: int = Field(..., ge=0, le=100, description="Percentage confidence of correlation")
    confidence_tier: str = Field(..., description="High / Medium / Low")
    matched_fields: List[str] = Field(default=[], description="Specific fields that correlated")
    shared_indicators: List[str] = Field(default=[], description="Common threat indicators/TTPs")
    shared_domains: List[str] = Field(default=[], description="Common domains or hostnames")
    shared_attachments: List[str] = Field(default=[], description="Common attachment files or types")
    reasoning: str = Field(..., description="Defensive rationale explaining the correlation finding")


class IncidentCorrelationReport(BaseModel):
    """Comprehensive correlation report connecting a target incident to historical events."""
    primary_analysis_id: str
    total_records_searched: int
    correlated_incident_count: int
    highest_confidence: str = "None"
    correlated_incidents: List[CorrelatedIncidentSummary] = []
    campaign_identified: bool = False
    campaign_name: Optional[str] = None
    campaign_summary: Optional[str] = None
    suggested_action: str = ""


class CampaignCluster(BaseModel):
    """Group of 2 or more security incidents tied to the same coordinated threat campaign."""
    campaign_id: str
    campaign_name: str
    confidence_level: str = "Medium"
    earliest_seen: Optional[datetime] = None
    latest_seen: Optional[datetime] = None
    incident_count: int
    incident_ids: List[str]
    common_senders: List[str] = []
    common_domains: List[str] = []
    common_threat_indicators: List[str] = []
    common_attack_types: List[str] = []
    average_risk_score: float
    summary: str


class CampaignDetectionResponse(BaseModel):
    """Response containing all detected threat campaigns across stored historical incidents."""
    total_incidents_analyzed: int
    total_campaigns_detected: int
    campaigns: List[CampaignCluster] = []
    isolated_incidents_count: int


# Rebuild ThreatInvestigationDossier to resolve forward reference
ThreatInvestigationDossier.model_rebuild()

# ─────────────────────────────────────────────
# AUTONOMOUS REMEDIATION SCHEMAS (Milestone 13)
# ─────────────────────────────────────────────

class RemediationActionType(str, Enum):
    """Categories of autonomous remediation actions the platform can execute."""
    EMAIL_QUARANTINE = "email_quarantine"
    NETWORK_DOMAIN_BLOCK = "network_domain_block"
    NETWORK_IP_BLOCK = "network_ip_block"
    IAM_SESSION_REVOCATION = "iam_session_revocation"
    ENDPOINT_ISOLATION_FLAG = "endpoint_isolation_flag"
    IOC_EXPORT = "ioc_export"


class RemediationActionItem(BaseModel):
    """A single autonomous remediation action executed by the platform."""
    action_id: str
    action_type: str = Field(..., description="Type of remediation action taken")
    target: str = Field(..., description="Target of the action, e.g. domain:paypal-update.xyz")
    parameters: Dict[str, Any] = {}
    status: str = Field(default="pending", description="pending / executed / simulated / failed")
    priority: str = Field(default="Immediate", description="Immediate / High / Medium")
    details: str = Field(..., description="Human-readable explanation of what this action does")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class RemediationExecutionRequest(BaseModel):
    """Request body for triggering autonomous remediation on a live email."""
    sender: str = Field(..., description="Sender email address", example="attacker@malicious-site.xyz")
    subject: str = Field(..., description="Email subject line", example="URGENT: Verify your account")
    body: str = Field(..., description="Email body text", example="Click here to verify immediately")
    attachments: Optional[List[AttachmentMetadata]] = Field(default=[], description="Attachment metadata")
    raw_headers: Optional[str] = Field(None, description="Optional raw RFC 822 email headers")
    dry_run: bool = Field(default=False, description="If True, simulate actions without executing")


class RemediationExecutionResult(BaseModel):
    """Complete audit record of an autonomous remediation execution."""
    remediation_id: str
    analysis_id: str
    threat_level: str
    risk_score: int
    is_dry_run: bool
    actions_attempted: int
    actions_successful: int
    actions_failed: int = 0
    executed_actions: List[RemediationActionItem] = []
    rollback_available: bool = False
    status: str = Field(..., description="completed / partial_failure / simulated / no_action_needed")
    summary: str
    executed_at: datetime = Field(default_factory=datetime.utcnow)


class RemediationAuditLogResponse(BaseModel):
    """Paginated list of past remediation actions for audit review."""
    total_records: int
    records: List[Dict[str, Any]] = []
    # ─────────────────────────────────────────────
# VERIFICATION & RISK REASSESSMENT SCHEMAS (Milestone 14)
# ─────────────────────────────────────────────

class ActionVerificationStatus(BaseModel):
    """Result of verifying an individual remediation action."""
    action_id: str
    action_type: str
    target: str
    is_verified: bool
    verification_check: str  # e.g., "mailbox_absence_check", "dns_sinkhole_probe"
    details: str
    verified_at: datetime = Field(default_factory=datetime.utcnow)


class RiskReassessmentReport(BaseModel):
    """Complete post-remediation verification and residual risk report."""
    verification_id: str
    remediation_id: str
    analysis_id: str
    containment_status: str = Field(..., description="FULLY_CONTAINED / PARTIALLY_CONTAINED / CONTAINMENT_FAILED")
    initial_risk_score: int
    initial_threat_level: str
    residual_risk_score: int
    residual_threat_level: str
    risk_reduction_percentage: float
    total_actions_checked: int
    actions_verified: int
    actions_failed_verification: int
    verification_details: List[ActionVerificationStatus] = []
    residual_risk_summary: str
    next_recommended_steps: List[str] = []
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class VerificationRequest(BaseModel):
    """Request body to verify an executed remediation record."""
    remediation_id: Optional[str] = None
    remediation_result: Optional[RemediationExecutionResult] = None
    # ─────────────────────────────────────────────
# NOTIFICATION & INCIDENT REPORTING SCHEMAS (Milestone 15)
# ─────────────────────────────────────────────

class NotificationRecipientType(str, Enum):
    USER = "user"          # Affected employee/recipient
    ADMIN = "admin"        # SOC Team / Security Administrator
    ALL = "all"            # Both user and admin broadcast


class SecurityNotificationItem(BaseModel):
    """An individual security alert notification record."""
    notification_id: str
    recipient_type: str = Field(..., description="user / admin")
    recipient: str = Field(..., description="Target email or role, e.g. victim@company.com or soc-team")
    subject: str = Field(..., description="Notification headline")
    message: str = Field(..., description="Full message content explaining the action taken")
    threat_level: str
    initial_risk_score: int
    residual_risk_score: int
    containment_status: str
    actions_summary: List[str] = []
    is_read: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)


class IncidentNotificationDispatch(BaseModel):
    """Result of dispatching incident notifications across all channels."""
    dispatch_id: str
    incident_id: str
    user_notification: Optional[SecurityNotificationItem] = None
    admin_notification: Optional[SecurityNotificationItem] = None
    channels_delivered: List[str] = []  # e.g. ["in_app_banner", "email_dispatch", "soc_webhook"]
    dispatched_at: datetime = Field(default_factory=datetime.utcnow)


class NotificationListResponse(BaseModel):
    """List of all generated in-app security notifications."""
    total_notifications: int
    unread_count: int
    notifications: List[SecurityNotificationItem] = []
    # ─────────────────────────────────────────────
# CONTINUOUS MONITORING SCHEMAS (Milestone 16)
# ─────────────────────────────────────────────

class MonitoringEvent(BaseModel):
    """A log event generated by the continuous monitoring worker."""
    event_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str = Field(..., description="cycle_start, threat_neutralized, safe_email, cycle_complete, error")
    message: str
    details: Dict[str, Any] = {}


class MonitoringStatus(BaseModel):
    """Current live operational status of the monitoring engine."""
    is_running: bool
    status: str = Field(..., description="running, idle, stopped")
    poll_interval_seconds: int
    total_cycles_completed: int
    total_emails_scanned: int
    threats_detected: int
    remediations_triggered: int
    notifications_dispatched: int
    last_poll_time: Optional[datetime] = None
    active_provider: str
    recent_events: List[MonitoringEvent] = []


class MonitoringCycleResult(BaseModel):
    """Detailed summary of a single monitoring evaluation cycle."""
    cycle_id: str
    started_at: datetime
    completed_at: datetime
    emails_evaluated: int
    new_threats_found: int
    remediations_executed: int
    details: List[Dict[str, Any]] = []


class MonitoringStartRequest(BaseModel):
    """Parameters to launch or reconfigure the continuous monitoring worker."""
    poll_interval_seconds: int = Field(default=15, ge=2, le=3600, description="Interval between inbox polling loops")
    auto_remediate: bool = Field(default=True, description="Automatically trigger M13/M14/M15 when threats are found")
    provider: str = Field(default="simulated", description="Email provider: simulated, gmail, or outlook")

# ─────────────────────────────────────────────
# TRAINING & QUIZ SCHEMAS (Milestone 17)
# ─────────────────────────────────────────────

class TrainingModuleSummary(BaseModel):
    """Summary of a cybersecurity awareness training topic."""
    module_id: str
    title: str
    category: str
    difficulty: str
    estimated_minutes: int
    description: str
    icon: str


class TrainingModuleDetail(BaseModel):
    """Full educational content for a specific training module."""
    module_id: str
    title: str
    category: str
    difficulty: str
    estimated_minutes: int
    description: str
    attack_mechanism: str
    real_world_example: str
    red_flag_indicators: List[str]
    defense_checklist: List[str]


class QuizQuestionOption(BaseModel):
    """Selectable answer choice for a quiz scenario."""
    option_id: str  # e.g., "phishing" or "legitimate"
    text: str


class QuizQuestionPublic(BaseModel):
    """Quiz question presented to the user (answer withheld for security)."""
    question_id: str
    title: str
    category: str
    difficulty: str
    scenario_sender: str
    scenario_subject: str
    scenario_body: str
    has_attachment: bool = False
    attachment_name: Optional[str] = None
    options: List[QuizQuestionOption]


class QuizSubmissionAnswer(BaseModel):
    """User response to a single quiz question."""
    question_id: str
    selected_option_id: str


class QuizSubmissionRequest(BaseModel):
    """Complete quiz submission payload."""
    user_identifier: Optional[str] = "student@university.edu"
    answers: List[QuizSubmissionAnswer]


class QuestionReviewDetail(BaseModel):
    """Detailed post-quiz review for a single question."""
    question_id: str
    title: str
    user_answer: str
    correct_answer: str
    is_correct: bool
    explanation: str
    red_flags: List[str] = []


class QuizResultResponse(BaseModel):
    """Graded quiz result and security awareness report."""
    submission_id: str
    total_questions: int
    correct_count: int
    score_percentage: float
    performance_rating: str
    summary: str
    recommendations: List[str]
    question_reviews: List[QuestionReviewDetail]
    submitted_at: datetime = Field(default_factory=datetime.utcnow)
# ─────────────────────────────────────────────
# GENERIC RESPONSE MODELS
# ─────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    message: str
    version: str
    environment: str
    database_connected: bool