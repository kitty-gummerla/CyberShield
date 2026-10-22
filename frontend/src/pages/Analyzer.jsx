import React, { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
    Search,
    Mail,
    Inbox,
    ShieldAlert,
    ShieldCheck,
    AlertTriangle,
    CheckCircle2,
    CheckCircle,
    Sparkles,
    Link2,
    Paperclip,
    FileCode,
    RotateCcw,
    Send,
    Info,
    ChevronDown,
    ChevronUp,
    Clock,
    ArrowRight,
    Plug,
    Lock,
    LogOut,
    FlaskConical,
    ExternalLink,
    RefreshCw,
    Terminal,
    FileText,
    Layers
} from 'lucide-react';
import { 
    getInboxMessages, 
    analyzeSelectedEmail, 
    analyzeEmail,
    getGmailStatus,
    disconnectGmail,
    GMAIL_CONNECT_URL
} from '../services/api';

// ─── Sample scenarios for Manual Input tab ──────────────────────────────────
const SAMPLE_SCENARIOS = [
    {
        name: "PayPal Credential Phishing",
        badge: "Credential Harvest",
        sender: "security-alert@paypal-update.xyz",
        subject: "URGENT: Unauthorized Account Access Detected",
        body: "Dear Customer, We detected an unauthorized login attempt from IP 185.220.101.5. Your account has been temporarily restricted. Click the secure verification portal below and confirm your password and 6-digit OTP immediately: http://paypal-verification.fake-security.xyz/login?user=auth",
        raw_headers: "From: \"PayPal Security Team\" <security-alert@paypal.com>\nReturn-Path: <bounce@attacker-vps.xyz>\nReceived-SPF: fail (ip 185.220.101.5 is not authorized)\nAuthentication-Results: mx.google.com; dkim=fail; dmarc=fail (p=REJECT)",
        attachments: []
    },
    {
        name: "Macro Malware Attachment",
        badge: "Weaponized File",
        sender: "payroll-update@company-services.com",
        subject: "Q3 Salary Adjustment & Bonus Calculation",
        body: "Hello Team, Please review the attached corporate spreadsheet regarding updated Q3 salary structures and bonus incentives. Enable macros when prompted to generate your personalized tax projection.",
        raw_headers: "From: \"Corporate HR\" <payroll-update@company-services.com>\nReceived-SPF: softfail",
        attachments: [
            {
                filename: "Q3_Salary_Breakdown.xlsm",
                file_size_bytes: 84500,
                content_type: "application/vnd.ms-excel.sheet.macroEnabled.12"
            }
        ]
    },
    {
        name: "Legitimate University Notice",
        badge: "Verified Safe",
        sender: "registrar@university.edu",
        subject: "Fall Semester Final Examination Schedule",
        body: "Dear Students, The final examination schedule has been officially released on the university student portal. Please review your exam hall allocations and timetable as usual. Best regards, Office of the Registrar.",
        raw_headers: "From: \"University Registrar\" <registrar@university.edu>\nReceived-SPF: pass\nAuthentication-Results: mx.google.com; dkim=pass; dmarc=pass",
        attachments: []
    }
];

// ─── Provider config — future OAuth providers listed here ───────────────────
const OAUTH_PROVIDERS = [
    {
        id: "gmail",
        label: "Gmail",
        icon: "G",
        color: "from-red-500/20 to-orange-500/20",
        border: "border-red-500/30",
        status: "not_configured",
        note: "Requires Google Cloud OAuth App registration."
    },
    {
        id: "outlook",
        label: "Outlook / Microsoft 365",
        icon: "O",
        color: "from-blue-500/20 to-indigo-500/20",
        border: "border-blue-500/30",
        status: "not_configured",
        note: "Requires Microsoft Azure App registration."
    }
];

// ─── Helper: guess risk hint from inbox email metadata ──────────────────────
function getRiskHint(email) {
    const snippet = (email.snippet || "").toLowerCase();
    const subject = (email.subject || "").toLowerCase();
    const combined = snippet + " " + subject;
    if (email.has_attachments) return { label: "Attachment", color: "text-amber-400 border-amber-800 bg-amber-950/40" };
    if (/urgent|password|verify|otp|suspend|unauthorized/.test(combined))
        return { label: "Suspicious", color: "text-rose-400 border-rose-800 bg-rose-950/40" };
    return null;
}

// ─── Main Component ──────────────────────────────────────────────────────────
export default function Analyzer() {
    const [searchParams, setSearchParams] = useSearchParams();
    const [activeTab, setActiveTab] = useState("inbox"); // "inbox" | "manual"
    const [inboxView, setInboxView] = useState("demo");  // "demo" | "gmail" | "connect"

    // Gmail Connection State
    const [gmailAccount, setGmailAccount] = useState({ connected: false, email: null });
    const [authNotification, setAuthNotification] = useState(null); // { type: 'success' | 'error', message: string }

    // Inbox State
    const [inboxEmails, setInboxEmails] = useState([]);
    const [inboxLoading, setInboxLoading] = useState(false);
    const [selectedMsgId, setSelectedMsgId] = useState(null);

    // Manual Form State
    const [sender, setSender] = useState("");
    const [subject, setSubject] = useState("");
    const [body, setBody] = useState("");
    const [rawHeaders, setRawHeaders] = useState("");
    const [attachments, setAttachments] = useState([]);
    const [showAdvanced, setShowAdvanced] = useState(false);

    // Analysis State
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    // Check OAuth status & query params on mount
    useEffect(() => {
        const checkStatus = async () => {
            try {
                const status = await getGmailStatus();
                setGmailAccount(status);

                const gmailParam = searchParams.get("gmail");
                if (gmailParam === "connected") {
                    setAuthNotification({
                        type: "success",
                        message: `Connected to Gmail account: ${status.email || ""}`
                    });
                    setInboxView("gmail");
                    fetchInbox("gmail");
                    setSearchParams({}, { replace: true });
                    return;
                } else if (gmailParam === "error") {
                    setAuthNotification({
                        type: "error",
                        message: "Gmail authentication was cancelled or encountered an error."
                    });
                    setSearchParams({}, { replace: true });
                }

                if (status.connected) {
                    setInboxView("gmail");
                }
                fetchInbox(status.connected ? "gmail" : "simulated");
            } catch (err) {
                fetchInbox("simulated");
            }
        };
        checkStatus();
    }, []);

    const fetchInbox = async (providerOverride) => {
        const provider = providerOverride || (inboxView === "gmail" ? "gmail" : "simulated");
        setInboxLoading(true);
        try {
            const data = await getInboxMessages(provider);
            setInboxEmails(data.messages || []);
        } catch (err) {
            console.error("Failed to load inbox:", err);
        } finally {
            setInboxLoading(false);
        }
    };

    const handleInspectInboxEmail = async (msgId) => {
        setSelectedMsgId(msgId);
        setLoading(true);
        setError(null);
        try {
            const provider = inboxView === "gmail" ? "gmail" : "simulated";
            const res = await analyzeSelectedEmail(msgId, provider);
            setResult(res);
        } catch (err) {
            setError(err.response?.data?.detail || err.message || "Failed to analyze selected inbox email.");
        } finally {
            setLoading(false);
        }
    };

    const handleDisconnectGmail = async () => {
        try {
            await disconnectGmail();
            setGmailAccount({ connected: false, email: null });
            setInboxView("demo");
            fetchInbox("simulated");
            setAuthNotification({
                type: "success",
                message: "Disconnected from Gmail. Reverted to Demo Inbox."
            });
        } catch (err) {
            setError("Failed to disconnect Gmail session.");
        }
    };

    const loadScenario = (s) => {
        setSender(s.sender);
        setSubject(s.subject);
        setBody(s.body);
        setRawHeaders(s.raw_headers || "");
        setAttachments(s.attachments || []);
        setResult(null);
        setError(null);
        if (s.raw_headers || (s.attachments && s.attachments.length > 0)) {
            setShowAdvanced(true);
        }
    };

    const handleResetManual = () => {
        setSender("");
        setSubject("");
        setBody("");
        setRawHeaders("");
        setAttachments([]);
        setResult(null);
        setError(null);
    };

    const handleManualSubmit = async (e) => {
        e.preventDefault();
        if (!sender.trim() || !body.trim()) {
            setError("Please provide at least a sender email and body.");
            return;
        }
        setLoading(true);
        setError(null);
        try {
            const payload = {
                sender: sender.trim(),
                subject: subject.trim(),
                body: body.trim(),
                raw_headers: rawHeaders.trim() || null,
                attachments: attachments
            };
            const res = await analyzeEmail(payload);
            setResult(res);
        } catch (err) {
            setError(err.response?.data?.detail || err.message || "Analysis request failed.");
        } finally {
            setLoading(false);
        }
    };

    const getScoreColor = (score) => {
        if (score >= 80) return "text-rose-500 border-rose-500/30 bg-rose-950/20";
        if (score >= 60) return "text-orange-400 border-orange-500/30 bg-orange-950/20";
        if (score >= 30) return "text-amber-400 border-amber-500/30 bg-amber-950/20";
        return "text-emerald-400 border-emerald-500/30 bg-emerald-950/20";
    };

    return (
        <div className="space-y-6">

            {/* ── Page Headline ── */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                    <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2.5">
                        <Search className="h-7 w-7 text-cyan-400" />
                        Email Threat Analyzer
                    </h1>
                    <p className="text-xs sm:text-sm text-slate-400 mt-1">
                        Inspect inbox emails or submit custom payloads for multi-vector threat scoring.
                    </p>
                </div>

                {/* Tab Switcher */}
                <div className="flex items-center p-1 rounded-xl bg-slate-900 border border-slate-800 self-start">
                    <button
                        type="button"
                        onClick={() => setActiveTab("inbox")}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${activeTab === "inbox"
                            ? "bg-cyan-500 text-slate-950 shadow-sm"
                            : "text-slate-400 hover:text-white"
                            }`}
                    >
                        <Inbox className="h-4 w-4" />
                        <span>Mailbox ({inboxEmails.length})</span>
                    </button>
                    <button
                        type="button"
                        onClick={() => setActiveTab("manual")}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${activeTab === "manual"
                            ? "bg-cyan-500 text-slate-950 shadow-sm"
                            : "text-slate-400 hover:text-white"
                            }`}
                    >
                        <Mail className="h-4 w-4" />
                        <span>Manual Input</span>
                    </button>
                </div>
            </div>

            {/* ── Auth Notification Banner ── */}
            {authNotification && (
                <div className={`rounded-xl p-3.5 text-xs flex items-center justify-between gap-3 border ${
                    authNotification.type === "success"
                        ? "bg-emerald-950/40 border-emerald-800/50 text-emerald-300"
                        : "bg-rose-950/40 border-rose-800/50 text-rose-300"
                }`}>
                    <div className="flex items-center gap-2">
                        {authNotification.type === "success" ? (
                            <CheckCircle className="h-4 w-4 text-emerald-400 flex-shrink-0" />
                        ) : (
                            <AlertTriangle className="h-4 w-4 text-rose-400 flex-shrink-0" />
                        )}
                        <span>{authNotification.message}</span>
                    </div>
                    <button
                        type="button"
                        onClick={() => setAuthNotification(null)}
                        className="text-xs font-mono opacity-70 hover:opacity-100 px-2 py-0.5"
                    >
                        Dismiss
                    </button>
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

                {/* ── Left Column: Email Source ── */}
                <div className="lg:col-span-6 space-y-4">

                    {/* ═══ TAB 1: MAILBOX ═══ */}
                    {activeTab === "inbox" && (
                        <div className="space-y-3">

                            {/* Sub-tab switcher: Demo Inbox | Gmail Inbox / Connect Real Mailbox */}
                            <div className="flex items-center p-1 rounded-lg bg-slate-900/80 border border-slate-800 w-full">
                                <button
                                    type="button"
                                    onClick={() => {
                                        setInboxView("demo");
                                        fetchInbox("simulated");
                                    }}
                                    className={`flex items-center gap-1.5 flex-1 justify-center px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${inboxView === "demo"
                                        ? "bg-slate-700 text-white"
                                        : "text-slate-500 hover:text-slate-300"
                                        }`}
                                >
                                    <FlaskConical className="h-3.5 w-3.5 text-cyan-400" />
                                    Demo Inbox (Simulated)
                                </button>
                                <button
                                    type="button"
                                    onClick={() => {
                                        if (gmailAccount.connected) {
                                            setInboxView("gmail");
                                            fetchInbox("gmail");
                                        } else {
                                            setInboxView("connect");
                                        }
                                    }}
                                    className={`flex items-center gap-1.5 flex-1 justify-center px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${inboxView === "gmail" || inboxView === "connect"
                                        ? "bg-slate-700 text-white"
                                        : "text-slate-500 hover:text-slate-300"
                                        }`}
                                >
                                    <Plug className={`h-3.5 w-3.5 ${gmailAccount.connected ? "text-emerald-400" : "text-slate-400"}`} />
                                    {gmailAccount.connected ? `Gmail (${gmailAccount.email})` : "Connect Real Mailbox"}
                                </button>
                            </div>

                            {/* ── DEMO INBOX VIEW ── */}
                            {inboxView === "demo" && (
                                <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">

                                    {/* Header row */}
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <h3 className="text-sm font-bold text-white flex items-center gap-2">
                                                <FlaskConical className="h-4 w-4 text-cyan-400" />
                                                Simulated Lab Inbox
                                            </h3>
                                            <p className="text-[11px] text-slate-400 mt-0.5">
                                                4 pre-loaded threat scenarios. Click any message to run a full threat inspection.
                                            </p>
                                        </div>
                                        <button
                                            onClick={() => fetchInbox("simulated")}
                                            disabled={inboxLoading}
                                            className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono disabled:opacity-50"
                                        >
                                            <RefreshCw className={`h-3 w-3 ${inboxLoading ? "animate-spin" : ""}`} />
                                            {inboxLoading ? "Loading..." : "Refresh"}
                                        </button>
                                    </div>

                                    {/* Demo badge */}
                                    <div className="flex items-center gap-2 text-[11px] font-mono px-3 py-2 rounded-lg bg-cyan-950/30 border border-cyan-800/40 text-cyan-300">
                                        <Lock className="h-3.5 w-3.5 flex-shrink-0" />
                                        <span>These are controlled lab emails — no real mailbox is accessed. Safe to analyze.</span>
                                    </div>

                                    {/* Email list */}
                                    {inboxEmails.length === 0 && !inboxLoading && (
                                        <div className="text-center py-10 text-xs text-slate-500">
                                            No emails loaded. Backend may be offline.
                                        </div>
                                    )}

                                    <div className="space-y-2.5">
                                        {inboxEmails.map((email) => {
                                            const isSelected = selectedMsgId === email.id;
                                            const hint = getRiskHint(email);
                                            return (
                                                <div
                                                    key={email.id}
                                                    onClick={() => handleInspectInboxEmail(email.id)}
                                                    className={`cursor-pointer p-3.5 rounded-xl border transition-all text-left group ${isSelected
                                                        ? "border-cyan-500 bg-cyan-950/20 shadow-sm shadow-cyan-950"
                                                        : "border-slate-800 bg-slate-950 hover:border-slate-700 hover:bg-slate-900"
                                                        }`}
                                                >
                                                    <div className="flex items-start justify-between gap-2">
                                                        <div className="space-y-0.5 flex-1 min-w-0">
                                                            <div className="flex items-center gap-2">
                                                                <span className="text-xs font-semibold text-white truncate">
                                                                    {email.sender}
                                                                </span>
                                                                {email.is_unread && (
                                                                    <span className="text-[9px] font-mono px-1.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 uppercase">
                                                                        Unread
                                                                    </span>
                                                                )}
                                                            </div>
                                                            <h4 className="text-xs font-medium text-slate-200 truncate">
                                                                {email.subject}
                                                            </h4>
                                                            <p className="text-[11px] text-slate-400 line-clamp-1">
                                                                {email.snippet}
                                                            </p>
                                                        </div>

                                                        <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
                                                            <span className="text-[10px] text-slate-500 font-mono flex items-center gap-1">
                                                                <Clock className="h-3 w-3" />
                                                                {email.received_at}
                                                            </span>
                                                            {hint && (
                                                                <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${hint.color}`}>
                                                                    {hint.label}
                                                                </span>
                                                            )}
                                                        </div>
                                                    </div>

                                                    <div className="mt-3 pt-2.5 border-t border-slate-900 flex items-center justify-between text-[11px]">
                                                        <span className="text-slate-600 font-mono text-[10px]">
                                                            {email.id}
                                                        </span>
                                                        <span className="text-cyan-400 font-semibold group-hover:translate-x-0.5 transition-transform flex items-center gap-1">
                                                            <span>Inspect Threat</span>
                                                            <ArrowRight className="h-3 w-3" />
                                                        </span>
                                                    </div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>
                            )}

                            {/* ── LIVE GMAIL INBOX VIEW ── */}
                            {inboxView === "gmail" && (
                                <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
                                    {/* Header row */}
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <h3 className="text-sm font-bold text-white flex items-center gap-2">
                                                <Plug className="h-4 w-4 text-emerald-400" />
                                                Live Gmail Inbox
                                            </h3>
                                            <p className="text-[11px] text-slate-400 mt-0.5">
                                                Connected: <span className="text-cyan-300 font-mono">{gmailAccount.email}</span>. Click any message to analyze.
                                            </p>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <button
                                                onClick={() => fetchInbox("gmail")}
                                                disabled={inboxLoading}
                                                className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono disabled:opacity-50"
                                            >
                                                <RefreshCw className={`h-3 w-3 ${inboxLoading ? "animate-spin" : ""}`} />
                                                {inboxLoading ? "Loading..." : "Refresh"}
                                            </button>
                                            <button
                                                type="button"
                                                onClick={handleDisconnectGmail}
                                                className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border border-rose-900/60 bg-rose-950/40 hover:bg-rose-900/40 text-rose-300 font-mono"
                                                title="Disconnect Gmail session"
                                            >
                                                <LogOut className="h-3 w-3" />
                                                Disconnect
                                            </button>
                                        </div>
                                    </div>

                                    {/* Live OAuth Badge */}
                                    <div className="flex items-center gap-2 text-[11px] font-mono px-3 py-2 rounded-lg bg-emerald-950/30 border border-emerald-800/40 text-emerald-300">
                                        <Lock className="h-3.5 w-3.5 flex-shrink-0" />
                                        <span>Read-only metadata mode. Email bodies and attachments are fetched only when you explicitly select a message.</span>
                                    </div>

                                    {/* Email list */}
                                    {inboxEmails.length === 0 && !inboxLoading && (
                                        <div className="text-center py-10 text-xs text-slate-500">
                                            No emails found in INBOX or session expired. Click Refresh to reload.
                                        </div>
                                    )}

                                    <div className="space-y-2.5">
                                        {inboxEmails.map((email) => {
                                            const isSelected = selectedMsgId === email.id;
                                            const hint = getRiskHint(email);
                                            return (
                                                <div
                                                    key={email.id}
                                                    onClick={() => handleInspectInboxEmail(email.id)}
                                                    className={`cursor-pointer p-3.5 rounded-xl border transition-all text-left group ${isSelected
                                                        ? "border-cyan-500 bg-cyan-950/20 shadow-sm shadow-cyan-950"
                                                        : "border-slate-800 bg-slate-950 hover:border-slate-700 hover:bg-slate-900"
                                                        }`}
                                                >
                                                    <div className="flex items-start justify-between gap-2">
                                                        <div className="space-y-0.5 flex-1 min-w-0">
                                                            <div className="flex items-center gap-2">
                                                                <span className="text-xs font-semibold text-white truncate">
                                                                    {email.sender}
                                                                </span>
                                                                {email.is_unread && (
                                                                    <span className="text-[9px] font-mono px-1.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 uppercase">
                                                                        Unread
                                                                    </span>
                                                                )}
                                                            </div>
                                                            <h4 className="text-xs font-medium text-slate-200 truncate">
                                                                {email.subject}
                                                            </h4>
                                                            <p className="text-[11px] text-slate-400 line-clamp-1">
                                                                {email.snippet}
                                                            </p>
                                                        </div>

                                                        <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
                                                            <span className="text-[10px] text-slate-500 font-mono flex items-center gap-1">
                                                                <Clock className="h-3 w-3" />
                                                                {email.received_at}
                                                            </span>
                                                            {hint && (
                                                                <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${hint.color}`}>
                                                                    {hint.label}
                                                                </span>
                                                            )}
                                                        </div>
                                                    </div>

                                                    <div className="mt-3 pt-2.5 border-t border-slate-900 flex items-center justify-between text-[11px]">
                                                        <span className="text-slate-600 font-mono text-[10px]">
                                                            {email.id}
                                                        </span>
                                                        <span className="text-cyan-400 font-semibold group-hover:translate-x-0.5 transition-transform flex items-center gap-1">
                                                            <span>Inspect Threat</span>
                                                            <ArrowRight className="h-3 w-3" />
                                                        </span>
                                                    </div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>
                            )}

                            {/* ── CONNECT REAL MAILBOX VIEW ── */}
                            {inboxView === "connect" && (
                                <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-5">
                                    <div>
                                        <h3 className="text-sm font-bold text-white flex items-center gap-2">
                                            <Plug className="h-4 w-4 text-emerald-400" />
                                            Connect a Real Email Mailbox
                                        </h3>
                                        <p className="text-[11px] text-slate-400 mt-1">
                                            Use OAuth to authorize CyberShield to read your inbox metadata.
                                            We only fetch message subjects and senders — never store your emails permanently.
                                        </p>
                                    </div>

                                    {/* How OAuth works — simple flow */}
                                    <div className="rounded-lg bg-slate-950 border border-slate-800 p-3.5 space-y-2">
                                        <p className="text-[11px] font-mono text-slate-300 font-semibold uppercase tracking-wider">
                                            How It Works
                                        </p>
                                        <div className="flex items-center gap-2 text-[11px] text-slate-400">
                                            <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 flex items-center justify-center font-mono font-bold text-[10px] flex-shrink-0">1</span>
                                            Click "Connect" → redirects to your email provider's OAuth login page
                                        </div>
                                        <div className="flex items-center gap-2 text-[11px] text-slate-400">
                                            <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 flex items-center justify-center font-mono font-bold text-[10px] flex-shrink-0">2</span>
                                            Authorize CyberShield to read-only access your mailbox metadata
                                        </div>
                                        <div className="flex items-center gap-2 text-[11px] text-slate-400">
                                            <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 flex items-center justify-center font-mono font-bold text-[10px] flex-shrink-0">3</span>
                                            CyberShield retrieves message list (subject, sender, date)
                                        </div>
                                        <div className="flex items-center gap-2 text-[11px] text-slate-400">
                                            <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 flex items-center justify-center font-mono font-bold text-[10px] flex-shrink-0">4</span>
                                            You click a specific message → only that message is fetched and analyzed
                                        </div>
                                    </div>

                                    {/* Provider Cards */}
                                    <div className="space-y-3">
                                        {OAUTH_PROVIDERS.map((provider) => (
                                            <div
                                                key={provider.id}
                                                className={`rounded-xl border ${provider.border} bg-gradient-to-br ${provider.color} p-4`}
                                            >
                                                <div className="flex items-center justify-between">
                                                    <div className="flex items-center gap-3">
                                                        <div className="w-9 h-9 rounded-xl bg-slate-900/80 border border-slate-700 flex items-center justify-center font-bold text-white text-sm">
                                                            {provider.icon}
                                                        </div>
                                                        <div>
                                                            <p className="text-sm font-bold text-white">{provider.label}</p>
                                                            <p className="text-[11px] text-slate-400">{provider.note}</p>
                                                        </div>
                                                    </div>

                                                    {provider.id === "gmail" ? (
                                                        <button
                                                            type="button"
                                                            onClick={() => { window.location.href = GMAIL_CONNECT_URL; }}
                                                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-sm transition-all cursor-pointer"
                                                        >
                                                            <Plug className="h-3.5 w-3.5" />
                                                            Connect Gmail
                                                        </button>
                                                    ) : (
                                                        <button
                                                            disabled
                                                            title="OAuth setup required — see note below"
                                                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-slate-500 text-xs font-semibold cursor-not-allowed"
                                                        >
                                                            <Lock className="h-3.5 w-3.5" />
                                                            Setup Required
                                                        </button>
                                                    )}
                                                </div>
                                            </div>
                                        ))}
                                    </div>

                                    {/* Setup instruction note */}
                                    <div className="rounded-lg bg-amber-950/20 border border-amber-800/40 p-3.5 space-y-2">
                                        <p className="text-xs font-semibold text-amber-300 flex items-center gap-1.5">
                                            <AlertTriangle className="h-4 w-4" />
                                            OAuth Setup Required for Real Mailbox
                                        </p>
                                        <p className="text-[11px] text-slate-400 leading-relaxed">
                                            To enable Gmail: register a Google Cloud OAuth 2.0 App, add
                                            <code className="text-cyan-300 font-mono mx-1">http://127.0.0.1:8000/auth/gmail/callback</code>
                                            as an authorized redirect URI, and set <code className="text-cyan-300 font-mono">GMAIL_CLIENT_ID</code> / <code className="text-cyan-300 font-mono">GMAIL_CLIENT_SECRET</code> in your backend <code className="text-cyan-300 font-mono">.env</code> file.
                                        </p>
                                        <p className="text-[11px] text-slate-400 leading-relaxed">
                                            To enable Outlook: register an Azure App, add
                                            <code className="text-cyan-300 font-mono mx-1">http://127.0.0.1:8000/auth/outlook/callback</code>
                                            as a redirect URI, and set <code className="text-cyan-300 font-mono">OUTLOOK_CLIENT_ID</code> / <code className="text-cyan-300 font-mono">OUTLOOK_CLIENT_SECRET</code> in <code className="text-cyan-300 font-mono">.env</code>.
                                        </p>
                                        <a
                                            href="https://console.cloud.google.com/apis/credentials"
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-mono"
                                        >
                                            <ExternalLink className="h-3 w-3" />
                                            Google Cloud Console →
                                        </a>
                                    </div>
                                </div>
                            )}

                        </div>
                    )}

                    {/* ═══ TAB 2: MANUAL SUBMISSION ═══ */}
                    {activeTab === "manual" && (
                        <div className="space-y-4">
                            {/* Quick Load Bar */}
                            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3.5">
                                <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5 font-mono">
                                    <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
                                    <span>Quick-Load Sample Templates:</span>
                                </div>
                                <div className="flex flex-wrap gap-2">
                                    {SAMPLE_SCENARIOS.map((s, idx) => (
                                        <button
                                            key={idx}
                                            type="button"
                                            onClick={() => loadScenario(s)}
                                            className="text-xs px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-cyan-500/10 hover:border-cyan-500/40 hover:text-cyan-300 text-slate-300 transition-all flex items-center gap-1.5"
                                        >
                                            <span className="font-medium">{s.name}</span>
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Form */}
                            <form onSubmit={handleManualSubmit} className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-3.5">
                                <div>
                                    <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1 font-mono">
                                        Sender Email *
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="e.g. security-alert@paypal-update.xyz"
                                        value={sender}
                                        onChange={(e) => setSender(e.target.value)}
                                        className="w-full text-xs font-mono px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                                        required
                                    />
                                </div>

                                <div>
                                    <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1 font-mono">
                                        Subject Line
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="e.g. URGENT: Account Locked"
                                        value={subject}
                                        onChange={(e) => setSubject(e.target.value)}
                                        className="w-full text-xs px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                                    />
                                </div>

                                <div>
                                    <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1 font-mono">
                                        Email Body Content *
                                    </label>
                                    <textarea
                                        rows={5}
                                        placeholder="Paste the message content..."
                                        value={body}
                                        onChange={(e) => setBody(e.target.value)}
                                        className="w-full text-xs font-mono px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                                        required
                                    />
                                </div>

                                {/* Advanced headers toggle */}
                                <div className="border-t border-slate-800/80 pt-3">
                                    <button
                                        type="button"
                                        onClick={() => setShowAdvanced(!showAdvanced)}
                                        className="flex items-center justify-between w-full text-xs font-mono text-slate-400 hover:text-cyan-400 py-1"
                                    >
                                        <span className="flex items-center gap-1.5">
                                            <FileCode className="h-4 w-4" />
                                            Add RFC Headers & Attachments
                                        </span>
                                        {showAdvanced ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                                    </button>

                                    {showAdvanced && (
                                        <div className="space-y-3 pt-3 mt-2 border-t border-slate-800/50">
                                            <div>
                                                <label className="block text-xs text-slate-400 mb-1 font-mono">
                                                    Raw Headers (SPF / DKIM / DMARC):
                                                </label>
                                                <textarea
                                                    rows={3}
                                                    placeholder={"Received-SPF: fail\nAuthentication-Results: dkim=fail; dmarc=fail"}
                                                    value={rawHeaders}
                                                    onChange={(e) => setRawHeaders(e.target.value)}
                                                    className="w-full text-[11px] font-mono px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 placeholder-slate-700 focus:outline-none focus:border-cyan-500"
                                                />
                                            </div>
                                        </div>
                                    )}
                                </div>

                                <div className="flex items-center gap-2 pt-2">
                                    <button
                                        type="submit"
                                        disabled={loading}
                                        className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-md shadow-cyan-950 disabled:opacity-50"
                                    >
                                        <Send className="h-4 w-4" />
                                        <span>Run Threat Analysis</span>
                                    </button>
                                    <button
                                        type="button"
                                        onClick={handleResetManual}
                                        className="p-2.5 rounded-xl border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300"
                                    >
                                        <RotateCcw className="h-4 w-4" />
                                    </button>
                                </div>
                            </form>
                        </div>
                    )}

                    {/* Error Banner */}
                    {error && (
                        <div className="rounded-lg bg-rose-950/40 border border-rose-800/50 p-3 text-xs text-rose-300 flex items-start gap-2">
                            <AlertTriangle className="h-4 w-4 text-rose-400 flex-shrink-0 mt-0.5" />
                            <span>{error}</span>
                        </div>
                    )}
                </div>

                {/* ── Right Column: Live Analysis Result Card ── */}
                <div className="lg:col-span-6 space-y-4">
                    {!result && !loading && (
                        <div className="rounded-xl border border-dashed border-slate-800 bg-slate-900/30 p-12 text-center text-slate-500 flex flex-col items-center justify-center min-h-[350px]">
                            <Search className="h-10 w-10 text-slate-700 mb-3" />
                            <h3 className="text-sm font-semibold text-slate-400">Awaiting Email Selection</h3>
                            <p className="text-xs text-slate-500 max-w-xs mt-1">
                                Click any email from the <strong>Demo Inbox</strong> or use the <strong>Manual Input</strong> form to begin threat analysis.
                            </p>
                        </div>
                    )}

                    {loading && (
                        <div className="rounded-xl border border-cyan-500/20 bg-slate-900/40 p-12 text-center flex flex-col items-center justify-center min-h-[350px] space-y-4">
                            <div className="relative">
                                <div className="h-14 w-14 rounded-full border-4 border-cyan-500/20 border-t-cyan-400 animate-spin" />
                                <ShieldAlert className="h-6 w-6 text-cyan-400 absolute top-4 left-4 animate-pulse" />
                            </div>
                            <div className="space-y-1">
                                <h3 className="text-sm font-bold text-white">Inspecting Threat Vectors</h3>
                                <p className="text-xs text-slate-400 font-mono">
                                    Evaluating Text • URLs • Headers • Attachments • Scorer
                                </p>
                            </div>
                        </div>
                    )}

                    {result && (
                        <div className="space-y-4">
                            {/* Score & Verdict Card */}
                            <div className={`rounded-xl border p-5 ${getScoreColor(result.risk_score)}`}>
                                <div className="flex items-center justify-between">
                                    <div>
                                        <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-slate-900/80 font-bold border border-current">
                                            Threat Level: {result.risk_level?.toUpperCase()}
                                        </span>
                                        <h3 className="text-lg font-extrabold text-white mt-2">
                                            {result.verdict}
                                        </h3>
                                    </div>
                                    <div className="text-right">
                                        <span className="text-3xl font-extrabold font-mono tracking-tight">
                                            {result.risk_score}
                                        </span>
                                        <span className="text-xs font-mono text-slate-400 block">/ 100 Risk</span>
                                    </div>
                                </div>

                                {/* Vector Breakdown Grid */}
                                {result.score_breakdown && (
                                    <div className="mt-4 pt-4 border-t border-slate-800/60 grid grid-cols-5 gap-2 text-center">
                                        {[
                                            { label: "Content", key: "content_score" },
                                            { label: "Sender", key: "sender_score" },
                                            { label: "URLs", key: "url_score" },
                                            { label: "Files", key: "attachment_score" },
                                            { label: "Headers", key: "header_score" },
                                        ].map((v) => (
                                            <div key={v.key} className="bg-slate-900/80 p-1.5 rounded border border-slate-800">
                                                <span className="text-[9px] font-mono text-slate-400 block uppercase">{v.label}</span>
                                                <span className="text-xs font-bold font-mono text-slate-200">+{result.score_breakdown[v.key]}</span>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>

                            {/* AI Explanation */}
                            {result.ai_explanation && (
                                <div className="rounded-xl border border-cyan-500/30 bg-slate-900/80 p-4 space-y-2">
                                    <div className="flex items-center gap-1.5 text-xs font-bold text-cyan-300 font-mono">
                                        <Sparkles className="h-4 w-4 text-cyan-400" />
                                        <span>AI Security Analyst Verdict</span>
                                    </div>
                                    <p className="text-xs text-slate-300 leading-relaxed">
                                        {result.ai_explanation}
                                    </p>
                                </div>
                            )}

                            {/* Threat Indicators */}
                            <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 space-y-3">
                                <div className="flex items-center justify-between text-xs font-semibold text-slate-300">
                                    <span className="flex items-center gap-1.5 font-mono">
                                        <AlertTriangle className="h-4 w-4 text-amber-400" />
                                        Detected Threat Indicators ({result.indicators?.length || 0})
                                    </span>
                                </div>

                                {result.indicators && result.indicators.length > 0 ? (
                                    <div className="space-y-2">
                                        {result.indicators.map((ind, i) => (
                                            <div key={i} className="rounded-lg bg-slate-950 p-2.5 border border-slate-800 text-xs">
                                                <div className="flex items-center justify-between">
                                                    <span className="font-mono text-amber-300 font-semibold">{ind.indicator}</span>
                                                    <span className={`text-[10px] uppercase font-mono px-1.5 py-0.5 rounded ${ind.severity === "high"
                                                        ? "bg-rose-950 text-rose-400 border border-rose-800"
                                                        : "bg-amber-950 text-amber-400 border border-amber-800"
                                                        }`}>
                                                        {ind.severity}
                                                    </span>
                                                </div>
                                                <p className="text-[11px] text-slate-400 mt-1">{ind.description}</p>
                                                {ind.evidence && (
                                                    <div className="mt-1.5 text-[10px] font-mono bg-slate-900 px-2 py-1 rounded text-slate-300 border border-slate-800">
                                                        Evidence: <span className="text-cyan-300">"{ind.evidence}"</span>
                                                    </div>
                                                )}
                                            </div>
                                        ))}
                                    </div>
                                ) : (
                                    <div className="text-xs text-emerald-400 flex items-center gap-1.5 font-mono">
                                        <CheckCircle2 className="h-4 w-4" />
                                        No malicious indicators detected.
                                    </div>
                                )}
                            </div>

                            {/* URL Findings */}
                            {result.url_analysis && result.url_analysis.length > 0 && (
                                <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 space-y-2">
                                    <div className="flex items-center gap-1.5 text-xs font-mono text-slate-300 font-semibold">
                                        <Link2 className="h-4 w-4 text-cyan-400" />
                                        <span>Static URL Findings ({result.url_analysis.length})</span>
                                    </div>
                                    <div className="space-y-1.5">
                                        {result.url_analysis.map((u, i) => (
                                            <div key={i} className="text-xs font-mono p-2 rounded bg-slate-950 border border-slate-800 flex items-start justify-between">
                                                <span className="text-slate-300 break-all text-[11px]">{u.url}</span>
                                                <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase font-bold ml-2 ${u.is_suspicious
                                                    ? "bg-rose-950 text-rose-400 border border-rose-800"
                                                    : "bg-emerald-950 text-emerald-400 border border-emerald-800"
                                                    }`}>
                                                    {u.is_suspicious ? "Suspicious" : "Clean"}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Recommendations */}
                            {result.recommendations && result.recommendations.length > 0 && (
                                <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 space-y-2">
                                    <div className="flex items-center gap-1.5 text-xs font-mono text-cyan-300 font-semibold">
                                        <Info className="h-4 w-4 text-cyan-400" />
                                        <span>Recommended Defense Actions</span>
                                    </div>
                                    <ul className="space-y-1 text-xs text-slate-300 list-disc list-inside">
                                        {result.recommendations.map((rec, i) => (
                                            <li key={i} className="leading-relaxed">{rec}</li>
                                        ))}
                                    </ul>
                                </div>
                            )}

                            {/* ── SOC Escalation & Action Bar ── */}
                            <div className="rounded-xl border border-cyan-500/40 bg-gradient-to-r from-slate-900 via-cyan-950/20 to-slate-900 p-4 space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs font-mono font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-1.5">
                                        <Terminal className="h-4 w-4 text-cyan-400" />
                                        <span>Escalate to Threat Operations</span>
                                    </span>
                                    <span className="text-[10px] font-mono text-slate-400">
                                        {result.id ? `Incident #${result.id}` : 'Live Incident Stream'}
                                    </span>
                                </div>
                                <p className="text-[11px] text-slate-300">
                                    Transition this threat finding directly into deep forensic dossiers, MITRE ATT&CK mapping, campaign correlation, or launch autonomous remediation.
                                </p>
                                <div className="flex flex-wrap items-center gap-2 pt-1">
                                    <Link
                                        to={result.id ? `/investigation?tab=dossier&analysisId=${result.id}` : `/investigation?tab=dossier`}
                                        onClick={() => {
                                            try {
                                                localStorage.setItem('cybershield_active_incident', JSON.stringify({
                                                    id: result.id,
                                                    sender: sender || result.sender,
                                                    subject: subject || result.subject,
                                                    body: body || result.body,
                                                    raw_headers: rawHeaders || result.raw_headers
                                                }));
                                            } catch (e) {}
                                        }}
                                        className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all shadow-md shadow-cyan-950"
                                    >
                                        <FileText className="h-3.5 w-3.5" />
                                        <span>View Forensic Dossier</span>
                                        <ArrowRight className="h-3 w-3" />
                                    </Link>

                                    <Link
                                        to={result.id ? `/investigation?tab=remediation&analysisId=${result.id}` : `/investigation?tab=remediation`}
                                        onClick={() => {
                                            try {
                                                localStorage.setItem('cybershield_active_incident', JSON.stringify({
                                                    id: result.id,
                                                    sender: sender || result.sender,
                                                    subject: subject || result.subject,
                                                    body: body || result.body,
                                                    raw_headers: rawHeaders || result.raw_headers
                                                }));
                                            } catch (e) {}
                                        }}
                                        className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-rose-300 font-semibold text-xs border border-rose-900/50 transition-all"
                                    >
                                        <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />
                                        <span>Autonomous Remediation</span>
                                    </Link>

                                    <Link
                                        to="/investigation?tab=correlation"
                                        className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-purple-300 font-semibold text-xs border border-purple-900/50 transition-all"
                                    >
                                        <Layers className="h-3.5 w-3.5 text-purple-400" />
                                        <span>Correlate Campaign</span>
                                    </Link>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

            </div>
        </div>
    );
}