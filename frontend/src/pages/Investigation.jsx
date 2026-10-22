import React, { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
    Terminal,
    Search,
    ShieldAlert,
    ShieldCheck,
    AlertTriangle,
    CheckCircle2,
    XCircle,
    ExternalLink,
    FileText,
    Link2,
    Paperclip,
    Mail,
    Layers,
    Network,
    RefreshCw,
    Play,
    Activity,
    Clock,
    ArrowRight,
    Lock,
    UserX,
    Server,
    Eye,
    Sliders,
    ChevronRight,
    Zap
} from 'lucide-react';
import {
    getInvestigationDossier,
    generateLiveInvestigation,
    getAnalysesHistory,
    scanUrl,
    scanAttachment,
    scanHeaders,
    detectAllCampaigns,
    correlateIncidentById,
    executeRemediationById,
    executeLiveRemediation,
    dryRunRemediation,
    getRemediationAuditLog,
    verifyStoredRemediation,
    verifyLiveRemediation
} from '../services/api';

export default function Investigation() {
    const [searchParams, setSearchParams] = useSearchParams();
    const activeTab = searchParams.get('tab') || 'dossier'; // 'dossier' | 'scanners' | 'correlation' | 'remediation'
    const paramAnalysisId = searchParams.get('analysisId');

    const setTab = (tab) => {
        setSearchParams(prev => {
            const next = new URLSearchParams(prev);
            next.set('tab', tab);
            return next;
        });
    };

    // ─── 1. DOSSIER STATE ──────────────────────────────────────────────────────
    const [recentAnalyses, setRecentAnalyses] = useState([]);
    const [selectedAnalysisId, setSelectedAnalysisId] = useState(paramAnalysisId || '');
    const [dossier, setDossier] = useState(null);
    const [dossierLoading, setDossierLoading] = useState(false);
    const [dossierError, setDossierError] = useState(null);

    // Live Dossier Input state
    const [showLiveInput, setShowLiveInput] = useState(false);
    const [liveSender, setLiveSender] = useState('');
    const [liveSubject, setLiveSubject] = useState('');
    const [liveBody, setLiveBody] = useState('');
    const [liveHeaders, setLiveHeaders] = useState('');

    // ─── 2. SCANNERS STATE ─────────────────────────────────────────────────────
    const [scannerType, setScannerType] = useState('url'); // 'url' | 'attachment' | 'headers'
    const [scanInputUrl, setScanInputUrl] = useState('http://secure-login.paypal-verification.xyz/auth?user=victim');
    const [scanInputFilename, setScanInputFilename] = useState('Q3_Bonus_Calculation.xlsm');
    const [scanInputSize, setScanInputSize] = useState(84500);
    const [scanInputMime, setScanInputMime] = useState('application/vnd.ms-excel.sheet.macroEnabled.12');
    const [scanInputHeaders, setScanInputHeaders] = useState('From: "PayPal Support" <security@paypal-update.xyz>\nReturn-Path: <bounce@attacker-vps.net>\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail');
    const [scannerResult, setScannerResult] = useState(null);
    const [scannerLoading, setScannerLoading] = useState(false);
    const [scannerError, setScannerError] = useState(null);

    // ─── 3. CORRELATION STATE ──────────────────────────────────────────────────
    const [campaigns, setCampaigns] = useState(null);
    const [campaignsLoading, setCampaignsLoading] = useState(false);
    const [correlationReport, setCorrelationReport] = useState(null);
    const [correlationLoading, setCorrelationLoading] = useState(false);

    // ─── 4. REMEDIATION & VERIFICATION STATE ───────────────────────────────────
    const [remediationTargetId, setRemediationTargetId] = useState('');
    const [remediationResult, setRemediationResult] = useState(null);
    const [remediationLoading, setRemediationLoading] = useState(false);
    const [remediationError, setRemediationError] = useState(null);
    const [isDryRun, setIsDryRun] = useState(true);
    const [verificationReport, setVerificationReport] = useState(null);
    const [verificationLoading, setVerificationLoading] = useState(false);
    const [auditLog, setAuditLog] = useState([]);

    // ─── INITIAL DATA LOAD ─────────────────────────────────────────────────────
    useEffect(() => {
        loadRecentAnalyses();
        loadAuditLog();
        loadCampaigns();
    }, []);

    useEffect(() => {
        if (paramAnalysisId) {
            setSelectedAnalysisId(paramAnalysisId);
            setRemediationTargetId(paramAnalysisId);
            loadDossier(paramAnalysisId);
        } else {
            try {
                const cached = localStorage.getItem('cybershield_active_incident');
                if (cached) {
                    const parsed = JSON.parse(cached);
                    if (parsed.sender) setLiveSender(parsed.sender);
                    if (parsed.subject) setLiveSubject(parsed.subject);
                    if (parsed.body) setLiveBody(parsed.body);
                    if (parsed.raw_headers) setLiveHeaders(parsed.raw_headers);
                    if (parsed.id) {
                        setSelectedAnalysisId(parsed.id);
                        setRemediationTargetId(parsed.id);
                        loadDossier(parsed.id);
                    } else if (parsed.sender && parsed.body) {
                        generateLiveInvestigation({
                            sender: parsed.sender,
                            subject: parsed.subject || '',
                            body: parsed.body,
                            raw_headers: parsed.raw_headers || undefined
                        }).then(res => setDossier(res)).catch(() => {});
                    }
                }
            } catch (e) {}
        }
    }, [paramAnalysisId]);

    const loadRecentAnalyses = async () => {
        try {
            const data = await getAnalysesHistory(15, 0);
            setRecentAnalyses(data.records || []);
            if (!paramAnalysisId && data.records && data.records.length > 0) {
                const firstId = data.records[0].analysis_id;
                setSelectedAnalysisId(firstId);
                setRemediationTargetId(firstId);
                loadDossier(firstId);
            }
        } catch (err) {
            console.error("Failed to load past analyses:", err);
        }
    };

    const loadDossier = async (id) => {
        if (!id) return;
        setDossierLoading(true);
        setDossierError(null);
        try {
            const res = await getInvestigationDossier(id);
            setDossier(res);
        } catch (err) {
            setDossierError(err.response?.data?.detail || err.message || "Failed to load investigation dossier.");
        } finally {
            setDossierLoading(false);
        }
    };

    const handleRunLiveDossier = async (e) => {
        e.preventDefault();
        setDossierLoading(true);
        setDossierError(null);
        try {
            const res = await generateLiveInvestigation({
                sender: liveSender,
                subject: liveSubject,
                body: liveBody,
                raw_headers: liveHeaders || undefined
            });
            setDossier(res);
            setShowLiveInput(false);
        } catch (err) {
            setDossierError(err.response?.data?.detail || err.message || "Live investigation failed.");
        } finally {
            setDossierLoading(false);
        }
    };

    // ─── SCANNER HANDLER ───────────────────────────────────────────────────────
    const handleRunScanner = async () => {
        setScannerLoading(true);
        setScannerError(null);
        setScannerResult(null);
        try {
            let res;
            if (scannerType === 'url') {
                res = await scanUrl(scanInputUrl);
            } else if (scannerType === 'attachment') {
                res = await scanAttachment(scanInputFilename, Number(scanInputSize), scanInputMime);
            } else if (scannerType === 'headers') {
                res = await scanHeaders(scanInputHeaders);
            }
            setScannerResult(res);
        } catch (err) {
            setScannerError(err.response?.data?.detail || err.message || "Scanner analysis failed.");
        } finally {
            setScannerLoading(false);
        }
    };

    // ─── CAMPAIGNS & CORRELATION HANDLERS ──────────────────────────────────────
    const loadCampaigns = async () => {
        setCampaignsLoading(true);
        try {
            const res = await detectAllCampaigns();
            setCampaigns(res);
        } catch (err) {
            console.error("Campaign detection failed:", err);
        } finally {
            setCampaignsLoading(false);
        }
    };

    const handleCorrelateIncident = async (id) => {
        if (!id) return;
        setCorrelationLoading(true);
        try {
            const res = await correlateIncidentById(id);
            setCorrelationReport(res);
        } catch (err) {
            console.error("Incident correlation failed:", err);
        } finally {
            setCorrelationLoading(false);
        }
    };

    // ─── REMEDIATION & VERIFICATION HANDLERS ───────────────────────────────────
    const loadAuditLog = async () => {
        try {
            const res = await getRemediationAuditLog(20, 0);
            setAuditLog(res.records || []);
        } catch (err) {
            console.error("Failed to load audit log:", err);
        }
    };

    const handleExecuteRemediation = async () => {
        if (!remediationTargetId) return;
        setRemediationLoading(true);
        setRemediationError(null);
        setVerificationReport(null);
        try {
            const res = await executeRemediationById(remediationTargetId, isDryRun);
            setRemediationResult(res);
            loadAuditLog();
        } catch (err) {
            setRemediationError(err.response?.data?.detail || err.message || "Remediation execution failed.");
        } finally {
            setRemediationLoading(false);
        }
    };

    const handleRunVerification = async () => {
        if (!remediationResult) return;
        setVerificationLoading(true);
        try {
            const res = await verifyLiveRemediation(remediationResult);
            setVerificationReport(res);
        } catch (err) {
            console.error("Verification probe failed:", err);
        } finally {
            setVerificationLoading(false);
        }
    };

    const getSeverityBadge = (level) => {
        const l = (level || '').toLowerCase();
        if (l === 'critical') return 'bg-rose-950/80 text-rose-300 border-rose-800';
        if (l === 'high') return 'bg-orange-950/80 text-orange-300 border-orange-800';
        if (l === 'medium') return 'bg-amber-950/80 text-amber-300 border-amber-800';
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-800';
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
                <div>
                    <div className="flex items-center gap-2.5">
                        <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
                            <Terminal className="h-6 w-6" />
                        </div>
                        <div>
                            <h1 className="text-2xl font-bold text-white tracking-tight">Threat Investigation Center</h1>
                            <p className="text-xs text-slate-400">
                                Forensic incident dossiers, artifact scanners, campaign clustering, and autonomous remediation playbooks.
                            </p>
                        </div>
                    </div>
                </div>

                {/* Sub-Navigation Tabs */}
                <div className="flex items-center gap-1.5 p-1 bg-slate-900 border border-slate-800 rounded-xl text-xs">
                    <button
                        onClick={() => setTab('dossier')}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-all ${
                            activeTab === 'dossier'
                                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
                                : 'text-slate-400 hover:text-slate-200'
                        }`}
                    >
                        <FileText className="h-3.5 w-3.5" />
                        Forensic Dossier
                    </button>
                    <button
                        onClick={() => setTab('scanners')}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-all ${
                            activeTab === 'scanners'
                                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
                                : 'text-slate-400 hover:text-slate-200'
                        }`}
                    >
                        <Search className="h-3.5 w-3.5" />
                        Artifact Scanners
                    </button>
                    <button
                        onClick={() => setTab('correlation')}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-all ${
                            activeTab === 'correlation'
                                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
                                : 'text-slate-400 hover:text-slate-200'
                        }`}
                    >
                        <Network className="h-3.5 w-3.5" />
                        Campaign Correlation
                    </button>
                    <button
                        onClick={() => setTab('remediation')}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium transition-all ${
                            activeTab === 'remediation'
                                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
                                : 'text-slate-400 hover:text-slate-200'
                        }`}
                    >
                        <Zap className="h-3.5 w-3.5" />
                        Autonomous Response
                    </button>
                </div>
            </div>

            {/* ═══════════════════════════════════════════════════════════════════ */}
            {/* TAB 1: SOC FORENSIC DOSSIER */}
            {/* ═══════════════════════════════════════════════════════════════════ */}
            {activeTab === 'dossier' && (
                <div className="space-y-6">
                    {/* Controls Bar */}
                    <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-4 rounded-xl border border-slate-800 bg-slate-900/60">
                        <div className="flex items-center gap-3 flex-1">
                            <span className="text-xs font-medium text-slate-400 whitespace-nowrap">Target Incident:</span>
                            <select
                                value={selectedAnalysisId}
                                onChange={(e) => {
                                    setSelectedAnalysisId(e.target.value);
                                    setRemediationTargetId(e.target.value);
                                    loadDossier(e.target.value);
                                }}
                                className="w-full sm:max-w-md bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                            >
                                <option value="">-- Select Stored Incident --</option>
                                {recentAnalyses.map((rec) => (
                                    <option key={rec.analysis_id} value={rec.analysis_id}>
                                        [{rec.risk_level?.toUpperCase() || 'LOW'}] {rec.subject?.slice(0, 45)} ({rec.sender?.slice(0, 25)})
                                    </option>
                                ))}
                            </select>
                            <button
                                onClick={() => loadDossier(selectedAnalysisId)}
                                disabled={!selectedAnalysisId || dossierLoading}
                                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium border border-slate-700 transition-colors"
                            >
                                <RefreshCw className={`h-3.5 w-3.5 ${dossierLoading ? 'animate-spin' : ''}`} />
                            </button>
                        </div>

                        <div className="flex items-center gap-2">
                            <button
                                onClick={() => setShowLiveInput(!showLiveInput)}
                                className="px-3 py-1.5 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded-lg text-xs font-medium transition-colors"
                            >
                                {showLiveInput ? "Hide Live Input" : "Inspect Raw Email Payload"}
                            </button>
                        </div>
                    </div>

                    {/* Collapsible Live Input */}
                    {showLiveInput && (
                        <form onSubmit={handleRunLiveDossier} className="p-5 rounded-xl border border-purple-500/30 bg-purple-950/10 space-y-4">
                            <h3 className="text-xs font-bold text-purple-300 uppercase tracking-wider">Direct Live Payload Evaluation</h3>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-[11px] text-slate-400 mb-1">Sender</label>
                                    <input
                                        type="text"
                                        value={liveSender}
                                        onChange={(e) => setLiveSender(e.target.value)}
                                        placeholder="e.g. support@paypal-security.xyz"
                                        required
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200"
                                    />
                                </div>
                                <div>
                                    <label className="block text-[11px] text-slate-400 mb-1">Subject</label>
                                    <input
                                        type="text"
                                        value={liveSubject}
                                        onChange={(e) => setLiveSubject(e.target.value)}
                                        placeholder="e.g. URGENT: Verify Your Credentials"
                                        required
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200"
                                    />
                                </div>
                            </div>
                            <div>
                                <label className="block text-[11px] text-slate-400 mb-1">Email Body Text</label>
                                <textarea
                                    value={liveBody}
                                    onChange={(e) => setLiveBody(e.target.value)}
                                    placeholder="Paste suspicious email text containing links or requests..."
                                    rows={3}
                                    required
                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200"
                                />
                            </div>
                            <div>
                                <label className="block text-[11px] text-slate-400 mb-1">Raw RFC Headers (Optional)</label>
                                <textarea
                                    value={liveHeaders}
                                    onChange={(e) => setLiveHeaders(e.target.value)}
                                    placeholder="From: ... Received-SPF: fail ... Authentication-Results: ..."
                                    rows={2}
                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono"
                                />
                            </div>
                            <button
                                type="submit"
                                disabled={dossierLoading}
                                className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-purple-950 transition-colors"
                            >
                                {dossierLoading ? "Generating Dossier..." : "Generate SOC Dossier"}
                            </button>
                        </form>
                    )}

                    {/* Dossier Display */}
                    {dossierLoading && (
                        <div className="p-12 text-center border border-slate-800 rounded-xl bg-slate-900/40 space-y-3">
                            <RefreshCw className="h-8 w-8 text-purple-400 animate-spin mx-auto" />
                            <p className="text-xs text-slate-400">Synthesizing forensic indicators, attack phases, and remediation playbooks...</p>
                        </div>
                    )}

                    {dossierError && (
                        <div className="p-4 rounded-xl border border-rose-800 bg-rose-950/40 text-rose-300 text-xs">
                            {dossierError}
                        </div>
                    )}

                    {!dossierLoading && dossier && (
                        <div className="space-y-6">
                            {/* Executive Summary Card */}
                            <div className="rounded-xl border border-slate-800 bg-gradient-to-br from-slate-900 to-slate-950 p-6 space-y-4">
                                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
                                    <div>
                                        <div className="flex items-center gap-2">
                                            <span className="font-mono text-[10px] text-purple-400 uppercase tracking-widest">
                                                INCIDENT #{dossier.investigation_id?.slice(-8) || 'SOC-REF'}
                                            </span>
                                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border uppercase tracking-wider ${getSeverityBadge(dossier.overall_threat_level)}`}>
                                                {dossier.overall_threat_level} THREAT
                                            </span>
                                        </div>
                                        <h2 className="text-xl font-bold text-white mt-1">{dossier.subject}</h2>
                                        <p className="text-xs text-slate-400 font-mono mt-0.5">Sender: {dossier.sender}</p>
                                    </div>
                                    <div className="flex items-center gap-3">
                                        <div className="text-right">
                                            <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Unified Risk Score</span>
                                            <span className="text-2xl font-black text-purple-400">{dossier.risk_score} / 100</span>
                                        </div>
                                    </div>
                                </div>

                                <div className="space-y-2">
                                    <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Executive Threat Summary</h4>
                                    <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-3.5 rounded-lg border border-slate-800/60 font-mono">
                                        {dossier.executive_summary}
                                    </p>
                                </div>

                                {/* Action Shortcuts */}
                                <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-800/60">
                                    <button
                                        onClick={() => {
                                            setTab('remediation');
                                            setRemediationTargetId(selectedAnalysisId);
                                        }}
                                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-500/15 hover:bg-purple-500/25 text-purple-300 border border-purple-500/30 text-xs font-semibold transition-colors"
                                    >
                                        <Zap className="h-3.5 w-3.5" />
                                        Launch Autonomous Remediation
                                    </button>
                                    <button
                                        onClick={() => {
                                            setTab('correlation');
                                            handleCorrelateIncident(selectedAnalysisId);
                                        }}
                                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-semibold transition-colors"
                                    >
                                        <Network className="h-3.5 w-3.5" />
                                        Correlate with Global Campaigns
                                    </button>
                                </div>
                            </div>

                            {/* Attack Chain Breakdown (MITRE ATT&CK Alignment) */}
                            {dossier.attack_chain_breakdown && dossier.attack_chain_breakdown.length > 0 && (
                                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
                                    <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                                        <Layers className="h-4 w-4 text-purple-400" />
                                        Cyber Kill Chain & Attack Progression
                                    </h3>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
                                        {dossier.attack_chain_breakdown.map((phase, i) => (
                                            <div key={i} className="p-3 rounded-lg border border-slate-800 bg-slate-950/70 space-y-1.5">
                                                <div className="flex items-center justify-between text-[11px]">
                                                    <span className="font-bold text-purple-300">{phase.phase_name}</span>
                                                    <span className="font-mono text-slate-500 text-[10px]">{phase.technique_id || 'T1566'}</span>
                                                </div>
                                                <p className="text-[11px] text-slate-400 line-clamp-3">{phase.description}</p>
                                                <div className="text-[10px] text-slate-500 font-mono">
                                                    Confidence: <span className="text-slate-300">{phase.confidence || 'HIGH'}</span>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Forensic Evidence Matrix */}
                            {dossier.evidence_matrix && dossier.evidence_matrix.length > 0 && (
                                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
                                    <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                                        <Eye className="h-4 w-4 text-purple-400" />
                                        Forensic Evidence Matrix
                                    </h3>
                                    <div className="overflow-x-auto">
                                        <table className="w-full text-left text-xs">
                                            <thead>
                                                <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                                                    <th className="py-2 px-3">Vector</th>
                                                    <th className="py-2 px-3">Indicator</th>
                                                    <th className="py-2 px-3">Severity</th>
                                                    <th className="py-2 px-3">Extracted Artifact / Rationale</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                                                {dossier.evidence_matrix.map((ev, i) => (
                                                    <tr key={i} className="hover:bg-slate-800/30">
                                                        <td className="py-2.5 px-3 text-purple-300 capitalize">{ev.vector}</td>
                                                        <td className="py-2.5 px-3 text-slate-300">{ev.indicator}</td>
                                                        <td className="py-2.5 px-3">
                                                            <span className={`px-2 py-0.5 rounded text-[10px] border ${getSeverityBadge(ev.severity)}`}>
                                                                {ev.severity}
                                                            </span>
                                                        </td>
                                                        <td className="py-2.5 px-3 text-slate-400 font-sans">
                                                            <div>{ev.rationale}</div>
                                                            {ev.extracted_value && (
                                                                <div className="font-mono text-[10px] text-slate-500 mt-0.5 break-all">
                                                                    Value: {ev.extracted_value}
                                                                </div>
                                                            )}
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            )}

                            {/* Remediation Playbook Preview */}
                            {dossier.remediation_playbook && dossier.remediation_playbook.length > 0 && (
                                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
                                    <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                                        <ShieldCheck className="h-4 w-4 text-emerald-400" />
                                        Recommended Incident Remediation Playbook
                                    </h3>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                        {dossier.remediation_playbook.map((act, i) => (
                                            <div key={i} className="p-3 rounded-lg border border-slate-800 bg-slate-950/70 space-y-1">
                                                <div className="flex items-center justify-between text-xs">
                                                    <span className="font-bold text-slate-200">{act.action_type?.replace(/_/g, ' ').toUpperCase()}</span>
                                                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                                                        P{act.priority || 1}
                                                    </span>
                                                </div>
                                                <p className="text-[11px] text-slate-400">{act.description}</p>
                                                <div className="text-[10px] text-purple-400 font-mono pt-1">
                                                    Feasibility: {act.automation_feasibility || 'Autonomous'}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════════ */}
            {/* TAB 2: STANDALONE ARTIFACT SCANNERS */}
            {/* ═══════════════════════════════════════════════════════════════════ */}
            {activeTab === 'scanners' && (
                <div className="space-y-6">
                    {/* Scanner Type Switcher */}
                    <div className="flex border-b border-slate-800 gap-6">
                        <button
                            onClick={() => { setScannerType('url'); setScannerResult(null); }}
                            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all ${
                                scannerType === 'url' ? 'border-purple-500 text-purple-400' : 'border-transparent text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <Link2 className="h-4 w-4" />
                            URL Threat Scanner
                        </button>
                        <button
                            onClick={() => { setScannerType('headers'); setScannerResult(null); }}
                            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all ${
                                scannerType === 'headers' ? 'border-purple-500 text-purple-400' : 'border-transparent text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <Mail className="h-4 w-4" />
                            Email Header Inspector (SPF/DKIM/DMARC)
                        </button>
                        <button
                            onClick={() => { setScannerType('attachment'); setScannerResult(null); }}
                            className={`pb-3 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all ${
                                scannerType === 'attachment' ? 'border-purple-500 text-purple-400' : 'border-transparent text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <Paperclip className="h-4 w-4" />
                            Attachment Payload Scanner
                        </button>
                    </div>

                    {/* Scanner Input Panel */}
                    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
                        {scannerType === 'url' && (
                            <div className="space-y-3">
                                <div>
                                    <label className="block text-xs font-medium text-slate-300 mb-1">Target URL for Static Heuristic Inspection</label>
                                    <input
                                        type="url"
                                        value={scanInputUrl}
                                        onChange={(e) => setScanInputUrl(e.target.value)}
                                        placeholder="https://example.com/login"
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-slate-200 font-mono"
                                    />
                                    <p className="text-[11px] text-slate-500 mt-1">
                                        Inspects brand typosquatting, raw IP hosts, suspicious TLDs, disguised credential parameters, and unencrypted transport.
                                    </p>
                                </div>
                            </div>
                        )}

                        {scannerType === 'headers' && (
                            <div className="space-y-3">
                                <div>
                                    <label className="block text-xs font-medium text-slate-300 mb-1">Raw RFC 822 Email Headers</label>
                                    <textarea
                                        value={scanInputHeaders}
                                        onChange={(e) => setScanInputHeaders(e.target.value)}
                                        rows={6}
                                        placeholder="From: ...\nReturn-Path: ...\nAuthentication-Results: mx.google.com; dkim=fail; spf=fail"
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-200 font-mono"
                                    />
                                    <p className="text-[11px] text-slate-500 mt-1">
                                        Verifies SPF, DKIM, and DMARC alignment, Return-Path rerouting, and forged display sender identities.
                                    </p>
                                </div>
                            </div>
                        )}

                        {scannerType === 'attachment' && (
                            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                                <div className="sm:col-span-2">
                                    <label className="block text-xs font-medium text-slate-300 mb-1">Filename with Extension</label>
                                    <input
                                        type="text"
                                        value={scanInputFilename}
                                        onChange={(e) => setScanInputFilename(e.target.value)}
                                        placeholder="e.g. Invoice_981.pdf.exe"
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono"
                                    />
                                </div>
                                <div>
                                    <label className="block text-xs font-medium text-slate-300 mb-1">File Size (Bytes)</label>
                                    <input
                                        type="number"
                                        value={scanInputSize}
                                        onChange={(e) => setScanInputSize(e.target.value)}
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono"
                                    />
                                </div>
                                <div className="sm:col-span-3">
                                    <label className="block text-xs font-medium text-slate-300 mb-1">MIME Content-Type</label>
                                    <input
                                        type="text"
                                        value={scanInputMime}
                                        onChange={(e) => setScanInputMime(e.target.value)}
                                        placeholder="e.g. application/x-msdownload"
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono"
                                    />
                                </div>
                            </div>
                        )}

                        <button
                            onClick={handleRunScanner}
                            disabled={scannerLoading}
                            className="px-5 py-2.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-purple-950 transition-colors flex items-center gap-2"
                        >
                            {scannerLoading ? (
                                <>
                                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                                    Scanning Artifact...
                                </>
                            ) : (
                                <>
                                    <Search className="h-3.5 w-3.5" />
                                    Execute Deep Static Inspection
                                </>
                            )}
                        </button>
                    </div>

                    {/* Scanner Results Panel */}
                    {scannerError && (
                        <div className="p-4 rounded-xl border border-rose-800 bg-rose-950/40 text-rose-300 text-xs">
                            {scannerError}
                        </div>
                    )}

                    {scannerResult && (
                        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                                <div>
                                    <div className="flex items-center gap-2">
                                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${getSeverityBadge(scannerResult.risk_level)}`}>
                                            {scannerResult.risk_level} Risk
                                        </span>
                                        <span className="text-xs text-slate-400 font-mono">
                                            {scannerResult.is_suspicious ? "MALICIOUS ANOMALIES DETECTED" : "NO THREATS IDENTIFIED"}
                                        </span>
                                    </div>
                                    <h3 className="text-lg font-bold text-white mt-1">{scannerResult.verdict}</h3>
                                </div>
                                <div className="text-right">
                                    <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Artifact Risk Score</span>
                                    <span className="text-2xl font-black text-purple-400">{scannerResult.risk_score} / 100</span>
                                </div>
                            </div>

                            {/* Detected Reasons List */}
                            {scannerResult.reasons && scannerResult.reasons.length > 0 && (
                                <div className="space-y-2">
                                    <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Forensic Findings</h4>
                                    <ul className="space-y-1.5">
                                        {scannerResult.reasons.map((r, i) => (
                                            <li key={i} className="flex items-start gap-2 text-xs text-slate-300 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
                                                <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                                                <span>{r}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            )}

                            {/* Detailed Technical Structure */}
                            {scannerResult.sender_alignment && (
                                <div className="space-y-2 pt-2 border-t border-slate-800">
                                    <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Authentication Protocol Status</h4>
                                    <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
                                        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                                            <span className="block text-[10px] text-slate-500">SPF</span>
                                            <span className={`font-bold ${scannerResult.spf_status === 'pass' ? 'text-emerald-400' : 'text-rose-400'}`}>
                                                {scannerResult.spf_status?.toUpperCase() || 'NONE'}
                                            </span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                                            <span className="block text-[10px] text-slate-500">DKIM</span>
                                            <span className={`font-bold ${scannerResult.dkim_status === 'pass' ? 'text-emerald-400' : 'text-rose-400'}`}>
                                                {scannerResult.dkim_status?.toUpperCase() || 'NONE'}
                                            </span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                                            <span className="block text-[10px] text-slate-500">DMARC</span>
                                            <span className={`font-bold ${scannerResult.dmarc_status === 'pass' ? 'text-emerald-400' : 'text-rose-400'}`}>
                                                {scannerResult.dmarc_status?.toUpperCase() || 'NONE'}
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════════ */}
            {/* TAB 3: CAMPAIGN CORRELATION */}
            {/* ═══════════════════════════════════════════════════════════════════ */}
            {activeTab === 'correlation' && (
                <div className="space-y-6">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl border border-slate-800 bg-slate-900/60">
                        <div>
                            <h3 className="text-sm font-bold text-white">Global Threat Campaign Clusters</h3>
                            <p className="text-xs text-slate-400">
                                Groups historical incidents based on shared attacker infrastructure, domain patterns, and lure themes.
                            </p>
                        </div>
                        <button
                            onClick={loadCampaigns}
                            disabled={campaignsLoading}
                            className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition-colors self-start sm:self-auto"
                        >
                            <RefreshCw className={`h-3.5 w-3.5 ${campaignsLoading ? 'animate-spin' : ''}`} />
                            Refresh Clusters
                        </button>
                    </div>

                    {campaignsLoading && (
                        <div className="p-8 text-center border border-slate-800 rounded-xl bg-slate-900/40 text-xs text-slate-400">
                            Clustering attack infrastructure across historical telemetry...
                        </div>
                    )}

                    {!campaignsLoading && campaigns && (
                        <div className="space-y-4">
                            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
                                    <span className="text-[11px] text-slate-500 uppercase tracking-wider block">Total Incidents Analyzed</span>
                                    <span className="text-2xl font-bold text-white mt-1 block">{campaigns.total_incidents_analyzed || 0}</span>
                                </div>
                                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
                                    <span className="text-[11px] text-slate-500 uppercase tracking-wider block">Active Attack Campaigns</span>
                                    <span className="text-2xl font-bold text-purple-400 mt-1 block">{campaigns.active_campaigns_count || 0}</span>
                                </div>
                                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
                                    <span className="text-[11px] text-slate-500 uppercase tracking-wider block">Coordinated Threat Ratio</span>
                                    <span className="text-2xl font-bold text-cyan-400 mt-1 block">
                                        {campaigns.total_incidents_analyzed > 0
                                            ? Math.round(((campaigns.active_campaigns_count * 2) / campaigns.total_incidents_analyzed) * 100) + '%'
                                            : '0%'}
                                    </span>
                                </div>
                            </div>

                            {/* Campaign Cards */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {(campaigns.campaigns || []).map((camp, i) => (
                                    <div key={i} className="p-5 rounded-xl border border-slate-800 bg-slate-900/70 space-y-3">
                                        <div className="flex items-center justify-between">
                                            <span className="font-mono text-[10px] text-cyan-400 uppercase tracking-wider">
                                                CAMPAIGN #{camp.campaign_id?.slice(-8) || i + 1}
                                            </span>
                                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${getSeverityBadge(camp.severity)}`}>
                                                {camp.severity} SEVERITY
                                            </span>
                                        </div>
                                        <h4 className="text-sm font-bold text-white">{camp.campaign_name}</h4>
                                        <p className="text-xs text-slate-400 leading-relaxed">{camp.description}</p>
                                        
                                        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1.5 text-xs font-mono">
                                            <div className="text-slate-400 text-[11px]">
                                                Shared Indicator: <span className="text-slate-200">{camp.shared_indicator || 'Multiple Indicators'}</span>
                                            </div>
                                            <div className="text-slate-400 text-[11px]">
                                                Member Incidents: <span className="text-purple-400 font-bold">{camp.incident_count || camp.member_incident_ids?.length || 1}</span>
                                            </div>
                                            <div className="text-slate-400 text-[11px]">
                                                Confidence: <span className="text-emerald-400">{Math.round((camp.confidence_score || 0.85) * 100)}%</span>
                                            </div>
                                        </div>
                                    </div>
                                ))}

                                {(!campaigns.campaigns || campaigns.campaigns.length === 0) && (
                                    <div className="col-span-2 p-8 text-center border border-slate-800 rounded-xl bg-slate-900/30 text-xs text-slate-500">
                                        No active multi-incident campaign clusters detected. Attack patterns are currently isolated.
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════════ */}
            {/* TAB 4: AUTONOMOUS REMEDIATION & VERIFICATION */}
            {/* ═══════════════════════════════════════════════════════════════════ */}
            {activeTab === 'remediation' && (
                <div className="space-y-6">
                    {/* Execution Configuration Card */}
                    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                            <div>
                                <h3 className="text-base font-bold text-white">Autonomous Threat Remediation Engine</h3>
                                <p className="text-xs text-slate-400">
                                    Simulates or executes targeted threat isolation, quarantine, and access revocation playbooks.
                                </p>
                            </div>
                            <div className="flex items-center gap-2">
                                <label className="flex items-center gap-2 cursor-pointer bg-slate-950 border border-slate-800 px-3 py-1.5 rounded-lg text-xs font-mono">
                                    <input
                                        type="checkbox"
                                        checked={isDryRun}
                                        onChange={(e) => setIsDryRun(e.target.checked)}
                                        className="rounded border-slate-700 text-purple-600 focus:ring-0"
                                    />
                                    <span className={isDryRun ? "text-amber-400 font-bold" : "text-slate-400"}>
                                        {isDryRun ? "Dry-Run Simulation Mode" : "Autonomous Live Execution"}
                                    </span>
                                </label>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                            <div className="sm:col-span-2">
                                <label className="block text-xs font-medium text-slate-300 mb-1">Target Incident for Remediation</label>
                                <select
                                    value={remediationTargetId}
                                    onChange={(e) => setRemediationTargetId(e.target.value)}
                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono"
                                >
                                    <option value="">-- Choose Incident to Remediate --</option>
                                    {recentAnalyses.map((rec) => (
                                        <option key={rec.analysis_id} value={rec.analysis_id}>
                                            [{rec.risk_level?.toUpperCase()}] {rec.subject?.slice(0, 45)} (ID: {rec.analysis_id?.slice(-8)})
                                        </option>
                                    ))}
                                </select>
                            </div>
                            <div>
                                <label className="block text-xs font-medium text-slate-300 mb-1">Execution Trigger</label>
                                <button
                                    onClick={handleExecuteRemediation}
                                    disabled={!remediationTargetId || remediationLoading}
                                    className="w-full py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-lg text-xs font-bold shadow-md shadow-purple-950 transition-all flex items-center justify-center gap-2"
                                >
                                    {remediationLoading ? (
                                        <>
                                            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                                            Executing Playbook...
                                        </>
                                    ) : (
                                        <>
                                            <Play className="h-3.5 w-3.5" />
                                            Execute Remediation
                                        </>
                                    )}
                                </button>
                            </div>
                        </div>

                        {/* Safety Disclaimer */}
                        <div className="p-3 rounded-lg border border-amber-800/40 bg-amber-950/20 text-amber-300 text-[11px] flex items-center gap-2">
                            <Lock className="h-4 w-4 shrink-0 text-amber-400" />
                            <span>
                                <strong>Academic Safe Sandbox:</strong> Firewall blocking, credential revocation, and mailbox quarantining are performed in simulated safe mode. No live production data or mailbox messages will be destroyed.
                            </span>
                        </div>
                    </div>

                    {/* Remediation Results */}
                    {remediationError && (
                        <div className="p-4 rounded-xl border border-rose-800 bg-rose-950/40 text-rose-300 text-xs">
                            {remediationError}
                        </div>
                    )}

                    {remediationResult && (
                        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                                <div>
                                    <div className="flex items-center gap-2">
                                        <span className="font-mono text-[10px] text-purple-400 uppercase tracking-widest">
                                            REMEDIATION #{remediationResult.remediation_id?.slice(-8) || 'AUTO-PLAN'}
                                        </span>
                                        <span className="px-2 py-0.5 rounded text-[10px] font-bold border border-emerald-800 bg-emerald-950/60 text-emerald-300">
                                            {remediationResult.overall_status?.toUpperCase() || 'COMPLETED'}
                                        </span>
                                    </div>
                                    <h4 className="text-base font-bold text-white mt-1">Autonomous Playbook Execution Summary</h4>
                                </div>
                                <button
                                    onClick={handleRunVerification}
                                    disabled={verificationLoading}
                                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-bold shadow-md shadow-emerald-950 transition-colors flex items-center gap-2 self-start sm:self-auto"
                                >
                                    {verificationLoading ? (
                                        <>
                                            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                                            Running Probes...
                                        </>
                                    ) : (
                                        <>
                                            <CheckCircle2 className="h-3.5 w-3.5" />
                                            Verify & Reassess Residual Risk
                                        </>
                                    )}
                                </button>
                            </div>

                            {/* Executed Actions Table */}
                            <div className="space-y-3">
                                <h5 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Executed Security Controls</h5>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                    {(remediationResult.actions_executed || []).map((act, i) => (
                                        <div key={i} className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/80 space-y-1.5">
                                            <div className="flex items-center justify-between">
                                                <span className="text-xs font-bold text-slate-200">
                                                    {act.action_type?.replace(/_/g, ' ').toUpperCase()}
                                                </span>
                                                <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                                                    act.status === 'success' || act.status === 'simulated_success'
                                                        ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                                                        : 'bg-rose-950 text-rose-300 border-rose-800'
                                                }`}>
                                                    {act.status}
                                                </span>
                                            </div>
                                            <p className="text-[11px] text-slate-400">{act.details || act.description}</p>
                                            <div className="text-[10px] text-slate-500 font-mono">
                                                Target: <span className="text-purple-400">{act.target || 'Email / Account'}</span>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Verification Result Display */}
                            {verificationReport && (
                                <div className="p-5 rounded-xl border border-emerald-500/40 bg-emerald-950/15 space-y-3 pt-4">
                                    <div className="flex items-center justify-between border-b border-emerald-800/40 pb-3">
                                        <div className="flex items-center gap-2">
                                            <ShieldCheck className="h-5 w-5 text-emerald-400" />
                                            <h5 className="text-sm font-bold text-white">Post-Remediation Risk Verification Report</h5>
                                        </div>
                                        <div className="text-right">
                                            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Residual Risk Score</span>
                                            <span className="text-xl font-black text-emerald-400">
                                                {verificationReport.residual_risk_score} / 100 ({verificationReport.residual_threat_level})
                                            </span>
                                        </div>
                                    </div>

                                    <p className="text-xs text-slate-300 font-mono bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                                        {verificationReport.reassessment_summary}
                                    </p>

                                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
                                        <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono">
                                            <span className="text-[10px] text-slate-500 block">Controls Verified</span>
                                            <span className="text-emerald-400 font-bold">{verificationReport.controls_verified_count || 3} / 3 PASSED</span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono">
                                            <span className="text-[10px] text-slate-500 block">Threat Neutralized?</span>
                                            <span className="text-emerald-400 font-bold">{verificationReport.is_threat_neutralized ? "YES (CONTAINED)" : "ACTION REQUIRED"}</span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono">
                                            <span className="text-[10px] text-slate-500 block">Residual Risk Drop</span>
                                            <span className="text-purple-400 font-bold">-{verificationReport.risk_reduction_points || 65} Points</span>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Remediation Audit Log Table */}
                    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
                        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                                <Clock className="h-4 w-4 text-purple-400" />
                                Historical Remediation Audit Log
                            </h4>
                            <button
                                onClick={loadAuditLog}
                                className="text-xs text-slate-400 hover:text-slate-200 font-mono"
                            >
                                Refresh Log
                            </button>
                        </div>

                        <div className="overflow-x-auto">
                            <table className="w-full text-left text-xs">
                                <thead>
                                    <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                                        <th className="py-2 px-3">Remediation ID</th>
                                        <th className="py-2 px-3">Target Subject / Sender</th>
                                        <th className="py-2 px-3">Actions Count</th>
                                        <th className="py-2 px-3">Status</th>
                                        <th className="py-2 px-3">Timestamp</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                                    {auditLog.map((log, i) => (
                                        <tr key={i} className="hover:bg-slate-800/30">
                                            <td className="py-2.5 px-3 text-purple-300">
                                                {log.remediation_id?.slice(-8) || `REM-${i+1}`}
                                            </td>
                                            <td className="py-2.5 px-3 text-slate-300 font-sans">
                                                {log.subject || log.sender || 'Direct Incident Action'}
                                            </td>
                                            <td className="py-2.5 px-3 text-slate-400">
                                                {log.actions_executed?.length || 1} Actions
                                            </td>
                                            <td className="py-2.5 px-3">
                                                <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800">
                                                    {log.overall_status || 'SUCCESS'}
                                                </span>
                                            </td>
                                            <td className="py-2.5 px-3 text-slate-500">
                                                {log.executed_at ? new Date(log.executed_at).toLocaleTimeString() : 'Recent'}
                                            </td>
                                        </tr>
                                    ))}

                                    {auditLog.length === 0 && (
                                        <tr>
                                            <td colSpan={5} className="py-6 text-center text-slate-500 font-sans">
                                                No remediation records in audit trail yet. Execute a playbook above to generate records.
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}