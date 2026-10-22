import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
    ShieldAlert,
    Search,
    Radio,
    Terminal,
    GraduationCap,
    ArrowRight,
    ShieldCheck,
    Zap,
    Lock,
    Activity,
    AlertTriangle,
    CheckCircle2,
    Layers,
    Bell,
    Clock,
    Flame,
    FileText,
    ChevronRight,
    CircleDot
} from 'lucide-react';
import {
    getMonitoringStatus,
    detectAllCampaigns,
    getAnalysesHistory,
    getNotifications,
    getGmailStatus
} from '../services/api';

export default function Dashboard() {
    const [monitoringStatus, setMonitoringStatus] = useState(null);
    const [campaigns, setCampaigns] = useState(null);
    const [recentAnalyses, setRecentAnalyses] = useState([]);
    const [recentAlerts, setRecentAlerts] = useState([]);
    const [gmailAccount, setGmailAccount] = useState({ connected: false });
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchDashboardData = async () => {
            try {
                const [mon, camp, hist, notifs, gmail] = await Promise.allSettled([
                    getMonitoringStatus(),
                    detectAllCampaigns(),
                    getAnalysesHistory(5),
                    getNotifications(null, false),
                    getGmailStatus()
                ]);

                if (mon.status === 'fulfilled') setMonitoringStatus(mon.value);
                if (camp.status === 'fulfilled') setCampaigns(camp.value);
                if (hist.status === 'fulfilled') setRecentAnalyses(hist.value?.analyses || []);
                if (notifs.status === 'fulfilled') setRecentAlerts(notifs.value?.notifications?.slice(0, 3) || []);
                if (gmail.status === 'fulfilled') setGmailAccount(gmail.value || { connected: false });
            } finally {
                setLoading(false);
            }
        };

        fetchDashboardData();
        const interval = setInterval(fetchDashboardData, 10000);
        return () => clearInterval(interval);
    }, []);

    // 8-Stage Unified Threat Flow Pipeline
    const PIPELINE_STAGES = [
        {
            step: "01",
            title: "Continuous Ingestion",
            desc: "24/7 Watchdog polling on Gmail OAuth or simulated inbox.",
            to: "/monitoring",
            badge: "Ingest"
        },
        {
            step: "02",
            title: "Multi-Vector Detection",
            desc: "Analyzes content, sender, URLs, headers, and attachments.",
            to: "/analyzer",
            badge: "Detect"
        },
        {
            step: "03",
            title: "Forensic Dossier",
            desc: "MITRE ATT&CK mapping, Kill Chain, and evidence breakdown.",
            to: "/investigation?tab=dossier",
            badge: "Investigate"
        },
        {
            step: "04",
            title: "Threat Correlation",
            desc: "Clusters related incidents into global attack campaigns.",
            to: "/investigation?tab=correlation",
            badge: "Correlate"
        },
        {
            step: "05",
            title: "Autonomous Remediation",
            desc: "Zero-touch simulated quarantine, domain & sender blocks.",
            to: "/investigation?tab=remediation",
            badge: "Remediate"
        },
        {
            step: "06",
            title: "Post-Action Verification",
            desc: "Active re-probing and residual risk score recalculation.",
            to: "/investigation?tab=remediation",
            badge: "Verify"
        },
        {
            step: "07",
            title: "Incident Notifications",
            desc: "Automated plain-language employee alerts and SOC advisories.",
            to: "/monitoring",
            badge: "Notify"
        },
        {
            step: "08",
            title: "Adaptive Training",
            desc: "Curriculum modules and scenario-based defense quizzes.",
            to: "/training",
            badge: "Harden"
        }
    ];

    const isWatchdogRunning = monitoringStatus?.is_running || false;

    return (
        <div className="space-y-8">

            {/* ── Hero Section ── */}
            <div className="relative rounded-2xl border border-slate-800 bg-gradient-to-br from-slate-900 via-slate-900/70 to-slate-950 p-6 sm:p-8 overflow-hidden">
                <div className="absolute right-0 top-0 translate-x-12 -translate-y-12 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

                <div className="relative z-10 max-w-4xl space-y-4">
                    <div className="flex flex-wrap items-center gap-2">
                        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono bg-cyan-950/80 text-cyan-400 border border-cyan-800">
                            <Zap className="h-3.5 w-3.5" />
                            <span>CyberShield SOC Orchestrator Active</span>
                        </div>

                        <div className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono border ${
                            isWatchdogRunning
                                ? 'bg-emerald-950/80 text-emerald-400 border-emerald-800'
                                : 'bg-slate-900 text-slate-400 border-slate-700'
                        }`}>
                            <CircleDot className={`h-3 w-3 ${isWatchdogRunning ? 'animate-pulse text-emerald-400' : 'text-slate-500'}`} />
                            <span>Watchdog: {isWatchdogRunning ? 'Running' : 'Standby'}</span>
                        </div>

                        {gmailAccount?.connected && (
                            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono bg-blue-950/80 text-blue-300 border border-blue-800">
                                <span>Gmail: {gmailAccount.email}</span>
                            </div>
                        )}
                    </div>

                    <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
                        Autonomous Cyber Threat Detection & <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">Self-Healing SOC Platform</span>
                    </h1>

                    <p className="text-xs sm:text-sm text-slate-400 leading-relaxed max-w-3xl">
                        An end-to-end security operations suite combining 5-vector email inspection, MITRE ATT&CK kill-chain forensics,
                        automated campaign correlation, zero-touch remediation playbooks, continuous mailbox monitoring, and interactive human awareness training.
                    </p>

                    <div className="flex flex-wrap gap-3 pt-2">
                        <Link
                            to="/analyzer"
                            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-950 transition-all"
                        >
                            <Search className="h-4 w-4" />
                            <span>Analyze Email</span>
                            <ArrowRight className="h-3.5 w-3.5" />
                        </Link>

                        <Link
                            to="/investigation"
                            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs border border-slate-700 transition-all"
                        >
                            <Terminal className="h-4 w-4 text-purple-400" />
                            <span>Threat Investigation Center</span>
                        </Link>

                        <Link
                            to="/monitoring"
                            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs border border-slate-700 transition-all"
                        >
                            <Radio className="h-4 w-4 text-emerald-400" />
                            <span>24/7 Watchdog</span>
                        </Link>
                    </div>
                </div>
            </div>

            {/* ── SOC Telemetry Metric Counters ── */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                    <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Total Scanned</span>
                        <Search className="h-4 w-4 text-cyan-400" />
                    </div>
                    <span className="text-2xl sm:text-3xl font-extrabold font-mono text-white mt-1 block">
                        {(monitoringStatus?.total_emails_scanned || 0) + (recentAnalyses?.length || 0)}
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">Deduplicated messages</span>
                </div>

                <div className="rounded-xl border border-rose-900/30 bg-rose-950/10 p-4">
                    <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-rose-400">Threats Neutralized</span>
                        <ShieldAlert className="h-4 w-4 text-rose-400" />
                    </div>
                    <span className="text-2xl sm:text-3xl font-extrabold font-mono text-rose-400 mt-1 block">
                        {monitoringStatus?.remediations_triggered ?? 0}
                    </span>
                    <span className="text-[10px] text-rose-400/60 font-mono">Autonomous playbooks</span>
                </div>

                <div className="rounded-xl border border-purple-900/30 bg-purple-950/10 p-4">
                    <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-purple-400">Active Campaigns</span>
                        <Layers className="h-4 w-4 text-purple-400" />
                    </div>
                    <span className="text-2xl sm:text-3xl font-extrabold font-mono text-purple-300 mt-1 block">
                        {campaigns?.total_campaigns ?? 0}
                    </span>
                    <span className="text-[10px] text-purple-400/60 font-mono">Correlated clusters</span>
                </div>

                <div className="rounded-xl border border-emerald-900/30 bg-emerald-950/10 p-4">
                    <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400">Watchdog Cycles</span>
                        <Radio className="h-4 w-4 text-emerald-400" />
                    </div>
                    <span className="text-2xl sm:text-3xl font-extrabold font-mono text-emerald-400 mt-1 block">
                        {monitoringStatus?.total_cycles_completed ?? 0}
                    </span>
                    <span className="text-[10px] text-emerald-400/60 font-mono">Background loops</span>
                </div>
            </div>

            {/* ── 8-Stage Unified Threat Flow Pipeline Visualizer ── */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-5">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-slate-800 pb-3">
                    <div>
                        <h2 className="text-base font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                            <ShieldCheck className="h-5 w-5 text-cyan-400" />
                            <span>CyberShield End-to-End Threat Pipeline</span>
                        </h2>
                        <p className="text-xs text-slate-400 mt-0.5">
                            Unified lifecycle: ingestion &rarr; multi-vector detection &rarr; forensics &rarr; correlation &rarr; remediation &rarr; verification &rarr; alert &rarr; training.
                        </p>
                    </div>

                    <span className="text-[10px] font-mono text-slate-500 uppercase">
                        Click any stage to inspect
                    </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                    {PIPELINE_STAGES.map((s) => (
                        <Link
                            key={s.step}
                            to={s.to}
                            className="group p-4 rounded-xl border border-slate-800 bg-slate-950 hover:border-cyan-500/50 hover:bg-slate-900/90 transition-all block relative"
                        >
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-xs font-mono font-extrabold text-cyan-400">
                                    {s.step}
                                </span>
                                <span className="text-[9px] font-mono uppercase px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-700 group-hover:border-cyan-500/40">
                                    {s.badge}
                                </span>
                            </div>

                            <h3 className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors">
                                {s.title}
                            </h3>

                            <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                                {s.desc}
                            </p>

                            <div className="mt-3 flex items-center gap-1 text-[10px] font-mono text-cyan-400 group-hover:translate-x-1 transition-transform">
                                <span>Open Stage</span>
                                <ChevronRight className="h-3 w-3" />
                            </div>
                        </Link>
                    ))}
                </div>
            </div>

            {/* ── Two-Column SOC Dashboard Widgets ── */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

                {/* Left Widget: Recent Threat Incidents Feed */}
                <div className="lg:col-span-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                        <div className="flex items-center gap-2">
                            <Clock className="h-4 w-4 text-cyan-400" />
                            <h3 className="text-xs font-mono uppercase tracking-wider text-white font-bold">
                                Recent Threat Incidents
                            </h3>
                        </div>
                        <Link to="/analyzer" className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300">
                            Scan New &rarr;
                        </Link>
                    </div>

                    {recentAnalyses.length === 0 ? (
                        <div className="py-8 text-center text-slate-500 font-mono text-xs">
                            No stored analyses found. Run an inspection in the Email Analyzer to populate this feed.
                        </div>
                    ) : (
                        <div className="space-y-2.5">
                            {recentAnalyses.map((item) => (
                                <div
                                    key={item.id}
                                    className="p-3 rounded-xl border border-slate-800 bg-slate-950 flex items-center justify-between text-xs"
                                >
                                    <div className="min-w-0 pr-2">
                                        <div className="flex items-center gap-2">
                                            <span className="text-[10px] font-mono text-cyan-300 truncate font-semibold">
                                                {item.sender}
                                            </span>
                                            <span className="text-[10px] font-mono text-slate-500">
                                                {new Date(item.created_at).toLocaleDateString()}
                                            </span>
                                        </div>
                                        <p className="text-slate-300 font-medium truncate mt-0.5">
                                            {item.subject || '(No Subject)'}
                                        </p>
                                    </div>

                                    <div className="flex items-center gap-2 flex-shrink-0">
                                        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                                            item.risk_score >= 80
                                                ? 'bg-rose-950 text-rose-300 border-rose-800'
                                                : item.risk_score >= 60
                                                ? 'bg-amber-950 text-amber-300 border-amber-800'
                                                : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                                        }`}>
                                            Risk: {item.risk_score}
                                        </span>

                                        <Link
                                            to={`/investigation?tab=dossier&analysisId=${item.id}`}
                                            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700"
                                            title="View Forensic Dossier"
                                        >
                                            <Terminal className="h-3.5 w-3.5" />
                                        </Link>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Right Widget: Active Campaign Clusters & Alerts */}
                <div className="lg:col-span-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                        <div className="flex items-center gap-2">
                            <Layers className="h-4 w-4 text-purple-400" />
                            <h3 className="text-xs font-mono uppercase tracking-wider text-white font-bold">
                                Campaign Clusters ({campaigns?.total_campaigns ?? 0})
                            </h3>
                        </div>
                        <Link to="/investigation?tab=correlation" className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300">
                            Full Matrix &rarr;
                        </Link>
                    </div>

                    {campaigns?.campaigns && campaigns.campaigns.length > 0 ? (
                        <div className="space-y-2.5">
                            {campaigns.campaigns.slice(0, 3).map((camp) => (
                                <div
                                    key={camp.campaign_id}
                                    className="p-3 rounded-xl border border-purple-900/40 bg-purple-950/15 space-y-2"
                                >
                                    <div className="flex items-center justify-between text-xs">
                                        <span className="font-bold text-white font-mono">{camp.campaign_name}</span>
                                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
                                            {camp.incident_count} Incidents Correlated
                                        </span>
                                    </div>
                                    <p className="text-[11px] text-slate-300 leading-relaxed">
                                        {camp.narrative_summary}
                                    </p>
                                    <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400">
                                        <span>Primary Vector: <strong className="text-cyan-300">{camp.primary_vector}</strong></span>
                                        <span>•</span>
                                        <span>Confidence: <strong className="text-emerald-400">{camp.confidence_score}%</strong></span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="py-8 text-center text-slate-500 font-mono text-xs">
                            No campaigns detected yet. The correlation engine runs automatically as new incidents arrive.
                        </div>
                    )}

                    {/* Quick Link to Notifications */}
                    <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                        <span className="text-slate-400 flex items-center gap-1.5">
                            <Bell className="h-3.5 w-3.5 text-cyan-400" />
                            <span>Recent Alerts: {recentAlerts.length} logged</span>
                        </span>
                        <Link to="/monitoring" className="text-cyan-400 hover:text-cyan-300">
                            View Alerts Center &rarr;
                        </Link>
                    </div>
                </div>

            </div>

        </div>
    );
}