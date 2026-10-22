import React, { useState, useEffect, useRef } from 'react';
import {
    Radio,
    Play,
    Square,
    RefreshCw,
    ShieldAlert,
    ShieldCheck,
    AlertTriangle,
    Bell,
    CheckCircle2,
    Clock,
    Activity,
    Sliders,
    Zap,
    Mail,
    Trash2,
    Eye,
    ChevronDown,
    ChevronUp,
    ExternalLink,
    Filter,
    Inbox,
    Flame
} from 'lucide-react';
import {
    getMonitoringStatus,
    startMonitoring,
    stopMonitoring,
    pollNow,
    getMonitoringEvents,
    resetMonitoringCache,
    getNotifications,
    markNotificationRead,
    getGmailStatus
} from '../services/api';
import { Link } from 'react-router-dom';

export default function Monitoring() {
    // ── Monitoring State ──
    const [status, setStatus] = useState(null);
    const [loading, setLoading] = useState(true);
    const [actionLoading, setActionLoading] = useState(false);
    const [pollResult, setPollResult] = useState(null);
    const [error, setError] = useState(null);

    // Config options for starting monitoring
    const [pollInterval, setPollInterval] = useState(15);
    const [autoRemediate, setAutoRemediate] = useState(true);
    const [provider, setProvider] = useState('simulated');
    const [gmailConnected, setGmailConnected] = useState(false);
    const [gmailEmail, setGmailEmail] = useState(null);

    // ── Telemetry Events State ──
    const [events, setEvents] = useState([]);
    const [eventsFilter, setEventsFilter] = useState('all'); // 'all' | 'threats' | 'cycles'
    const [expandedEventId, setExpandedEventId] = useState(null);

    // ── Notifications State ──
    const [notifications, setNotifications] = useState([]);
    const [unreadCount, setUnreadCount] = useState(0);
    const [notifFilter, setNotifFilter] = useState('all'); // 'all' | 'unread' | 'user' | 'admin'
    const [notifsLoading, setNotifsLoading] = useState(false);

    // Active sub-view tab
    const [activeTab, setActiveTab] = useState('telemetry'); // 'telemetry' | 'notifications'

    // Polling timer reference
    const refreshIntervalRef = useRef(null);

    // ── Initial Load & Auto-Refresh Setup ──
    const fetchStatusAndEvents = async () => {
        try {
            const [statusData, eventsData] = await Promise.all([
                getMonitoringStatus(),
                getMonitoringEvents(40)
            ]);
            setStatus(statusData);
            setEvents(eventsData || []);
        } catch (err) {
            console.error('Failed to fetch monitoring telemetry:', err);
        }
    };

    const fetchAlerts = async () => {
        setNotifsLoading(true);
        try {
            const data = await getNotifications();
            setNotifications(data.notifications || []);
            setUnreadCount(data.unread_count || 0);
        } catch (err) {
            console.error('Failed to fetch notifications:', err);
        } finally {
            setNotifsLoading(false);
        }
    };

    useEffect(() => {
        const init = async () => {
            setLoading(true);
            try {
                const [gmailStat] = await Promise.all([
                    getGmailStatus().catch(() => ({ connected: false })),
                    fetchStatusAndEvents(),
                    fetchAlerts()
                ]);
                if (gmailStat && gmailStat.connected) {
                    setGmailConnected(true);
                    setGmailEmail(gmailStat.email);
                }
            } finally {
                setLoading(false);
            }
        };

        init();

        // 5-second polling interval for live SOC telemetry updates
        refreshIntervalRef.current = setInterval(() => {
            fetchStatusAndEvents();
            fetchAlerts();
        }, 5000);

        return () => {
            if (refreshIntervalRef.current) clearInterval(refreshIntervalRef.current);
        };
    }, []);

    // ── Monitoring Handlers ──
    const handleStartMonitoring = async () => {
        setActionLoading(true);
        setError(null);
        try {
            await startMonitoring(pollInterval, autoRemediate, provider);
            await fetchStatusAndEvents();
        } catch (err) {
            setError(err.response?.data?.detail || err.message || 'Failed to start monitoring engine.');
        } finally {
            setActionLoading(false);
        }
    };

    const handleStopMonitoring = async () => {
        setActionLoading(true);
        setError(null);
        try {
            await stopMonitoring();
            await fetchStatusAndEvents();
        } catch (err) {
            setError(err.response?.data?.detail || err.message || 'Failed to stop monitoring engine.');
        } finally {
            setActionLoading(false);
        }
    };

    const handlePollNow = async () => {
        setActionLoading(true);
        setError(null);
        setPollResult(null);
        try {
            const result = await pollNow();
            setPollResult(result);
            await fetchStatusAndEvents();
            await fetchAlerts();
        } catch (err) {
            setError(err.response?.data?.detail || err.message || 'Manual evaluation cycle failed.');
        } finally {
            setActionLoading(false);
        }
    };

    const handleResetCache = async () => {
        setActionLoading(true);
        setError(null);
        try {
            await resetMonitoringCache();
            await fetchStatusAndEvents();
        } catch (err) {
            setError(err.response?.data?.detail || err.message || 'Failed to reset deduplication cache.');
        } finally {
            setActionLoading(false);
        }
    };

    const handleMarkAsRead = async (id) => {
        try {
            await markNotificationRead(id);
            setNotifications(prev =>
                prev.map(n => n.notification_id === id ? { ...n, is_read: true } : n)
            );
            setUnreadCount(prev => Math.max(0, prev - 1));
        } catch (err) {
            console.error('Failed to mark notification read:', err);
        }
    };

    // Filter events
    const filteredEvents = events.filter(e => {
        if (eventsFilter === 'threats') {
            return e.event_type.includes('threat') || e.event_type.includes('remediation');
        }
        if (eventsFilter === 'cycles') {
            return e.event_type.includes('cycle');
        }
        return true;
    });

    // Filter notifications
    const filteredNotifications = notifications.filter(n => {
        if (notifFilter === 'unread') return !n.is_read;
        if (notifFilter === 'user') return n.recipient_type === 'user';
        if (notifFilter === 'admin') return n.recipient_type === 'admin';
        return true;
    });

    const isRunning = status?.is_running || false;

    return (
        <div className="space-y-6">

            {/* ── Page Header ── */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
                <div>
                    <div className="flex items-center gap-2.5">
                        <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/30">
                            <Radio className={`h-6 w-6 ${isRunning ? 'text-emerald-400 animate-pulse' : 'text-slate-400'}`} />
                        </div>
                        <div>
                            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2">
                                24/7 Watchdog Monitoring
                                <span className={`text-xs font-mono uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${
                                    isRunning
                                        ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                                        : 'bg-slate-900 text-slate-400 border-slate-700'
                                }`}>
                                    {isRunning ? 'Engine Active' : 'Engine Idle'}
                                </span>
                            </h1>
                            <p className="text-xs text-slate-400 mt-0.5 font-mono">
                                Continuous Mailbox Telemetry • Autonomous Threat Neutralization • SOC Notification Dispatch
                            </p>
                        </div>
                    </div>
                </div>

                {/* Sub-view Navigation Tabs */}
                <div className="flex items-center gap-2 bg-slate-950 p-1 rounded-xl border border-slate-800">
                    <button
                        onClick={() => setActiveTab('telemetry')}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                            activeTab === 'telemetry'
                                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                                : 'text-slate-400 hover:text-slate-200'
                        }`}
                    >
                        <Activity className="h-3.5 w-3.5" />
                        <span>Telemetry & Controls</span>
                    </button>

                    <button
                        onClick={() => setActiveTab('notifications')}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all relative ${
                            activeTab === 'notifications'
                                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                                : 'text-slate-400 hover:text-slate-200'
                        }`}
                    >
                        <Bell className="h-3.5 w-3.5" />
                        <span>Notification Center</span>
                        {unreadCount > 0 && (
                            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-rose-500 text-white font-bold animate-pulse">
                                {unreadCount}
                            </span>
                        )}
                    </button>
                </div>
            </div>

            {/* Error Banner */}
            {error && (
                <div className="rounded-xl bg-rose-950/40 border border-rose-800/60 p-4 text-xs text-rose-300 flex items-start gap-2.5">
                    <AlertTriangle className="h-4 w-4 text-rose-400 flex-shrink-0 mt-0.5" />
                    <span>{error}</span>
                </div>
            )}

            {/* ═══ TAB 1: TELEMETRY & CONTROLS ═══ */}
            {activeTab === 'telemetry' && (
                <div className="space-y-6">

                    {/* Operational Telemetry Cards */}
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3.5">
                            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">Total Cycles</span>
                            <span className="text-2xl font-extrabold font-mono text-white mt-1 block">
                                {status?.total_cycles_completed ?? 0}
                            </span>
                            <span className="text-[10px] text-slate-500 font-mono">Loop iterations</span>
                        </div>

                        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3.5">
                            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">Emails Scanned</span>
                            <span className="text-2xl font-extrabold font-mono text-cyan-400 mt-1 block">
                                {status?.total_emails_scanned ?? 0}
                            </span>
                            <span className="text-[10px] text-slate-500 font-mono">Deduplicated</span>
                        </div>

                        <div className="rounded-xl border border-rose-900/30 bg-rose-950/10 p-3.5">
                            <span className="text-[10px] font-mono uppercase tracking-wider text-rose-400 block">Threats Found</span>
                            <span className="text-2xl font-extrabold font-mono text-rose-400 mt-1 block">
                                {status?.threats_detected ?? 0}
                            </span>
                            <span className="text-[10px] text-rose-400/60 font-mono">Score &ge; 60</span>
                        </div>

                        <div className="rounded-xl border border-emerald-900/30 bg-emerald-950/10 p-3.5">
                            <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 block">Neutralized</span>
                            <span className="text-2xl font-extrabold font-mono text-emerald-400 mt-1 block">
                                {status?.remediations_triggered ?? 0}
                            </span>
                            <span className="text-[10px] text-emerald-400/60 font-mono">Auto-Quarantine</span>
                        </div>

                        <div className="rounded-xl border border-purple-900/30 bg-purple-950/10 p-3.5 col-span-2 sm:col-span-1">
                            <span className="text-[10px] font-mono uppercase tracking-wider text-purple-400 block">Alerts Dispatched</span>
                            <span className="text-2xl font-extrabold font-mono text-purple-300 mt-1 block">
                                {status?.notifications_dispatched ?? 0}
                            </span>
                            <span className="text-[10px] text-purple-400/60 font-mono">User + SOC</span>
                        </div>
                    </div>

                    {/* Engine Control & Configuration Dashboard */}
                    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-800/80 pb-3">
                            <div className="flex items-center gap-2">
                                <Sliders className="h-4 w-4 text-cyan-400" />
                                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                                    Watchdog Operations Controller
                                </h3>
                            </div>
                            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                                <Clock className="h-3.5 w-3.5 text-slate-500" />
                                <span>Last Loop: {status?.last_poll_time ? new Date(status.last_poll_time).toLocaleTimeString() : 'Awaiting start'}</span>
                            </div>
                        </div>

                        {/* Controls Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            {/* Option 1: Provider selection */}
                            <div className="rounded-xl bg-slate-950 border border-slate-800 p-3.5 space-y-2">
                                <label className="block text-[11px] font-mono font-semibold text-slate-300 uppercase">
                                    Monitored Mailbox Provider
                                </label>
                                <select
                                    disabled={isRunning}
                                    value={provider}
                                    onChange={(e) => setProvider(e.target.value)}
                                    className="w-full text-xs font-mono px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 disabled:opacity-60"
                                >
                                    <option value="simulated">Demo Inbox (Simulated Safe Stream)</option>
                                    <option value="gmail" disabled={!gmailConnected}>
                                        {gmailConnected ? `Gmail OAuth (${gmailEmail || 'Connected'})` : 'Gmail OAuth (Not Connected)'}
                                    </option>
                                </select>
                                <p className="text-[10px] text-slate-500">
                                    {provider === 'gmail'
                                        ? 'Monitors real Gmail messages via readonly OAuth API.'
                                        : 'Monitors academic simulated inbox containing real phishing & benign test sets.'}
                                </p>
                            </div>

                            {/* Option 2: Poll Frequency */}
                            <div className="rounded-xl bg-slate-950 border border-slate-800 p-3.5 space-y-2">
                                <div className="flex items-center justify-between">
                                    <label className="text-[11px] font-mono font-semibold text-slate-300 uppercase">
                                        Polling Frequency
                                    </label>
                                    <span className="text-xs font-mono font-bold text-cyan-400">{pollInterval}s</span>
                                </div>
                                <select
                                    disabled={isRunning}
                                    value={pollInterval}
                                    onChange={(e) => setPollInterval(Number(e.target.value))}
                                    className="w-full text-xs font-mono px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 disabled:opacity-60"
                                >
                                    <option value={5}>Every 5 Seconds (Rapid Lab Demo)</option>
                                    <option value={15}>Every 15 Seconds (Standard SOC)</option>
                                    <option value={30}>Every 30 Seconds</option>
                                    <option value={60}>Every 60 Seconds</option>
                                </select>
                                <p className="text-[10px] text-slate-500">
                                    Interval between asynchronous inbox evaluation passes.
                                </p>
                            </div>

                            {/* Option 3: Auto-Remediation policy */}
                            <div className="rounded-xl bg-slate-950 border border-slate-800 p-3.5 space-y-2">
                                <label className="block text-[11px] font-mono font-semibold text-slate-300 uppercase">
                                    Autonomous Action Policy
                                </label>
                                <div className="flex items-center justify-between pt-1">
                                    <span className="text-xs text-slate-300 font-mono">Zero-Touch Remediation</span>
                                    <button
                                        type="button"
                                        disabled={isRunning}
                                        onClick={() => setAutoRemediate(!autoRemediate)}
                                        className={`w-11 h-6 rounded-full transition-colors relative flex items-center p-0.5 ${
                                            autoRemediate ? 'bg-emerald-600' : 'bg-slate-700'
                                        } disabled:opacity-50`}
                                    >
                                        <div className={`w-5 h-5 rounded-full bg-white transition-transform ${
                                            autoRemediate ? 'translate-x-5' : 'translate-x-0'
                                        }`} />
                                    </button>
                                </div>
                                <p className="text-[10px] text-slate-500">
                                    Automatically triggers quarantine, domain blocking, and alert dispatch on high-risk emails.
                                </p>
                            </div>
                        </div>

                        {/* Action Buttons Toolbar */}
                        <div className="flex flex-wrap items-center gap-2.5 pt-2 border-t border-slate-800/60">
                            {!isRunning ? (
                                <button
                                    onClick={handleStartMonitoring}
                                    disabled={actionLoading}
                                    className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow-md shadow-emerald-950 transition-all disabled:opacity-50"
                                >
                                    <Play className="h-4 w-4 fill-white" />
                                    <span>Start 24/7 Watchdog</span>
                                </button>
                            ) : (
                                <button
                                    onClick={handleStopMonitoring}
                                    disabled={actionLoading}
                                    className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs shadow-md shadow-rose-950 transition-all disabled:opacity-50"
                                >
                                    <Square className="h-4 w-4 fill-white" />
                                    <span>Stop Watchdog Worker</span>
                                </button>
                            )}

                            <button
                                onClick={handlePollNow}
                                disabled={actionLoading}
                                className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs shadow-md shadow-cyan-950 transition-all disabled:opacity-50"
                            >
                                <Zap className="h-4 w-4" />
                                <span>Poll Now (Immediate Cycle)</span>
                            </button>

                            <button
                                onClick={handleResetCache}
                                disabled={actionLoading}
                                className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold text-xs border border-slate-700 transition-all disabled:opacity-50"
                                title="Clears processed message hashes so inbox can be rescanned"
                            >
                                <RefreshCw className={`h-3.5 w-3.5 ${actionLoading ? 'animate-spin' : ''}`} />
                                <span>Reset Dedup Cache</span>
                            </button>
                        </div>
                    </div>

                    {/* Immediate Poll Result Card (if triggered) */}
                    {pollResult && (
                        <div className="rounded-xl border border-cyan-500/30 bg-slate-900/90 p-4 space-y-3">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    <CheckCircle2 className="h-4 w-4 text-cyan-400" />
                                    <h4 className="text-xs font-bold text-white font-mono uppercase tracking-wider">
                                        Immediate Evaluation Pass Completed ({pollResult.cycle_id})
                                    </h4>
                                </div>
                                <span className="text-[10px] font-mono text-slate-400">
                                    {new Date(pollResult.completed_at).toLocaleTimeString()}
                                </span>
                            </div>

                            <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
                                <div className="bg-slate-950 p-2 rounded border border-slate-800">
                                    <span className="text-[10px] text-slate-500 block">Evaluated</span>
                                    <span className="text-sm font-bold text-slate-200">{pollResult.emails_evaluated}</span>
                                </div>
                                <div className="bg-slate-950 p-2 rounded border border-slate-800">
                                    <span className="text-[10px] text-slate-500 block">New Threats</span>
                                    <span className="text-sm font-bold text-rose-400">{pollResult.new_threats_found}</span>
                                </div>
                                <div className="bg-slate-950 p-2 rounded border border-slate-800">
                                    <span className="text-[10px] text-slate-500 block">Remediations</span>
                                    <span className="text-sm font-bold text-emerald-400">{pollResult.remediations_executed}</span>
                                </div>
                            </div>

                            {pollResult.details && pollResult.details.length > 0 && (
                                <div className="space-y-1.5 pt-2">
                                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Cycle Highlights:</span>
                                    {pollResult.details.map((d, i) => (
                                        <div key={i} className="text-[11px] font-mono p-2 rounded bg-slate-950 border border-slate-800/80 flex items-center justify-between">
                                            <span className="text-slate-300 truncate max-w-md">{d.subject || d.message_id}</span>
                                            <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                                                d.action === 'remediated'
                                                    ? 'bg-rose-950 text-rose-400 border border-rose-800'
                                                    : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                            }`}>
                                                {d.action || 'clean'} (Risk: {d.risk_score ?? 0})
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    )}

                    {/* Real-time Telemetry Event Feed */}
                    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-800/80 pb-3">
                            <div className="flex items-center gap-2">
                                <Activity className="h-4 w-4 text-cyan-400" />
                                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                                    Live SOC Telemetry Stream ({filteredEvents.length})
                                </h3>
                            </div>

                            {/* Event Filter Pills */}
                            <div className="flex items-center gap-1.5 text-xs">
                                <button
                                    onClick={() => setEventsFilter('all')}
                                    className={`px-2.5 py-1 rounded-lg font-mono text-[11px] transition-all ${
                                        eventsFilter === 'all'
                                            ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                                            : 'text-slate-400 hover:text-slate-200'
                                    }`}
                                >
                                    All Events
                                </button>
                                <button
                                    onClick={() => setEventsFilter('threats')}
                                    className={`px-2.5 py-1 rounded-lg font-mono text-[11px] transition-all ${
                                        eventsFilter === 'threats'
                                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                                            : 'text-slate-400 hover:text-slate-200'
                                    }`}
                                >
                                    Threats & Neutralizations
                                </button>
                                <button
                                    onClick={() => setEventsFilter('cycles')}
                                    className={`px-2.5 py-1 rounded-lg font-mono text-[11px] transition-all ${
                                        eventsFilter === 'cycles'
                                            ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                                            : 'text-slate-400 hover:text-slate-200'
                                    }`}
                                >
                                    Loop Cycles
                                </button>
                            </div>
                        </div>

                        {/* Events Table / Feed */}
                        {filteredEvents.length === 0 ? (
                            <div className="text-center py-10 text-slate-500 font-mono text-xs">
                                No telemetry events recorded yet. Click "Poll Now" or "Start Watchdog" to initiate activity.
                            </div>
                        ) : (
                            <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                                {filteredEvents.map((evt) => {
                                    const isExpanded = expandedEventId === evt.event_id;
                                    const isThreat = evt.event_type.includes('threat') || evt.event_type.includes('neutralized');
                                    const isCycle = evt.event_type.includes('cycle');

                                    return (
                                        <div
                                            key={evt.event_id}
                                            className={`rounded-xl border p-3 transition-all ${
                                                isThreat
                                                    ? 'border-rose-900/40 bg-rose-950/15'
                                                    : isCycle
                                                    ? 'border-slate-800 bg-slate-950/60'
                                                    : 'border-slate-800/80 bg-slate-900/40'
                                            }`}
                                        >
                                            <div className="flex items-center justify-between text-xs">
                                                <div className="flex items-center gap-2">
                                                    <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold border ${
                                                        isThreat
                                                            ? 'bg-rose-950 text-rose-300 border-rose-800'
                                                            : isCycle
                                                            ? 'bg-purple-950 text-purple-300 border-purple-800'
                                                            : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                                                    }`}>
                                                        {evt.event_type.replace('_', ' ')}
                                                    </span>
                                                    <span className="font-semibold text-slate-200">{evt.message}</span>
                                                </div>

                                                <div className="flex items-center gap-2 text-slate-400 font-mono text-[11px]">
                                                    <span>{new Date(evt.timestamp).toLocaleTimeString()}</span>
                                                    {evt.details && Object.keys(evt.details).length > 0 && (
                                                        <button
                                                            onClick={() => setExpandedEventId(isExpanded ? null : evt.event_id)}
                                                            className="text-slate-400 hover:text-cyan-400 p-0.5"
                                                        >
                                                            {isExpanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                                                        </button>
                                                    )}
                                                </div>
                                            </div>

                                            {/* Expandable JSON Details */}
                                            {isExpanded && evt.details && (
                                                <div className="mt-2.5 pt-2.5 border-t border-slate-800/80">
                                                    <pre className="text-[10px] font-mono text-cyan-300 bg-slate-950 p-2.5 rounded border border-slate-800 overflow-x-auto">
                                                        {JSON.stringify(evt.details, null, 2)}
                                                    </pre>
                                                </div>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>

                </div>
            )}

            {/* ═══ TAB 2: INTEGRATED NOTIFICATION CENTER ═══ */}
            {activeTab === 'notifications' && (
                <div className="space-y-4">
                    {/* Filter bar */}
                    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3.5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                        <div className="flex items-center gap-2 text-xs">
                            <span className="font-mono text-slate-400 font-semibold uppercase tracking-wider">Alert Recipient:</span>
                            <div className="flex items-center gap-1.5">
                                {[
                                    { id: 'all', label: 'All Alerts' },
                                    { id: 'unread', label: `Unread (${unreadCount})` },
                                    { id: 'user', label: 'Employee Notifications' },
                                    { id: 'admin', label: 'SOC Admin Advisories' },
                                ].map(f => (
                                    <button
                                        key={f.id}
                                        onClick={() => setNotifFilter(f.id)}
                                        className={`px-2.5 py-1 rounded-lg font-mono text-[11px] transition-all ${
                                            notifFilter === f.id
                                                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                                                : 'text-slate-400 hover:text-slate-200'
                                        }`}
                                    >
                                        {f.label}
                                    </button>
                                ))}
                            </div>
                        </div>

                        <button
                            onClick={fetchAlerts}
                            disabled={notifsLoading}
                            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-400 font-mono"
                        >
                            <RefreshCw className={`h-3 w-3 ${notifsLoading ? 'animate-spin' : ''}`} />
                            <span>Refresh Alerts</span>
                        </button>
                    </div>

                    {/* Notifications List */}
                    {filteredNotifications.length === 0 ? (
                        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-12 text-center text-slate-500 space-y-2">
                            <Bell className="h-8 w-8 text-slate-700 mx-auto" />
                            <h4 className="text-sm font-semibold text-slate-400">No Security Alerts Found</h4>
                            <p className="text-xs text-slate-500 max-w-sm mx-auto">
                                Notifications are automatically dispatched by the watchdog engine or autonomous remediation playbook upon threat containment.
                            </p>
                        </div>
                    ) : (
                        <div className="space-y-3">
                            {filteredNotifications.map((notif) => {
                                const isAdmin = notif.recipient_type === 'admin';
                                const isUnread = !notif.is_read;

                                return (
                                    <div
                                        key={notif.notification_id}
                                        className={`rounded-xl border p-4 transition-all ${
                                            isUnread
                                                ? 'border-cyan-500/40 bg-slate-900/90 shadow-sm shadow-cyan-950/40'
                                                : 'border-slate-800 bg-slate-900/50 opacity-80'
                                        }`}
                                    >
                                        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 border-b border-slate-800/80 pb-3">
                                            <div className="space-y-1">
                                                <div className="flex items-center gap-2">
                                                    <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold border ${
                                                        isAdmin
                                                            ? 'bg-purple-950 text-purple-300 border-purple-800'
                                                            : 'bg-blue-950 text-blue-300 border-blue-800'
                                                    }`}>
                                                        {isAdmin ? 'SOC Admin Advisory' : 'Employee Alert'}
                                                    </span>

                                                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                                                        To: {notif.recipient}
                                                    </span>

                                                    {isUnread && (
                                                        <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                                                    )}
                                                </div>
                                                <h4 className="text-sm font-bold text-white">
                                                    {notif.subject}
                                                </h4>
                                            </div>

                                            <div className="flex items-center gap-2 font-mono text-[11px] text-slate-400 flex-shrink-0">
                                                <span>{new Date(notif.created_at).toLocaleString()}</span>
                                                {isUnread && (
                                                    <button
                                                        onClick={() => handleMarkAsRead(notif.notification_id)}
                                                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[10px] border border-slate-700 font-semibold"
                                                    >
                                                        Mark Read
                                                    </button>
                                                )}
                                            </div>
                                        </div>

                                        {/* Message Content */}
                                        <p className="text-xs text-slate-300 mt-3 whitespace-pre-line leading-relaxed">
                                            {notif.message}
                                        </p>

                                        {/* Action Badges / Summary */}
                                        {notif.actions_summary && notif.actions_summary.length > 0 && (
                                            <div className="mt-3 pt-3 border-t border-slate-800/60 flex flex-wrap items-center gap-1.5">
                                                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mr-1">
                                                    Actions Taken:
                                                </span>
                                                {notif.actions_summary.map((act, i) => (
                                                    <span
                                                        key={i}
                                                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-emerald-300 border border-emerald-900/60"
                                                    >
                                                        {act}
                                                    </span>
                                                ))}
                                            </div>
                                        )}

                                        {/* Risk Reduction Metrics */}
                                        <div className="mt-3 flex items-center gap-3 text-[11px] font-mono text-slate-400">
                                            <span>
                                                Initial Risk: <strong className="text-rose-400">{notif.initial_risk_score}</strong>
                                            </span>
                                            <span>&rarr;</span>
                                            <span>
                                                Residual Risk: <strong className="text-emerald-400">{notif.residual_risk_score}</strong>
                                            </span>
                                            <span className="text-slate-600">|</span>
                                            <span className="text-slate-300">
                                                Containment: <strong>{notif.containment_status}</strong>
                                            </span>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            )}

        </div>
    );
}