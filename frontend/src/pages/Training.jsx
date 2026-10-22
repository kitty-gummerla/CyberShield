import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
    GraduationCap,
    BookOpen,
    CheckCircle2,
    Clock,
    AlertTriangle,
    ShieldCheck,
    ArrowRight,
    HelpCircle,
    Brain,
    Globe,
    FileWarning,
    DollarSign,
    Layers,
    ChevronRight,
    Award,
    RotateCcw
} from 'lucide-react';
import { listTrainingModules, getModuleDetail } from '../services/api';

// Icon map helper
const ICON_MAP = {
    Brain: Brain,
    Globe: Globe,
    FileWarning: FileWarning,
    ShieldCheck: ShieldCheck,
    DollarSign: DollarSign,
};

export default function Training() {
    const [modules, setModules] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    // Selected module for full study view
    const [activeModuleId, setActiveModuleId] = useState(null);
    const [activeModuleDetail, setActiveModuleDetail] = useState(null);
    const [detailLoading, setDetailLoading] = useState(false);

    // Local completion tracking
    const [completedModules, setCompletedModules] = useState(() => {
        try {
            const saved = localStorage.getItem('cybershield_completed_modules');
            return saved ? JSON.parse(saved) : [];
        } catch {
            return [];
        }
    });

    useEffect(() => {
        const fetchModules = async () => {
            setLoading(true);
            try {
                const data = await listTrainingModules();
                setModules(data || []);
                // Default to opening the first module if none selected
                if (data && data.length > 0 && !activeModuleId) {
                    loadModuleDetail(data[0].module_id);
                }
            } catch (err) {
                setError(err.response?.data?.detail || err.message || 'Failed to load training modules.');
            } finally {
                setLoading(false);
            }
        };
        fetchModules();
    }, []);

    const loadModuleDetail = async (id) => {
        setActiveModuleId(id);
        setDetailLoading(true);
        try {
            const detail = await getModuleDetail(id);
            setActiveModuleDetail(detail);
        } catch (err) {
            console.error('Failed to load module detail:', err);
        } finally {
            setDetailLoading(false);
        }
    };

    const toggleCompletion = (id) => {
        setCompletedModules(prev => {
            const next = prev.includes(id) ? prev.filter(m => m !== id) : [...prev, id];
            try {
                localStorage.setItem('cybershield_completed_modules', JSON.stringify(next));
            } catch (e) {}
            return next;
        });
    };

    const progressPercent = modules.length > 0
        ? Math.round((completedModules.length / modules.length) * 100)
        : 0;

    return (
        <div className="space-y-6">

            {/* ── Page Header ── */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
                <div>
                    <div className="flex items-center gap-2.5">
                        <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/30">
                            <GraduationCap className="h-6 w-6 text-amber-400" />
                        </div>
                        <div>
                            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2">
                                Cybersecurity Awareness Training
                            </h1>
                            <p className="text-xs text-slate-400 mt-0.5 font-mono">
                                Interactive Threat Defense Curriculum • Attack Mechanisms • Red-Flag Indicators
                            </p>
                        </div>
                    </div>
                </div>

                {/* Quick Link to Quiz */}
                <Link
                    to="/quiz"
                    className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-950 transition-all self-start sm:self-auto"
                >
                    <HelpCircle className="h-4 w-4" />
                    <span>Test Skills in Quiz</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                </Link>
            </div>

            {/* ── Curriculum Progress Bar ── */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                <div className="flex items-center justify-between text-xs mb-2">
                    <span className="font-mono text-slate-300 font-semibold flex items-center gap-1.5">
                        <Award className="h-4 w-4 text-amber-400" />
                        Training Progress: {completedModules.length} of {modules.length} Modules Completed
                    </span>
                    <span className="font-mono text-amber-400 font-bold">{progressPercent}%</span>
                </div>
                <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                    <div
                        className="bg-gradient-to-r from-amber-500 to-emerald-400 h-2 rounded-full transition-all duration-500"
                        style={{ width: `${progressPercent}%` }}
                    />
                </div>
            </div>

            {error && (
                <div className="rounded-xl bg-rose-950/40 border border-rose-800/60 p-4 text-xs text-rose-300 flex items-start gap-2.5">
                    <AlertTriangle className="h-4 w-4 text-rose-400 flex-shrink-0 mt-0.5" />
                    <span>{error}</span>
                </div>
            )}

            {/* ── Main Curriculum Layout: Sidebar List + Content Reader ── */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

                {/* Left Column: Modules Navigation List */}
                <div className="lg:col-span-4 space-y-3">
                    <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
                        <BookOpen className="h-3.5 w-3.5 text-cyan-400" />
                        <span>Core Curriculum Modules</span>
                    </h3>

                    {loading ? (
                        <div className="text-xs font-mono text-slate-500 p-4 text-center">Loading curriculum modules...</div>
                    ) : (
                        <div className="space-y-2">
                            {modules.map((m) => {
                                const isSelected = activeModuleId === m.module_id;
                                const isDone = completedModules.includes(m.module_id);
                                const IconComponent = ICON_MAP[m.icon] || BookOpen;

                                return (
                                    <button
                                        key={m.module_id}
                                        type="button"
                                        onClick={() => loadModuleDetail(m.module_id)}
                                        className={`w-full text-left p-3.5 rounded-xl border transition-all flex items-start gap-3 ${
                                            isSelected
                                                ? 'bg-slate-800/90 border-cyan-500/50 shadow-md shadow-cyan-950/30'
                                                : 'bg-slate-900/40 border-slate-800 hover:border-slate-700 hover:bg-slate-900/80'
                                        }`}
                                    >
                                        <div className={`p-2 rounded-lg border mt-0.5 ${
                                            isSelected
                                                ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
                                                : 'bg-slate-950 border-slate-800 text-slate-400'
                                        }`}>
                                            <IconComponent className="h-4 w-4" />
                                        </div>

                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center justify-between gap-1">
                                                <span className="text-[10px] font-mono text-slate-500 uppercase">{m.module_id}</span>
                                                <span className={`text-[9px] font-mono uppercase px-1.5 py-0.2 rounded border ${
                                                    m.difficulty === 'Beginner'
                                                        ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                                                        : m.difficulty === 'Intermediate'
                                                        ? 'bg-blue-950/60 text-blue-400 border-blue-800/60'
                                                        : 'bg-purple-950/60 text-purple-400 border-purple-800/60'
                                                }`}>
                                                    {m.difficulty}
                                                </span>
                                            </div>

                                            <h4 className={`text-xs font-bold mt-1 truncate ${
                                                isSelected ? 'text-white' : 'text-slate-200'
                                            }`}>
                                                {m.title}
                                            </h4>

                                            <div className="flex items-center gap-3 mt-1.5 text-[10px] font-mono text-slate-400">
                                                <span className="flex items-center gap-1">
                                                    <Clock className="h-3 w-3" />
                                                    {m.estimated_minutes} mins
                                                </span>
                                                {isDone && (
                                                    <span className="flex items-center gap-1 text-emerald-400 font-semibold">
                                                        <CheckCircle2 className="h-3 w-3" />
                                                        Completed
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    </button>
                                );
                            })}
                        </div>
                    )}
                </div>

                {/* Right Column: Detailed Lesson Content Reader */}
                <div className="lg:col-span-8">
                    {detailLoading && (
                        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-12 text-center text-slate-400 font-mono text-xs">
                            Loading module lesson content...
                        </div>
                    )}

                    {!detailLoading && activeModuleDetail && (
                        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-6">

                            {/* Lesson Header */}
                            <div className="border-b border-slate-800 pb-5 space-y-3">
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                    <div className="flex items-center gap-2 text-xs font-mono">
                                        <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400">
                                            {activeModuleDetail.module_id}
                                        </span>
                                        <span className="text-slate-500">•</span>
                                        <span className="text-cyan-400">{activeModuleDetail.category}</span>
                                        <span className="text-slate-500">•</span>
                                        <span className="text-slate-400">{activeModuleDetail.estimated_minutes} min read</span>
                                    </div>

                                    <button
                                        type="button"
                                        onClick={() => toggleCompletion(activeModuleDetail.module_id)}
                                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold font-mono border transition-all ${
                                            completedModules.includes(activeModuleDetail.module_id)
                                                ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800 hover:bg-emerald-900/60'
                                                : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700'
                                        }`}
                                    >
                                        <CheckCircle2 className="h-3.5 w-3.5" />
                                        <span>
                                            {completedModules.includes(activeModuleDetail.module_id)
                                                ? 'Completed'
                                                : 'Mark as Completed'}
                                        </span>
                                    </button>
                                </div>

                                <h2 className="text-xl sm:text-2xl font-extrabold text-white">
                                    {activeModuleDetail.title}
                                </h2>
                                <p className="text-xs text-slate-300 leading-relaxed">
                                    {activeModuleDetail.description}
                                </p>
                            </div>

                            {/* Section 1: How the Attack Mechanism Works */}
                            <div className="space-y-2.5">
                                <h3 className="text-xs font-mono uppercase tracking-wider text-rose-400 font-bold flex items-center gap-1.5">
                                    <AlertTriangle className="h-4 w-4" />
                                    <span>Attack Mechanism & Exploitation Theory</span>
                                </h3>
                                <div className="rounded-xl border border-rose-950/50 bg-rose-950/15 p-4 text-xs text-slate-200 leading-relaxed font-sans">
                                    {activeModuleDetail.attack_mechanism}
                                </div>
                            </div>

                            {/* Section 2: Real-World Incident Case Study */}
                            <div className="space-y-2.5">
                                <h3 className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-1.5">
                                    <Layers className="h-4 w-4" />
                                    <span>Real-World Threat Scenario</span>
                                </h3>
                                <div className="rounded-xl border border-cyan-950/50 bg-cyan-950/15 p-4 text-xs text-slate-300 italic leading-relaxed">
                                    "{activeModuleDetail.real_world_example}"
                                </div>
                            </div>

                            {/* Section 3: Red-Flag Indicators Checklist */}
                            <div className="space-y-2.5">
                                <h3 className="text-xs font-mono uppercase tracking-wider text-amber-400 font-bold flex items-center gap-1.5">
                                    <FileWarning className="h-4 w-4" />
                                    <span>Red-Flag Indicators to Inspect</span>
                                </h3>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                                    {activeModuleDetail.red_flag_indicators?.map((flag, idx) => (
                                        <div
                                            key={idx}
                                            className="rounded-lg bg-slate-950 border border-slate-800 p-3 text-xs text-slate-300 flex items-start gap-2"
                                        >
                                            <span className="w-4 h-4 rounded-full bg-amber-950/80 border border-amber-800 text-amber-400 flex items-center justify-center text-[10px] font-mono font-bold flex-shrink-0 mt-0.5">
                                                !
                                            </span>
                                            <span>{flag}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Section 4: Defense & Hardening Checklist */}
                            <div className="space-y-2.5">
                                <h3 className="text-xs font-mono uppercase tracking-wider text-emerald-400 font-bold flex items-center gap-1.5">
                                    <ShieldCheck className="h-4 w-4" />
                                    <span>Employee Defense Checklist</span>
                                </h3>
                                <div className="space-y-2">
                                    {activeModuleDetail.defense_checklist?.map((defense, idx) => (
                                        <div
                                            key={idx}
                                            className="rounded-lg bg-slate-950 border border-slate-800 p-3 text-xs text-slate-300 flex items-start gap-2.5"
                                        >
                                            <CheckCircle2 className="h-4 w-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                                            <span>{defense}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Bottom Navigation between modules & Quiz */}
                            <div className="pt-4 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
                                <button
                                    type="button"
                                    onClick={() => toggleCompletion(activeModuleDetail.module_id)}
                                    className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5"
                                >
                                    <CheckCircle2 className="h-4 w-4" />
                                    <span>
                                        {completedModules.includes(activeModuleDetail.module_id)
                                            ? 'Lesson Marked Complete'
                                            : 'Click to Mark Lesson Completed'}
                                    </span>
                                </button>

                                <Link
                                    to="/quiz"
                                    className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs border border-slate-700 transition-all"
                                >
                                    <span>Take Quiz on this Topic</span>
                                    <ArrowRight className="h-3.5 w-3.5 text-cyan-400" />
                                </Link>
                            </div>

                        </div>
                    )}
                </div>

            </div>

        </div>
    );
}