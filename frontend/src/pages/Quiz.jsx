import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
    HelpCircle,
    CheckCircle2,
    XCircle,
    AlertTriangle,
    ShieldAlert,
    ShieldCheck,
    ArrowRight,
    ArrowLeft,
    RotateCcw,
    Award,
    Mail,
    Paperclip,
    Sparkles,
    GraduationCap,
    Clock,
    Send
} from 'lucide-react';
import { getQuizQuestions, submitQuiz } from '../services/api';

export default function Quiz() {
    const [questions, setQuestions] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    // Quiz progress state
    const [currentIndex, setCurrentIndex] = useState(0);
    const [selectedAnswers, setSelectedAnswers] = useState({}); // { [question_id]: option_id }
    const [submitting, setSubmitting] = useState(false);

    // Graded result state
    const [result, setResult] = useState(null);

    useEffect(() => {
        loadQuiz();
    }, []);

    const loadQuiz = async () => {
        setLoading(true);
        setError(null);
        setResult(null);
        setSelectedAnswers({});
        setCurrentIndex(0);
        try {
            const data = await getQuizQuestions();
            setQuestions(data || []);
        } catch (err) {
            setError(err.response?.data?.detail || err.message || 'Failed to load quiz questions.');
        } finally {
            setLoading(false);
        }
    };

    const handleSelectOption = (questionId, optionId) => {
        setSelectedAnswers(prev => ({
            ...prev,
            [questionId]: optionId
        }));
    };

    const handleNext = () => {
        if (currentIndex < questions.length - 1) {
            setCurrentIndex(prev => prev + 1);
        }
    };

    const handlePrev = () => {
        if (currentIndex > 0) {
            setCurrentIndex(prev => prev - 1);
        }
    };

    const handleSubmit = async () => {
        // Build answer list
        const answersList = Object.entries(selectedAnswers).map(([qid, optId]) => ({
            question_id: qid,
            selected_option_id: optId
        }));

        setSubmitting(true);
        setError(null);
        try {
            const report = await submitQuiz(answersList);
            setResult(report);
        } catch (err) {
            setError(err.response?.data?.detail || err.message || 'Quiz submission failed.');
        } finally {
            setSubmitting(false);
        }
    };

    const currentQ = questions[currentIndex];
    const totalQ = questions.length;
    const answeredCount = Object.keys(selectedAnswers).length;
    const allAnswered = totalQ > 0 && answeredCount === totalQ;

    return (
        <div className="space-y-6 max-w-4xl mx-auto">

            {/* ── Page Header ── */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
                <div>
                    <div className="flex items-center gap-2.5">
                        <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30">
                            <HelpCircle className="h-6 w-6 text-cyan-400" />
                        </div>
                        <div>
                            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2">
                                Phishing Defense Quiz
                            </h1>
                            <p className="text-xs text-slate-400 mt-0.5 font-mono">
                                Scenario-Based Threat Identification • Live Evaluation • Defense Insights
                            </p>
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    <Link
                        to="/training"
                        className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300 hover:text-white hover:border-slate-700 transition-all"
                    >
                        <GraduationCap className="h-3.5 w-3.5 text-amber-400" />
                        <span>Curriculum Lessons</span>
                    </Link>

                    {result && (
                        <button
                            onClick={loadQuiz}
                            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-mono text-cyan-300 border border-slate-700 transition-all"
                        >
                            <RotateCcw className="h-3.5 w-3.5" />
                            <span>Retake Quiz</span>
                        </button>
                    )}
                </div>
            </div>

            {error && (
                <div className="rounded-xl bg-rose-950/40 border border-rose-800/60 p-4 text-xs text-rose-300 flex items-start gap-2.5">
                    <AlertTriangle className="h-4 w-4 text-rose-400 flex-shrink-0 mt-0.5" />
                    <span>{error}</span>
                </div>
            )}

            {/* ═══ VIEW 1: TAKING THE QUIZ ═══ */}
            {!result && (
                <div className="space-y-6">

                    {loading ? (
                        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-12 text-center text-slate-400 font-mono text-xs">
                            Loading quiz scenario bank...
                        </div>
                    ) : totalQ === 0 ? (
                        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-12 text-center text-slate-500 font-mono text-xs">
                            No quiz scenarios available.
                        </div>
                    ) : (
                        <div className="space-y-6">

                            {/* Progress & Question Stepper Bar */}
                            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
                                <div className="flex items-center justify-between text-xs font-mono">
                                    <span className="text-slate-300 font-semibold">
                                        Question {currentIndex + 1} of {totalQ}
                                    </span>
                                    <span className="text-cyan-400">
                                        Answered: {answeredCount} / {totalQ}
                                    </span>
                                </div>

                                {/* Step tracker pills */}
                                <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
                                    {questions.map((q, idx) => {
                                        const isAnswered = !!selectedAnswers[q.question_id];
                                        const isCurrent = currentIndex === idx;

                                        return (
                                            <button
                                                key={q.question_id}
                                                type="button"
                                                onClick={() => setCurrentIndex(idx)}
                                                className={`h-2 flex-1 rounded-full transition-all ${
                                                    isCurrent
                                                        ? 'bg-cyan-400 ring-2 ring-cyan-400/50'
                                                        : isAnswered
                                                        ? 'bg-emerald-500'
                                                        : 'bg-slate-800'
                                                }`}
                                                title={`Question ${idx + 1}`}
                                            />
                                        );
                                    })}
                                </div>
                            </div>

                            {/* Current Question Scenario Card */}
                            {currentQ && (
                                <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-5">

                                    {/* Question Meta Header */}
                                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-4">
                                        <div className="flex items-center gap-2 text-xs font-mono">
                                            <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400">
                                                {currentQ.question_id}
                                            </span>
                                            <span className="text-slate-500">•</span>
                                            <span className="text-cyan-400">{currentQ.category}</span>
                                            <span className="text-slate-500">•</span>
                                            <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                                                currentQ.difficulty === 'Beginner'
                                                    ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                                                    : currentQ.difficulty === 'Intermediate'
                                                    ? 'bg-blue-950/60 text-blue-400 border-blue-800/60'
                                                    : 'bg-purple-950/60 text-purple-400 border-purple-800/60'
                                            }`}>
                                                {currentQ.difficulty}
                                            </span>
                                        </div>

                                        <span className="text-xs font-mono text-slate-500">
                                            Inspect email details below
                                        </span>
                                    </div>

                                    <h3 className="text-lg font-bold text-white">
                                        {currentQ.title}
                                    </h3>

                                    {/* Simulated Email Envelope Card */}
                                    <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 space-y-3 font-mono text-xs">
                                        <div className="border-b border-slate-800/80 pb-2 space-y-1">
                                            <div className="flex items-center gap-2 text-slate-400">
                                                <span className="text-slate-500 uppercase text-[10px] w-14">From:</span>
                                                <span className="text-cyan-300 font-bold">{currentQ.scenario_sender}</span>
                                            </div>
                                            <div className="flex items-center gap-2 text-slate-300">
                                                <span className="text-slate-500 uppercase text-[10px] w-14">Subject:</span>
                                                <span className="text-white font-semibold">{currentQ.scenario_subject}</span>
                                            </div>
                                        </div>

                                        {/* Body */}
                                        <div className="text-slate-300 whitespace-pre-line leading-relaxed font-sans text-xs pt-1">
                                            {currentQ.scenario_body}
                                        </div>

                                        {/* Attachment badge */}
                                        {currentQ.has_attachment && (
                                            <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center gap-2">
                                                <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-amber-900/60 text-amber-300 text-xs">
                                                    <Paperclip className="h-3.5 w-3.5 text-amber-400" />
                                                    <span>Attachment: {currentQ.attachment_name || 'Suspicious_File.xlsm'}</span>
                                                </div>
                                            </div>
                                        )}
                                    </div>

                                    {/* Decision / Options Section */}
                                    <div className="space-y-3 pt-2">
                                        <label className="block text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
                                            Select Your Threat Assessment:
                                        </label>

                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                            {currentQ.options?.map((opt) => {
                                                const isSelected = selectedAnswers[currentQ.question_id] === opt.option_id;

                                                return (
                                                    <button
                                                        key={opt.option_id}
                                                        type="button"
                                                        onClick={() => handleSelectOption(currentQ.question_id, opt.option_id)}
                                                        className={`p-4 rounded-xl border text-left transition-all flex items-center justify-between ${
                                                            isSelected
                                                                ? 'bg-cyan-950/40 border-cyan-400 shadow-md shadow-cyan-950/40'
                                                                : 'bg-slate-950 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
                                                        }`}
                                                    >
                                                        <div className="space-y-1">
                                                            <span className="text-xs font-bold text-white block">
                                                                {opt.text}
                                                            </span>
                                                            <span className="text-[10px] font-mono text-slate-400 uppercase">
                                                                Option: {opt.option_id}
                                                            </span>
                                                        </div>

                                                        <div className={`w-5 h-5 rounded-full border flex items-center justify-center ${
                                                            isSelected
                                                                ? 'border-cyan-400 bg-cyan-400'
                                                                : 'border-slate-700 bg-slate-900'
                                                        }`}>
                                                            {isSelected && <div className="w-2 h-2 rounded-full bg-slate-950" />}
                                                        </div>
                                                    </button>
                                                );
                                            })}
                                        </div>
                                    </div>

                                    {/* Navigation & Submission Controls */}
                                    <div className="pt-4 border-t border-slate-800 flex items-center justify-between gap-3">
                                        <button
                                            type="button"
                                            onClick={handlePrev}
                                            disabled={currentIndex === 0}
                                            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs border border-slate-700 disabled:opacity-40 transition-all"
                                        >
                                            <ArrowLeft className="h-3.5 w-3.5" />
                                            <span>Previous</span>
                                        </button>

                                        <div className="flex items-center gap-2">
                                            {currentIndex < totalQ - 1 ? (
                                                <button
                                                    type="button"
                                                    onClick={handleNext}
                                                    className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs border border-slate-700 transition-all"
                                                >
                                                    <span>Next Question</span>
                                                    <ArrowRight className="h-3.5 w-3.5" />
                                                </button>
                                            ) : (
                                                <button
                                                    type="button"
                                                    onClick={handleSubmit}
                                                    disabled={submitting || !allAnswered}
                                                    className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-slate-950 font-bold text-xs shadow-lg shadow-emerald-950 disabled:opacity-50 transition-all"
                                                >
                                                    <Send className="h-3.5 w-3.5" />
                                                    <span>{submitting ? 'Grading Answers...' : 'Submit & Grade Quiz'}</span>
                                                </button>
                                            )}
                                        </div>
                                    </div>

                                </div>
                            )}

                        </div>
                    )}

                </div>
            )}

            {/* ═══ VIEW 2: GRADED QUIZ RESULTS & REVIEW ═══ */}
            {result && (
                <div className="space-y-6">

                    {/* Result Hero Banner */}
                    <div className="rounded-2xl border border-cyan-500/30 bg-gradient-to-br from-slate-900 via-slate-900/90 to-slate-950 p-6 sm:p-8 space-y-4">
                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800/80 pb-5">
                            <div>
                                <span className="text-[10px] font-mono uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-300 font-bold">
                                    Official Quiz Evaluation
                                </span>
                                <h2 className="text-2xl sm:text-3xl font-extrabold text-white mt-2">
                                    Score: <span className="text-cyan-400 font-mono">{result.score_percentage}%</span> ({result.correct_count} of {result.total_questions} Correct)
                                </h2>
                                <p className="text-xs text-slate-400 mt-1 font-mono">
                                    Submitted at {new Date(result.submitted_at).toLocaleTimeString()} • Submission #{result.submission_id}
                                </p>
                            </div>

                            <div className="text-left sm:text-right">
                                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 block">Performance Tier</span>
                                <span className={`text-sm sm:text-base font-extrabold font-mono px-3 py-1.5 rounded-xl border mt-1 inline-block ${
                                    result.score_percentage >= 80
                                        ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                                        : result.score_percentage >= 50
                                        ? 'bg-amber-950/80 text-amber-300 border-amber-800'
                                        : 'bg-rose-950/80 text-rose-300 border-rose-800'
                                }`}>
                                    {result.performance_rating}
                                </span>
                            </div>
                        </div>

                        {/* Summary Narrative */}
                        <div className="rounded-xl bg-slate-950/60 border border-slate-800/80 p-4 text-xs text-slate-300 leading-relaxed font-sans">
                            {result.summary}
                        </div>

                        {/* Recommendations */}
                        {result.recommendations && result.recommendations.length > 0 && (
                            <div className="space-y-2 pt-2">
                                <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
                                    <Sparkles className="h-3.5 w-3.5" />
                                    <span>Targeted Defense Recommendations:</span>
                                </h4>
                                <ul className="space-y-1 text-xs text-slate-300 list-disc list-inside">
                                    {result.recommendations.map((rec, i) => (
                                        <li key={i}>{rec}</li>
                                    ))}
                                </ul>
                            </div>
                        )}
                    </div>

                    {/* Question Breakdown Section */}
                    <div className="space-y-4">
                        <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                            <ShieldAlert className="h-4 w-4 text-cyan-400" />
                            <span>Detailed Scenario Review ({result.question_reviews?.length || 0})</span>
                        </h3>

                        <div className="space-y-3">
                            {result.question_reviews?.map((review, idx) => {
                                const isCorrect = review.is_correct;

                                return (
                                    <div
                                        key={review.question_id}
                                        className={`rounded-xl border p-5 space-y-3 ${
                                            isCorrect
                                                ? 'border-emerald-900/40 bg-emerald-950/10'
                                                : 'border-rose-900/40 bg-rose-950/15'
                                        }`}
                                    >
                                        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 border-b border-slate-800/80 pb-3">
                                            <div className="space-y-1">
                                                <div className="flex items-center gap-2">
                                                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                                                        Question {idx + 1} ({review.question_id})
                                                    </span>
                                                    <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold border ${
                                                        isCorrect
                                                            ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                                                            : 'bg-rose-950 text-rose-300 border-rose-800'
                                                    }`}>
                                                        {isCorrect ? 'Correct Decision' : 'Incorrect Assessment'}
                                                    </span>
                                                </div>
                                                <h4 className="text-sm font-bold text-white">
                                                    {review.title}
                                                </h4>
                                            </div>

                                            <div className="text-xs font-mono text-slate-400">
                                                <span>Your Answer: <strong className={isCorrect ? 'text-emerald-400' : 'text-rose-400'}>{review.user_answer}</strong></span>
                                                {!isCorrect && (
                                                    <span className="block text-slate-300">
                                                        Correct Answer: <strong className="text-emerald-400">{review.correct_answer}</strong>
                                                    </span>
                                                )}
                                            </div>
                                        </div>

                                        {/* Explanation */}
                                        <p className="text-xs text-slate-300 leading-relaxed font-sans">
                                            {review.explanation}
                                        </p>

                                        {/* Red flags identified */}
                                        {review.red_flags && review.red_flags.length > 0 && (
                                            <div className="pt-2 border-t border-slate-800/60 flex flex-wrap items-center gap-1.5">
                                                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mr-1">
                                                    Key Red Flags:
                                                </span>
                                                {review.red_flags.map((flag, fi) => (
                                                    <span
                                                        key={fi}
                                                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-amber-300 border border-amber-900/60"
                                                    >
                                                        {flag}
                                                    </span>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    {/* Bottom Action Bar */}
                    <div className="flex items-center justify-between pt-4 border-t border-slate-800">
                        <Link
                            to="/training"
                            className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-white"
                        >
                            <ArrowLeft className="h-3.5 w-3.5" />
                            <span>Return to Training Curriculum</span>
                        </Link>

                        <button
                            onClick={loadQuiz}
                            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs shadow-md shadow-cyan-950 transition-all"
                        >
                            <RotateCcw className="h-4 w-4" />
                            <span>Retake Quiz Scenario Bank</span>
                        </button>
                    </div>

                </div>
            )}

        </div>
    );
}