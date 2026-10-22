import React, { useState, useEffect } from 'react';
import { NavLink, Link } from 'react-router-dom';
import {
    ShieldAlert,
    Activity,
    Search,
    Terminal,
    Radio,
    GraduationCap,
    HelpCircle,
    CircleDot,
    Bell
} from 'lucide-react';
import { checkBackendHealth, getNotifications } from '../services/api';

export default function Navbar() {
    const [backendOnline, setBackendOnline] = useState(false);
    const [unreadAlerts, setUnreadAlerts] = useState(0);

    useEffect(() => {
        const verifyHealthAndAlerts = async () => {
            const res = await checkBackendHealth();
            setBackendOnline(res.online);

            try {
                const notifs = await getNotifications(null, true);
                setUnreadAlerts(notifs.unread_count || 0);
            } catch (e) {}
        };

        verifyHealthAndAlerts();
        const interval = setInterval(verifyHealthAndAlerts, 10000);
        return () => clearInterval(interval);
    }, []);

    const navLinks = [
        { to: "/", label: "Dashboard", icon: Activity },
        { to: "/analyzer", label: "Email Analyzer", icon: Search },
        { to: "/investigation", label: "Threat Center", icon: Terminal },
        { to: "/monitoring", label: "24/7 Watchdog", icon: Radio, badge: unreadAlerts > 0 ? unreadAlerts : null },
        { to: "/training", label: "Awareness Training", icon: GraduationCap },
        { to: "/quiz", label: "Phishing Quiz", icon: HelpCircle },
    ];

    return (
        <nav className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-50">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex items-center justify-between h-16">

                    {/* Brand Logo */}
                    <NavLink to="/" className="flex items-center space-x-2.5 group">
                        <div className="bg-cyan-500/10 p-2 rounded-xl border border-cyan-500/30 group-hover:border-cyan-400/60 transition-colors">
                            <ShieldAlert className="h-5 w-5 text-cyan-400" />
                        </div>
                        <span className="text-lg font-bold tracking-wider text-white">
                            CYBER<span className="text-cyan-400">SHIELD</span>
                        </span>
                    </NavLink>

                    {/* Navigation Links */}
                    <div className="hidden md:flex items-center space-x-1">
                        {navLinks.map((item) => {
                            const Icon = item.icon;
                            return (
                                <NavLink
                                    key={item.to}
                                    to={item.to}
                                    className={({ isActive }) =>
                                        `flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all relative ${isActive
                                            ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm shadow-cyan-950"
                                            : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/60"
                                        }`
                                    }
                                >
                                    <Icon className="h-4 w-4" />
                                    <span>{item.label}</span>
                                    {item.badge && (
                                        <span className="w-4 h-4 rounded-full bg-rose-500 text-white font-mono text-[9px] font-bold flex items-center justify-center animate-pulse">
                                            {item.badge}
                                        </span>
                                    )}
                                </NavLink>
                            );
                        })}
                    </div>

                    {/* Right Tools: Notification Bell & Backend Health Badge */}
                    <div className="flex items-center gap-3">
                        <Link
                            to="/monitoring"
                            title="View Security Alerts & Notifications"
                            className="relative p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white transition-all"
                        >
                            <Bell className="h-4 w-4 text-slate-400 hover:text-cyan-400" />
                            {unreadAlerts > 0 && (
                                <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-white font-mono text-[9px] font-bold flex items-center justify-center animate-pulse">
                                    {unreadAlerts}
                                </span>
                            )}
                        </Link>

                        <div className={`flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border ${backendOnline
                            ? "bg-emerald-950/50 text-emerald-400 border-emerald-800/50"
                            : "bg-rose-950/50 text-rose-400 border-rose-800/50"
                            }`}>
                            <CircleDot className={`h-3 w-3 ${backendOnline ? "animate-pulse text-emerald-400" : "text-rose-400"}`} />
                            <span className="font-mono text-[11px]">
                                {backendOnline ? "API Online (8000)" : "API Disconnected"}
                            </span>
                        </div>
                    </div>

                </div>
            </div>
        </nav>
    );
}