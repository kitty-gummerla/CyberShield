import React from 'react';
import { ShieldCheck } from 'lucide-react';

export default function Footer() {
    return (
        <footer className="border-t border-slate-800/80 bg-slate-950/60 mt-auto py-6">
            <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-4">
                <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-cyan-500" />
                    <span>CyberShield Autonomous Threat Detection & Security Awareness Platform</span>
                </div>
                <div className="flex items-center gap-4 font-mono text-[11px]">
                    <span>FastAPI Backend</span>
                    <span>•</span>
                    <span>Autonomous SOC</span>
                    <span>•</span>
                    <span>Academic Project</span>
                </div>
            </div>
        </footer>
    );
}