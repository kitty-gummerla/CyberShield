import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import Dashboard from './pages/Dashboard';
import Analyzer from './pages/Analyzer';
import Investigation from './pages/Investigation';
import Monitoring from './pages/Monitoring';
import Training from './pages/Training';
import Quiz from './pages/Quiz';

export default function App() {
    return (
        <BrowserRouter>
            <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
                <Navbar />
                <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
                    <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/analyzer" element={<Analyzer />} />
                        <Route path="/investigation" element={<Investigation />} />
                        <Route path="/monitoring" element={<Monitoring />} />
                        <Route path="/training" element={<Training />} />
                        <Route path="/quiz" element={<Quiz />} />
                    </Routes>
                </main>
                <Footer />
            </div>
        </BrowserRouter>
    );
}