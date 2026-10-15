import React, { useState, useEffect } from 'react';
import { PlusCircle, Clock, RefreshCw, ShieldCheck, AlertCircle } from 'lucide-react';

interface NavbarProps {
  currentView: string;
  onNewInvestigation: () => void;
  onRefresh: () => void;
  isRefreshing?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentView,
  onNewInvestigation,
  onRefresh,
  isRefreshing = false
}) => {
  const [time, setTime] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTime(now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const getTitle = () => {
    switch (currentView) {
      case 'dashboard': return 'Security Operations Center Dashboard';
      case 'ingest': return 'Ingest Email Evidence for Analysis';
      case 'cases': return 'Investigation Case Management';
      case 'case_detail': return 'Case Forensic Workspace';
      case 'intel': return 'Threat Intelligence & Observable Lookup';
      case 'compare': return 'Investigation Correlation & Case Comparison';
      case 'settings': return 'Platform Integrations & Policy Settings';
      default: return 'PhishScope Platform';
    }
  };

  return (
    <header className="h-16 border-b border-soc-border bg-soc-card/70 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center gap-4">
        <h1 className="text-base font-semibold text-white tracking-wide">{getTitle()}</h1>
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded bg-soc-panel border border-soc-border text-[11px] font-mono text-soc-cyan">
          <span className="h-2 w-2 rounded-full bg-soc-cyan animate-pulse" />
          <span>RUNTIME LIVE</span>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* UTC Clock */}
        <div className="hidden md:flex items-center gap-2 text-xs font-mono text-slate-400 bg-soc-panel px-3 py-1.5 rounded-lg border border-soc-border">
          <Clock className="h-3.5 w-3.5 text-soc-muted" />
          <span>{time}</span>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          title="Refresh Data"
          className="p-2 rounded-lg border border-soc-border bg-soc-panel text-slate-300 hover:text-white hover:bg-soc-hover transition-colors"
        >
          <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin text-soc-accent' : ''}`} />
        </button>

        {/* Quick Ingest Button */}
        {currentView !== 'ingest' && (
          <button
            onClick={onNewInvestigation}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-soc-accent hover:bg-blue-600 text-white text-xs font-semibold shadow-[0_0_15px_rgba(59,130,246,0.3)] transition-all"
          >
            <PlusCircle className="h-4 w-4" />
            <span>New Investigation</span>
          </button>
        )}
      </div>
    </header>
  );
};
