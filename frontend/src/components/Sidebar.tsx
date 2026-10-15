import React from 'react';
import {
  LayoutDashboard, PlusCircle, FolderKanban, Search,
  GitCompare, Settings, ShieldAlert, Activity, User
} from 'lucide-react';

interface SidebarProps {
  currentView: string;
  onNavigate: (view: string) => void;
  casesCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentView, onNavigate, casesCount = 0 }) => {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },
    { id: 'ingest', label: 'New Investigation', icon: PlusCircle },
    { id: 'cases', label: 'Case Management', icon: FolderKanban, badge: casesCount },
    { id: 'intel', label: 'Threat Intel Lookup', icon: Search },
    { id: 'compare', label: 'Case Comparison', icon: GitCompare },
    { id: 'settings', label: 'Settings & Integrations', icon: Settings },
  ];

  return (
    <aside className="w-64 flex-shrink-0 border-r border-soc-border bg-soc-card flex flex-col justify-between select-none">
      <div>
        {/* Brand Header */}
        <div className="h-16 flex items-center px-6 border-b border-soc-border gap-3">
          <div className="h-9 w-9 rounded-lg bg-soc-accent/15 border border-soc-accent/40 flex items-center justify-center text-soc-accent shadow-[0_0_15px_rgba(59,130,246,0.3)]">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-white tracking-wider text-base">PhishScope</span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-soc-accent/20 text-soc-accent font-semibold">v1.0</span>
            </div>
            <p className="text-[10px] text-soc-muted font-mono tracking-tight uppercase">Threat Intel Platform</p>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = currentView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  active
                    ? 'bg-soc-accent text-white shadow-[0_0_15px_rgba(59,130,246,0.35)] font-semibold'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-soc-hover'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`h-4 w-4 ${active ? 'text-white' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {typeof item.badge === 'number' && item.badge > 0 && (
                  <span className={`text-[11px] font-mono px-2 py-0.5 rounded-full ${
                    active ? 'bg-white/20 text-white' : 'bg-soc-panel text-slate-300 border border-soc-border'
                  }`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Analyst Profile Footer */}
      <div className="p-3 border-t border-soc-border">
        <div className="flex items-center gap-3 p-2.5 rounded-lg bg-soc-panel/70 border border-soc-border/60">
          <div className="h-8 w-8 rounded-full bg-soc-hover border border-soc-border flex items-center justify-center text-soc-cyan">
            <User className="h-4 w-4" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-xs font-semibold text-white truncate">Lead SOC Analyst</p>
            <div className="flex items-center gap-1.5 mt-0.5">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" />
              <span className="text-[10px] text-emerald-400 font-mono">ACTIVE (ANALYST)</span>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
};
