import React, { useEffect, useState } from 'react';
import {
  ShieldAlert, AlertTriangle, CheckCircle2, Clock,
  ArrowUpRight, Globe, Link2, ExternalLink, Activity, Server, Radio
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie
} from 'recharts';
import { DashboardMetrics } from '../types';
import { api } from '../services/api';

interface DashboardViewProps {
  onNavigate: (view: string, caseId?: number) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ onNavigate }) => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = async () => {
    try {
      setLoading(true);
      const data = await api.getDashboardMetrics();
      setMetrics(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch dashboard metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
    // Poll metrics every 10 seconds for real-time dashboard updates
    const interval = setInterval(fetchMetrics, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !metrics) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-soc-accent border-t-transparent" />
          <p className="text-sm font-mono text-soc-muted">Querying SOC Telemetry Engine...</p>
        </div>
      </div>
    );
  }

  if (error && !metrics) {
    return (
      <div className="p-8">
        <div className="rounded-xl border border-rose-800/40 bg-rose-950/20 p-6 text-center">
          <AlertTriangle className="mx-auto h-8 w-8 text-rose-400 mb-2" />
          <h3 className="text-base font-semibold text-rose-200">Metrics Engine Unavailable</h3>
          <p className="text-xs text-rose-300 mt-1">{error}</p>
          <button
            onClick={fetchMetrics}
            className="mt-4 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-xs font-semibold text-white"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  const riskData = metrics ? [
    { name: 'Low', count: metrics.risk_distribution.low, color: '#10b981' },
    { name: 'Medium', count: metrics.risk_distribution.medium, color: '#f59e0b' },
    { name: 'High', count: metrics.risk_distribution.high, color: '#f97316' },
    { name: 'Critical', count: metrics.risk_distribution.critical, color: '#f43f5e' },
  ] : [];

  const statusPieData = metrics ? [
    { name: 'Needs Review', value: metrics.status_breakdown.needs_review, color: '#f59e0b' },
    { name: 'Confirmed Malicious', value: metrics.status_breakdown.confirmed_malicious, color: '#f43f5e' },
    { name: 'Benign', value: metrics.status_breakdown.benign, color: '#10b981' },
    { name: 'Analysing', value: metrics.status_breakdown.analysing, color: '#3b82f6' },
    { name: 'Closed', value: metrics.status_breakdown.closed, color: '#64748b' },
  ].filter(d => d.value > 0) : [];

  return (
    <div className="p-6 space-y-6">
      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Investigations */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 tracking-wider uppercase">Total Cases</span>
            <span className="p-2 rounded-lg bg-soc-panel text-soc-accent border border-soc-border">
              <ShieldAlert className="h-4 w-4" />
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-white">{metrics?.total_cases || 0}</span>
            <span className="text-xs text-soc-muted">Forensic records</span>
          </div>
          <div className="mt-3 flex items-center gap-1.5 text-xs text-soc-accent hover:underline cursor-pointer" onClick={() => onNavigate('cases')}>
            <span>View Case Ledger</span>
            <ArrowUpRight className="h-3 w-3" />
          </div>
        </div>

        {/* Needs Review */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 relative overflow-hidden group hover:border-amber-500/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-amber-400 tracking-wider uppercase">Needs Review</span>
            <span className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <AlertTriangle className="h-4 w-4" />
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-white">{metrics?.needs_review || 0}</span>
            <span className="text-xs text-amber-300">Pending analyst triage</span>
          </div>
          <div className="mt-3 flex items-center gap-1.5 text-xs text-amber-400 hover:underline cursor-pointer" onClick={() => onNavigate('cases')}>
            <span>Filter Pending Cases</span>
            <ArrowUpRight className="h-3 w-3" />
          </div>
        </div>

        {/* High & Critical Threats */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 relative overflow-hidden group hover:border-rose-500/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-rose-400 tracking-wider uppercase">High & Critical</span>
            <span className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <Radio className="h-4 w-4 animate-pulse" />
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-white">{metrics?.high_critical_cases || 0}</span>
            <span className="text-xs text-rose-300">Threat score ≥ 50</span>
          </div>
          <div className="mt-3 text-xs text-rose-400 font-mono">
            {metrics?.malicious_count || 0} Confirmed Malicious
          </div>
        </div>

        {/* Ingested & Analysing */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 relative overflow-hidden group hover:border-emerald-500/40 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-emerald-400 tracking-wider uppercase">Benign & Cleared</span>
            <span className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <CheckCircle2 className="h-4 w-4" />
            </span>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-white">{metrics?.benign_count || 0}</span>
            <span className="text-xs text-emerald-300">Low risk baseline</span>
          </div>
          <div className="mt-3 text-xs text-slate-400 font-mono">
            {metrics?.pending_analysis || 0} currently analyzing
          </div>
        </div>
      </div>

      {/* Threat Intel Provider Health Strip */}
      <div className="rounded-xl border border-soc-border bg-soc-card p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-soc-accent" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Active Threat Intelligence Integrations</h3>
          </div>
          <span className="text-[11px] text-soc-muted font-mono">Real-time status probes</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {metrics?.integrations.map((p, idx) => (
            <div key={idx} className="flex items-center justify-between p-3 rounded-lg bg-soc-panel border border-soc-border/70">
              <div className="min-w-0">
                <p className="text-xs font-semibold text-white truncate">{p.name}</p>
                <p className="text-[10px] text-slate-400 truncate">{p.description}</p>
              </div>
              <div className="flex flex-col items-end flex-shrink-0 ml-2">
                <span className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded ${
                  p.status === 'OPERATIONAL'
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : 'bg-slate-700 text-slate-300'
                }`}>
                  {p.status}
                </span>
                {p.latency_ms > 0 && (
                  <span className="text-[9px] text-soc-muted font-mono mt-0.5">{p.latency_ms}ms</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution Bar Chart */}
        <div className="lg:col-span-2 rounded-xl border border-soc-border bg-soc-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Risk Score Distribution</h3>
              <p className="text-xs text-soc-muted">Breakdown of ingested cases by weighted risk classification</p>
            </div>
            <span className="text-xs font-mono text-soc-accent bg-soc-panel px-2.5 py-1 rounded border border-soc-border">
              Total: {metrics?.total_cases || 0}
            </span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#ffffff', fontSize: '12px' }}
                  itemStyle={{ color: '#ffffff' }}
                  labelStyle={{ color: '#ffffff', fontWeight: 600 }}
                  cursor={{ fill: '#1f293d', opacity: 0.4 }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {riskData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Case Status Distribution Pie Chart */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Triage Status</h3>
            <p className="text-xs text-soc-muted">Investigation lifecycle distribution</p>
          </div>
          <div className="h-52 my-auto">
            {statusPieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={statusPieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={75}
                    paddingAngle={3}
                  >
                    {statusPieData.map((entry, index) => (
                      <Cell key={`pie-cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#ffffff', fontSize: '12px' }}
                    itemStyle={{ color: '#ffffff' }}
                    labelStyle={{ color: '#ffffff', fontWeight: 600 }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-xs text-soc-muted">
                No active case distributions
              </div>
            )}
          </div>
          <div className="space-y-1.5 pt-2 border-t border-soc-border text-xs">
            {statusPieData.map((item, idx) => (
              <div key={idx} className="flex items-center justify-between text-slate-300">
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
                  <span>{item.name}</span>
                </div>
                <span className="font-mono font-semibold">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Lower Section: Top Domains/URLs & Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Suspicious Domains & URLs */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Globe className="h-4 w-4 text-soc-cyan" />
              Frequently Observed Attack Domains
            </h3>
            <span className="text-xs text-soc-muted">IOC Telemetry</span>
          </div>

          <div className="space-y-2">
            {metrics?.top_domains && metrics.top_domains.length > 0 ? (
              metrics.top_domains.map((dom, idx) => (
                <div key={idx} className="flex items-center justify-between p-3 rounded-lg bg-soc-panel border border-soc-border">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="font-mono text-xs text-soc-muted">#{idx + 1}</span>
                    <span className="font-mono text-xs text-white truncate">{dom.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-soc-hover text-slate-300">
                      {dom.count} cases
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-xs text-soc-muted py-4 text-center">No domain telemetry recorded yet. Ingest an email to populate.</p>
            )}
          </div>

          {metrics?.top_urls && metrics.top_urls.length > 0 && (
            <div className="pt-2">
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-2">
                <Link2 className="h-3.5 w-3.5 text-soc-accent" />
                Repeated Suspicious URLs
              </h4>
              <div className="space-y-2">
                {metrics.top_urls.slice(0, 3).map((u, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2.5 rounded-lg bg-soc-panel border border-soc-border text-xs">
                    <span className="font-mono text-slate-300 truncate max-w-xs">{u.name}</span>
                    <span className="font-mono text-slate-400 flex-shrink-0 ml-2">{u.count}x</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Recent Investigation Activity */}
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Activity className="h-4 w-4 text-soc-accent" />
              Live Investigation Activity Feed
            </h3>
            <span className="text-xs text-soc-muted font-mono">Audit trail</span>
          </div>

          <div className="space-y-3">
            {metrics?.recent_activity && metrics.recent_activity.length > 0 ? (
              metrics.recent_activity.map((act) => (
                <div
                  key={act.id}
                  onClick={() => onNavigate('cases', act.case_id)}
                  className="p-3 rounded-lg bg-soc-panel border border-soc-border hover:border-slate-600 transition-colors cursor-pointer"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-semibold text-soc-accent">{act.case_number}</span>
                    <span className="text-[11px] text-soc-muted font-mono">{act.timestamp.substring(11, 19)}</span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1 line-clamp-2">{act.note_text}</p>
                  <div className="flex items-center justify-between mt-2 pt-1.5 border-t border-soc-border/50 text-[10px] text-slate-400">
                    <span>By: <strong className="text-slate-200">{act.author}</strong></span>
                    <span className="font-mono uppercase px-1.5 py-0.2 rounded bg-soc-hover">{act.action_type}</span>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-xs text-soc-muted py-6 text-center">No analyst notes recorded yet.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
