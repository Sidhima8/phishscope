import React, { useState, useEffect } from 'react';
import {
  Settings, Server, Shield, Key, Users,
  CheckCircle2, AlertTriangle, ExternalLink, RefreshCw
} from 'lucide-react';
import { api } from '../services/api';

export const SettingsView: React.FC = () => {
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStatus();
  }, []);

  const loadStatus = async () => {
    try {
      setLoading(true);
      const res = await api.getIntegrationsStatus();
      setIntegrations(res.providers || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-wide">Settings & Integrations</h2>
        <p className="text-xs text-soc-muted mt-1">
          Review connected threat intelligence feeds, engine scoring parameters, and access controls.
        </p>
      </div>

      {/* Threat Intel Provider Configuration */}
      <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-soc-border">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-soc-accent" />
            <h3 className="text-sm font-semibold text-white">External Intelligence Providers</h3>
          </div>
          <button
            onClick={loadStatus}
            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-soc-panel hover:bg-soc-hover border border-soc-border text-xs text-slate-300"
          >
            <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
            <span>Probe Providers</span>
          </button>
        </div>

        <div className="space-y-3">
          {integrations.map((p) => (
            <div key={p.id} className="p-4 rounded-lg bg-soc-panel border border-soc-border flex items-center justify-between gap-4 text-xs">
              <div className="space-y-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-white">{p.name}</span>
                  {p.requires_api_key && (
                    <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-soc-card text-amber-400 border border-amber-500/20">
                      API KEY REQUIRED
                    </span>
                  )}
                </div>
                <p className="text-slate-400">{p.description}</p>
              </div>

              <div className="flex-shrink-0">
                <span className={`font-mono text-xs font-semibold px-2.5 py-1 rounded ${
                  p.status === 'OPERATIONAL'
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : 'bg-slate-700 text-slate-300'
                }`}>
                  {p.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Risk Engine Scoring Parameters */}
      <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3">
        <div className="flex items-center gap-2 pb-3 border-b border-soc-border">
          <Shield className="h-4 w-4 text-soc-cyan" />
          <h3 className="text-sm font-semibold text-white">Explainable Risk Engine Weights</h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div className="p-3.5 rounded-lg bg-soc-panel border border-soc-border space-y-1">
            <span className="text-emerald-400 font-bold block">LOW RISK</span>
            <span className="font-mono text-white text-sm">0 – 24 pts</span>
            <p className="text-[11px] text-soc-muted">Standard operational email; benign patterns.</p>
          </div>

          <div className="p-3.5 rounded-lg bg-soc-panel border border-soc-border space-y-1">
            <span className="text-yellow-400 font-bold block">MEDIUM RISK</span>
            <span className="font-mono text-white text-sm">25 – 49 pts</span>
            <p className="text-[11px] text-soc-muted">Suspicious anomalies; requires analyst review.</p>
          </div>

          <div className="p-3.5 rounded-lg bg-soc-panel border border-soc-border space-y-1">
            <span className="text-amber-400 font-bold block">HIGH RISK</span>
            <span className="font-mono text-white text-sm">50 – 74 pts</span>
            <p className="text-[11px] text-soc-muted">Probable phishing; high spoofing/urgency.</p>
          </div>

          <div className="p-3.5 rounded-lg bg-soc-panel border border-soc-border space-y-1">
            <span className="text-rose-400 font-bold block">CRITICAL RISK</span>
            <span className="font-mono text-white text-sm">75 – 100 pts</span>
            <p className="text-[11px] text-soc-muted">Active malicious campaign or weaponized payload.</p>
          </div>
        </div>
      </div>

      {/* Role-Based Access Reference */}
      <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3">
        <div className="flex items-center gap-2 pb-3 border-b border-soc-border">
          <Users className="h-4 w-4 text-soc-accent" />
          <h3 className="text-sm font-semibold text-white">Access Control & Analyst Profiles</h3>
        </div>

        <div className="space-y-2 text-xs font-mono">
          <div className="p-3 rounded-lg bg-soc-panel border border-soc-border flex items-center justify-between">
            <div>
              <strong className="text-white">Lead Analyst:</strong> analyst@phishscope.local
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-soc-accent/20 text-soc-accent font-semibold">
              ROLE: ANALYST
            </span>
          </div>

          <div className="p-3 rounded-lg bg-soc-panel border border-soc-border flex items-center justify-between">
            <div>
              <strong className="text-white">Administrator:</strong> admin@phishscope.local
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-semibold">
              ROLE: ADMIN
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
