import React, { useState } from 'react';
import {
  Search, Globe, ShieldAlert, CheckCircle2, AlertTriangle,
  Server, Link2, Hash, Copy, Check, Clock, ExternalLink, Loader2
} from 'lucide-react';
import { api } from '../services/api';
import { IndicatorLookupResult } from '../types';

export const IntelLookupView: React.FC = () => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<IndicatorLookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const data = await api.lookupIndicator(query.trim());
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (result) {
      navigator.clipboard.writeText(result.defanged);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-wide">Threat Intelligence & Observable Lookup</h2>
        <p className="text-xs text-soc-muted mt-1">
          Query suspicious URLs, hostnames, IP addresses, or file hashes against URLhaus, VirusTotal, RDAP WHOIS, and authoritative DNS resolvers.
        </p>
      </div>

      {/* Query Search Form */}
      <form onSubmit={handleLookup} className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3">
        <label className="block text-xs font-medium text-slate-300">
          Target Indicator (URL, Domain, IPv4, or File Hash)
        </label>
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-3 h-4 w-4 text-soc-muted" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="e.g. micros0ft-account-verify.com, http://185.220.101.5/office, or SHA256"
              className="w-full rounded-lg border border-soc-border bg-soc-panel pl-10 pr-4 py-2.5 text-xs font-mono text-white placeholder-slate-500 focus:border-soc-accent focus:outline-none"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-soc-accent hover:bg-blue-600 text-white text-xs font-semibold shadow-[0_0_15px_rgba(59,130,246,0.3)] transition-all disabled:opacity-50"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>Querying Feeds...</span>
              </>
            ) : (
              <>
                <Search className="h-4 w-4" />
                <span>Investigate Indicator</span>
              </>
            )}
          </button>
        </div>

        {/* Quick Example Links */}
        <div className="flex items-center gap-2 text-[11px] text-slate-400 pt-1">
          <span>Quick test presets:</span>
          <button
            type="button"
            onClick={() => setQuery('micros0ft-account-verify.com')}
            className="text-soc-cyan hover:underline font-mono"
          >
            micros0ft-account-verify.com
          </button>
          <span>•</span>
          <button
            type="button"
            onClick={() => setQuery('http://185.220.101.5/office365/login')}
            className="text-soc-cyan hover:underline font-mono"
          >
            Raw IP Phish URL
          </button>
          <span>•</span>
          <button
            type="button"
            onClick={() => setQuery('techsecuritydigest.com')}
            className="text-soc-cyan hover:underline font-mono"
          >
            techsecuritydigest.com
          </button>
        </div>
      </form>

      {error && (
        <div className="rounded-xl border border-rose-800/40 bg-rose-950/20 p-4 flex items-center gap-3 text-rose-300 text-xs">
          <AlertTriangle className="h-5 w-5 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Lookup Results Card */}
      {result && (
        <div className="rounded-xl border border-soc-border bg-soc-card p-6 space-y-6">
          {/* Header Summary */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-soc-border gap-3">
            <div className="flex items-center gap-3">
              <span className={`text-xs font-mono uppercase font-bold px-2.5 py-1 rounded border ${
                result.reputation === 'MALICIOUS' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
                result.reputation === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              }`}>
                {result.reputation}
              </span>
              <div>
                <span className="font-mono text-sm text-white font-semibold select-all">
                  {result.defanged}
                </span>
                <span className="text-[11px] text-soc-muted font-mono block">Type: {result.type}</span>
              </div>
            </div>

            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-soc-panel border border-soc-border text-xs text-slate-300 hover:text-white transition-colors self-start sm:self-auto"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copied ? 'Copied Defanged' : 'Copy Defanged'}</span>
            </button>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed font-sans bg-soc-panel/50 p-3.5 rounded-lg border border-soc-border/70">
            {result.summary}
          </p>

          {/* Provider Results Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* URLhaus Result */}
            {result.urlhaus && (
              <div className="rounded-xl border border-soc-border bg-soc-panel p-4 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white flex items-center gap-1.5">
                    <Server className="h-4 w-4 text-soc-accent" />
                    URLhaus (abuse.ch)
                  </span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                    result.urlhaus.reputation === 'malicious' ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/10 text-emerald-400'
                  }`}>
                    {result.urlhaus.status?.toUpperCase()}
                  </span>
                </div>
                <div className="space-y-1 text-slate-400 font-mono text-[11px]">
                  <div>Reputation: <strong className="text-white">{result.urlhaus.reputation}</strong></div>
                  {result.urlhaus.threat && <div>Threat Type: <span className="text-rose-400">{result.urlhaus.threat}</span></div>}
                  {result.urlhaus.reporter && <div>Reporter: <span className="text-slate-300">{result.urlhaus.reporter}</span></div>}
                  {result.urlhaus.message && <div className="text-slate-400">{result.urlhaus.message}</div>}
                </div>
              </div>
            )}

            {/* VirusTotal Result */}
            {result.virustotal && (
              <div className="rounded-xl border border-soc-border bg-soc-panel p-4 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white flex items-center gap-1.5">
                    <ShieldAlert className="h-4 w-4 text-soc-cyan" />
                    VirusTotal v3
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-soc-card text-slate-300">
                    {result.virustotal.status?.toUpperCase()}
                  </span>
                </div>
                <div className="space-y-1 text-slate-400 font-mono text-[11px]">
                  <div>Reputation: <strong className="text-white">{result.virustotal.reputation}</strong></div>
                  {result.virustotal.malicious_count !== undefined && (
                    <div>Detections: <span className="text-rose-400 font-bold">{result.virustotal.malicious_count} engines</span> flagged</div>
                  )}
                  {result.virustotal.message && <div className="text-slate-400">{result.virustotal.message}</div>}
                </div>
              </div>
            )}

            {/* RDAP WHOIS Result */}
            {result.rdap && (
              <div className="rounded-xl border border-soc-border bg-soc-panel p-4 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white flex items-center gap-1.5">
                    <Globe className="h-4 w-4 text-soc-accent" />
                    RDAP Domain Registration
                  </span>
                  {result.rdap.is_newly_registered && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                      NEW DOMAIN (&lt;30 DAYS)
                    </span>
                  )}
                </div>
                <div className="space-y-1 text-slate-400 font-mono text-[11px]">
                  <div>Registrar: <strong className="text-white">{result.rdap.registrar || 'Unknown'}</strong></div>
                  <div>Domain Age: <strong className="text-white">{result.rdap.age_days !== null ? `${result.rdap.age_days} days` : 'N/A'}</strong></div>
                  <div>Created: <span className="text-slate-300">{result.rdap.registration_date || 'N/A'}</span></div>
                </div>
              </div>
            )}

            {/* DNS Resolver Result */}
            {result.dns && (
              <div className="rounded-xl border border-soc-border bg-soc-panel p-4 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white flex items-center gap-1.5">
                    <Server className="h-4 w-4 text-emerald-400" />
                    DNS Records
                  </span>
                  <span className="text-[10px] font-mono text-emerald-400">RESOLVED</span>
                </div>
                <div className="space-y-1 text-slate-400 font-mono text-[11px]">
                  <div>MX: <span className="text-slate-200">{result.dns.mx_records?.join(', ') || 'None'}</span></div>
                  <div>A Records: <span className="text-slate-200">{result.dns.a_records?.join(', ') || 'None'}</span></div>
                  <div>TXT Records: <span className="text-slate-200">{result.dns.txt_records?.length || 0} record(s)</span></div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
