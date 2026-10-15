import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, Download, FileJson, ArrowLeft, Clock,
  Copy, Check, AlertTriangle, ShieldCheck, Globe, Link2,
  Paperclip, FileText, ChevronDown, Activity, Send,
  HelpCircle, ExternalLink, RefreshCw, Eye, AlertCircle
} from 'lucide-react';
import { CaseDetail, CaseStatus, Finding } from '../types';
import { api } from '../services/api';
import { RiskBadge } from '../components/RiskBadge';
import { StatusBadge } from '../components/StatusBadge';
import { ConfirmationModal } from '../components/ConfirmationModal';

interface CaseDetailViewProps {
  caseId: number;
  onBack: () => void;
}

export const CaseDetailView: React.FC<CaseDetailViewProps> = ({ caseId, onBack }) => {
  const [caseData, setCaseData] = useState<CaseDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Active tab
  const [activeTab, setActiveTab] = useState<'overview' | 'headers' | 'urls' | 'attachments' | 'risk_math' | 'preview' | 'notes'>('overview');

  // Copy toast state
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedIndicator, setCopiedIndicator] = useState<string | null>(null);

  // Status Change Confirmation Modal
  const [modalOpen, setModalOpen] = useState(false);
  const [pendingStatus, setPendingStatus] = useState<CaseStatus | null>(null);

  // New Note
  const [newNote, setNewNote] = useState('');
  const [submittingNote, setSubmittingNote] = useState(false);

  // Expanded Redirects Cache
  const [expandedUrls, setExpandedUrls] = useState<Record<string, any>>({});
  const [expandingUrl, setExpandingUrl] = useState<string | null>(null);

  const fetchCaseDetail = async () => {
    try {
      setLoading(true);
      const data = await api.getCaseDetail(caseId);
      setCaseData(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Failed to load case detail');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCaseDetail();
  }, [caseId]);

  const handleCopyHash = () => {
    if (caseData?.file_hash_sha256) {
      navigator.clipboard.writeText(caseData.file_hash_sha256);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  const handleCopyText = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedIndicator(val);
    setTimeout(() => setCopiedIndicator(null), 2000);
  };

  const handleStatusSelectChange = (newStatus: CaseStatus) => {
    if (newStatus === 'CONFIRMED_MALICIOUS' || newStatus === 'BENIGN') {
      setPendingStatus(newStatus);
      setModalOpen(true);
    } else {
      executeStatusUpdate(newStatus);
    }
  };

  const executeStatusUpdate = async (status: CaseStatus, reason?: string, confirmed = false) => {
    try {
      await api.updateCaseStatus(caseId, status, reason, confirmed);
      fetchCaseDetail();
    } catch (err: any) {
      alert(err.message || 'Failed to update status');
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    try {
      setSubmittingNote(true);
      await api.addNote(caseId, newNote.trim());
      setNewNote('');
      fetchCaseDetail();
    } catch (err: any) {
      alert(err.message || 'Failed to add note');
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleExpandRedirect = async (url: string) => {
    try {
      setExpandingUrl(url);
      const res = await api.expandUrl(url);
      setExpandedUrls((prev) => ({ ...prev, [url]: res }));
    } catch (err: any) {
      alert(err.message || 'Redirect expansion failed');
    } finally {
      setExpandingUrl(null);
    }
  };

  if (loading && !caseData) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <RefreshCw className="h-8 w-8 animate-spin text-soc-accent" />
          <p className="text-sm font-mono text-soc-muted">Loading Investigation Forensic Workspace...</p>
        </div>
      </div>
    );
  }

  if (error || !caseData) {
    return (
      <div className="p-8 max-w-xl mx-auto">
        <div className="rounded-xl border border-rose-800/40 bg-rose-950/20 p-6 text-center">
          <AlertCircle className="mx-auto h-8 w-8 text-rose-400 mb-2" />
          <h3 className="text-base font-semibold text-rose-200">Failed to Load Investigation</h3>
          <p className="text-xs text-rose-300 mt-1">{error}</p>
          <button
            onClick={onBack}
            className="mt-4 px-4 py-2 rounded-lg bg-soc-panel hover:bg-soc-hover border border-soc-border text-xs font-semibold text-white"
          >
            Return to Case List
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner Navigation */}
      <div className="flex items-center justify-between pb-4 border-b border-soc-border">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-lg border border-soc-border bg-soc-panel hover:bg-soc-hover text-slate-300 hover:text-white transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div>
            <div className="flex items-center gap-2.5">
              <span className="font-mono text-sm font-bold text-soc-accent">{caseData.case_number}</span>
              <RiskBadge level={caseData.risk_level} score={caseData.risk_score} size="sm" />
              <StatusBadge status={caseData.status} size="sm" />
            </div>
            <h2 className="text-base font-semibold text-white mt-0.5 truncate max-w-2xl">
              {caseData.subject || 'Investigation Evidence'}
            </h2>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5">
          {/* Status Change Selector */}
          <div className="flex items-center gap-2 bg-soc-panel px-3 py-1.5 rounded-lg border border-soc-border">
            <span className="text-xs text-slate-400 font-medium">Status:</span>
            <select
              value={caseData.status}
              onChange={(e) => handleStatusSelectChange(e.target.value as CaseStatus)}
              className="bg-transparent text-xs text-white font-medium focus:outline-none cursor-pointer"
            >
              <option value="NEW" className="bg-soc-card">NEW</option>
              <option value="ANALYSING" className="bg-soc-card">ANALYSING</option>
              <option value="NEEDS_REVIEW" className="bg-soc-card">NEEDS REVIEW</option>
              <option value="CONFIRMED_MALICIOUS" className="bg-soc-card">CONFIRMED MALICIOUS</option>
              <option value="BENIGN" className="bg-soc-card">BENIGN</option>
              <option value="CLOSED" className="bg-soc-card">CLOSED</option>
            </select>
          </div>

          {/* Download PDF Report */}
          <a
            href={api.getPdfReportUrl(caseData.id)}
            download
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-soc-panel hover:bg-soc-hover border border-soc-border text-xs font-semibold text-white transition-colors"
          >
            <Download className="h-3.5 w-3.5 text-soc-accent" />
            <span>Forensic PDF</span>
          </a>

          {/* Download JSON Export */}
          <a
            href={api.getJsonExportUrl(caseData.id)}
            download
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-soc-panel hover:bg-soc-hover border border-soc-border text-xs font-semibold text-white transition-colors"
          >
            <FileJson className="h-3.5 w-3.5 text-soc-cyan" />
            <span>JSON Package</span>
          </a>
        </div>
      </div>

      {/* Evidence Summary Strip */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 p-4 rounded-xl border border-soc-border bg-soc-card text-xs">
        <div>
          <span className="text-slate-400 block text-[11px]">Sender Identity</span>
          <span className="font-semibold text-white truncate block mt-0.5">{caseData.sender || 'Unknown'}</span>
          <span className="font-mono text-soc-muted text-[10px] truncate block">{caseData.sender_domain || 'No Domain'}</span>
        </div>

        <div>
          <span className="text-slate-400 block text-[11px]">Evidence SHA-256 Hash</span>
          <div className="flex items-center gap-1.5 mt-0.5">
            <span className="font-mono text-slate-300 text-[11px] truncate">{caseData.file_hash_sha256.substring(0, 20)}...</span>
            <button
              onClick={handleCopyHash}
              className="p-1 rounded hover:bg-soc-panel text-soc-muted hover:text-white"
              title="Copy Evidence SHA-256"
            >
              {copiedHash ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>

        <div>
          <span className="text-slate-400 block text-[11px]">Analysis Completeness</span>
          <span className="font-mono text-white block mt-0.5">
            {caseData.completed_checks} completed / {caseData.unavailable_checks} unavail
          </span>
          <span className="text-[10px] text-soc-cyan font-mono">Confidence: {caseData.confidence}</span>
        </div>

        <div>
          <span className="text-slate-400 block text-[11px]">Investigation Ingest Time</span>
          <span className="font-mono text-slate-300 block mt-0.5">
            {caseData.created_at.substring(0, 19).replace('T', ' ')} UTC
          </span>
          <span className="text-[10px] text-soc-muted font-mono">File: {caseData.original_file_name || 'raw.eml'}</span>
        </div>
      </div>

      {/* Forensic Workspace Tabs */}
      <div className="flex border-b border-soc-border overflow-x-auto text-xs font-semibold">
        {[
          { id: 'overview', label: 'Briefing & MITRE ATT&CK', count: caseData.findings.length },
          { id: 'headers', label: 'Headers & Authentication' },
          { id: 'urls', label: 'URLs & Observables', count: caseData.indicators.length },
          { id: 'attachments', label: 'Attachments', count: caseData.attachments.length },
          { id: 'risk_math', label: 'Explainable Risk Engine' },
          { id: 'preview', label: 'Email Preview' },
          { id: 'notes', label: 'Notes & Timeline', count: caseData.notes.length },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-all whitespace-nowrap ${
              activeTab === tab.id
                ? 'border-soc-accent text-white bg-soc-panel/30 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>{tab.label}</span>
            {typeof tab.count === 'number' && (
              <span className={`px-1.5 py-0.2 rounded-full font-mono text-[10px] ${
                activeTab === tab.id ? 'bg-soc-accent text-white' : 'bg-soc-panel text-slate-400'
              }`}>
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* TAB CONTENT 1: Executive Briefing & MITRE ATT&CK */}
      {activeTab === 'overview' && (
        <div className="space-y-5">
          {/* Executive Summary Card */}
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-soc-accent" />
              Executive Forensic Briefing
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed font-sans">
              {caseData.executive_summary || 'Analysis complete. Review itemized findings below.'}
            </p>
          </div>

          {/* MITRE ATT&CK Techniques */}
          {caseData.mitre_techniques && caseData.mitre_techniques.length > 0 && (
            <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Activity className="h-4 w-4 text-soc-cyan" />
                Mapped MITRE ATT&CK Techniques
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {caseData.mitre_techniques.map((tech) => (
                  <div key={tech.id} className="p-3.5 rounded-lg bg-soc-panel border border-soc-border space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-soc-cyan">{tech.id}</span>
                      <span className="text-[11px] font-semibold text-white">{tech.name}</span>
                    </div>
                    <p className="text-xs text-slate-400 leading-normal">{tech.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Key Findings List */}
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Top Identified Threat Indicators</h3>
              <span className="text-xs text-soc-muted font-mono">{caseData.findings.length} findings recorded</span>
            </div>

            <div className="space-y-2.5">
              {caseData.findings.map((f) => (
                <div key={f.id} className="p-3.5 rounded-lg bg-soc-panel border border-soc-border space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-white text-xs">{f.indicator_name}</span>
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-soc-card text-soc-muted">
                        {f.category}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-mono text-rose-400 font-semibold">+{f.points_added} pts</span>
                      <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded ${
                        f.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300' :
                        f.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300' :
                        f.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-300' : 'bg-slate-700 text-slate-300'
                      }`}>
                        {f.severity}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 bg-soc-card/60 p-2.5 rounded border border-soc-border/50 font-mono">
                    {f.observed_evidence}
                  </p>

                  <p className="text-xs text-slate-400">{f.explanation}</p>

                  {f.recommended_step && (
                    <div className="pt-1 text-xs text-soc-cyan flex items-center gap-1.5">
                      <strong>Remediation:</strong> {f.recommended_step}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT 2: Headers & Authentication */}
      {activeTab === 'headers' && (
        <div className="space-y-6">
          {/* Authentication Badge Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* SPF Card */}
            <div className="rounded-xl border border-soc-border bg-soc-card p-4 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-white">SPF Authentication</span>
                <span className={`font-mono text-xs font-semibold px-2 py-0.5 rounded ${
                  caseData.auth_summary?.spf?.verdict === 'PASS' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'
                }`}>
                  {caseData.auth_summary?.spf?.verdict || 'NONE'}
                </span>
              </div>
              <div className="text-xs space-y-1 text-slate-400">
                <div className="flex justify-between">
                  <span>Recorded Header:</span>
                  <span className="font-mono text-slate-200">{caseData.auth_summary?.spf?.recorded?.toUpperCase() || 'NONE'}</span>
                </div>
                <div className="flex justify-between">
                  <span>DNS Record:</span>
                  <span className="font-mono text-slate-200">{caseData.auth_summary?.spf?.dns_record_found ? 'Published' : 'Missing'}</span>
                </div>
                <div className="flex justify-between">
                  <span>Alignment:</span>
                  <span className="font-mono text-slate-200">{caseData.auth_summary?.spf?.alignment ? 'Aligned' : 'Unaligned'}</span>
                </div>
              </div>
              {caseData.auth_summary?.spf?.dns_record && (
                <div className="p-2 rounded bg-soc-panel font-mono text-[10px] text-slate-300 truncate">
                  {caseData.auth_summary.spf.dns_record}
                </div>
              )}
            </div>

            {/* DKIM Card */}
            <div className="rounded-xl border border-soc-border bg-soc-card p-4 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-white">DKIM Cryptographic Signature</span>
                <span className={`font-mono text-xs font-semibold px-2 py-0.5 rounded ${
                  caseData.auth_summary?.dkim?.verdict === 'PASS' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-700 text-slate-300'
                }`}>
                  {caseData.auth_summary?.dkim?.verdict || 'NONE'}
                </span>
              </div>
              <div className="text-xs space-y-1 text-slate-400">
                <div className="flex justify-between">
                  <span>Signature Present:</span>
                  <span className="font-mono text-slate-200">{caseData.auth_summary?.dkim?.signature_present ? 'Yes' : 'No'}</span>
                </div>
                <div className="flex justify-between">
                  <span>Selector / Domain:</span>
                  <span className="font-mono text-slate-200 truncate max-w-[120px]">{caseData.auth_summary?.dkim?.selector || 'N/A'} / {caseData.auth_summary?.dkim?.domain || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span>DNS Public Key:</span>
                  <span className="font-mono text-slate-200">{caseData.auth_summary?.dkim?.dns_key_found ? 'Verified' : 'Unavailable'}</span>
                </div>
              </div>
            </div>

            {/* DMARC Card */}
            <div className="rounded-xl border border-soc-border bg-soc-card p-4 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-white">DMARC Policy Enforcement</span>
                <span className={`font-mono text-xs font-semibold px-2 py-0.5 rounded ${
                  caseData.auth_summary?.dmarc?.verdict === 'PASS' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'
                }`}>
                  {caseData.auth_summary?.dmarc?.verdict || 'NONE'}
                </span>
              </div>
              <div className="text-xs space-y-1 text-slate-400">
                <div className="flex justify-between">
                  <span>Enforcement Policy:</span>
                  <span className="font-mono text-slate-200">{caseData.auth_summary?.dmarc?.policy?.toUpperCase() || 'NONE'}</span>
                </div>
                <div className="flex justify-between">
                  <span>DNS Record:</span>
                  <span className="font-mono text-slate-200">{caseData.auth_summary?.dmarc?.dns_record_found ? 'Published' : 'Missing'}</span>
                </div>
              </div>
              {caseData.auth_summary?.dmarc?.dns_record && (
                <div className="p-2 rounded bg-soc-panel font-mono text-[10px] text-slate-300 truncate">
                  {caseData.auth_summary.dmarc.dns_record}
                </div>
              )}
            </div>
          </div>

          {/* Spoofing & Mismatch Alerts */}
          {caseData.auth_summary?.mismatches && (
            <div className="space-y-2">
              {caseData.auth_summary.mismatches.display_name_spoofing && (
                <div className="p-3.5 rounded-lg border border-rose-800/50 bg-rose-950/30 text-rose-300 text-xs flex items-center gap-3">
                  <AlertTriangle className="h-5 w-5 text-rose-400 flex-shrink-0" />
                  <div>
                    <strong className="text-rose-200">Display Name Impersonation Detected:</strong> The sender display name masquerades as {caseData.auth_summary.mismatches.spoofed_brand || 'protected brand'} while utilizing an unauthorized domain ({caseData.sender_domain}).
                  </div>
                </div>
              )}

              {caseData.auth_summary.mismatches.reply_to_mismatch && (
                <div className="p-3.5 rounded-lg border border-amber-800/50 bg-amber-950/30 text-amber-300 text-xs flex items-center gap-3">
                  <AlertTriangle className="h-5 w-5 text-amber-400 flex-shrink-0" />
                  <div>
                    <strong className="text-amber-200">Reply-To Routing Anomaly:</strong> The Reply-To header diverts recipient responses away from the From sender domain.
                  </div>
                </div>
              )}

              {caseData.auth_summary.mismatches.lookalike_domain && (
                <div className="p-3.5 rounded-lg border border-rose-800/50 bg-rose-950/30 text-rose-300 text-xs flex items-center gap-3">
                  <AlertTriangle className="h-5 w-5 text-rose-400 flex-shrink-0" />
                  <div>
                    <strong className="text-rose-200">Typo-Squatted Domain:</strong> Domain closely mimics {caseData.auth_summary.mismatches.lookalike_brand} through homoglyph characters or edit distance manipulations.
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Received-Hop Visual Diagram */}
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Globe className="h-4 w-4 text-soc-accent" />
              Received Relay Hops (Reverse Chronological Trace)
            </h3>

            {caseData.received_hops && caseData.received_hops.length > 0 ? (
              <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-soc-border">
                {caseData.received_hops.map((hop, idx) => (
                  <div key={idx} className="relative">
                    <div className="absolute -left-[27px] top-1.5 h-3.5 w-3.5 rounded-full border-2 border-soc-accent bg-soc-card" />
                    <div className="p-3.5 rounded-lg bg-soc-panel border border-soc-border text-xs space-y-1.5">
                      <div className="flex items-center justify-between font-mono">
                        <span className="font-bold text-soc-accent">Hop #{hop.hop_index}</span>
                        <span className="text-[11px] text-slate-400">{hop.date_str || 'Timestamp recorded'}</span>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300 font-mono text-[11px]">
                        <div>From IP: <strong className="text-white">{hop.from_ip || 'Internal / N/A'}</strong></div>
                        <div>By Host: <span className="text-slate-400">{hop.by_host || 'Gateway'}</span></div>
                      </div>
                      {hop.is_private_ip && (
                        <span className="inline-block text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                          RFC 1918 Private Subnet Origin
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-soc-muted">No Received headers were extracted from message headers.</p>
            )}
          </div>

          {/* Raw Headers Drawer */}
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white">Full Parsed RFC 822 Headers</h3>
            <pre className="p-4 rounded-lg bg-soc-bg border border-soc-border text-[11px] font-mono text-slate-300 overflow-x-auto max-h-72">
              {caseData.raw_headers || 'No raw headers available'}
            </pre>
          </div>
        </div>
      )}

      {/* TAB CONTENT 3: URLs & Observables */}
      {activeTab === 'urls' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Link2 className="h-4 w-4 text-soc-cyan" />
                Extracted URLs & Hyperlinks ({caseData.indicators.length})
              </h3>
              <span className="text-xs text-soc-muted font-mono">Auto-Defanged for Analyst Safety</span>
            </div>

            {caseData.indicators.length > 0 ? (
              <div className="space-y-3">
                {caseData.indicators.map((ind) => {
                  const expanded = expandedUrls[ind.raw_value];
                  const isExpanding = expandingUrl === ind.raw_value;
                  return (
                    <div key={ind.id} className="p-4 rounded-lg bg-soc-panel border border-soc-border space-y-3">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-semibold ${
                            ind.reputation === 'MALICIOUS' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                            ind.reputation === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                            'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20'
                          }`}>
                            {ind.reputation}
                          </span>
                          <span className="font-mono text-xs text-white truncate max-w-lg select-all">
                            {ind.defanged_value}
                          </span>
                        </div>

                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleCopyText(ind.defanged_value)}
                            className="flex items-center gap-1 px-2.5 py-1 rounded bg-soc-card border border-soc-border text-[11px] text-slate-300 hover:text-white transition-colors"
                          >
                            {copiedIndicator === ind.defanged_value ? (
                              <>
                                <Check className="h-3 w-3 text-emerald-400" />
                                <span>Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy className="h-3 w-3" />
                                <span>Copy Defanged</span>
                              </>
                            )}
                          </button>

                          <button
                            onClick={() => handleExpandRedirect(ind.raw_value)}
                            disabled={isExpanding}
                            className="flex items-center gap-1 px-2.5 py-1 rounded bg-soc-accent/20 hover:bg-soc-accent/30 border border-soc-accent/40 text-[11px] text-soc-accent font-semibold transition-colors disabled:opacity-50"
                          >
                            {isExpanding ? (
                              <RefreshCw className="h-3 w-3 animate-spin" />
                            ) : (
                              <ExternalLink className="h-3 w-3" />
                            )}
                            <span>Follow Redirects</span>
                          </button>
                        </div>
                      </div>

                      {/* Flags Badges */}
                      {ind.flags && ind.flags.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {ind.flags.map((flag, fIdx) => (
                            <span key={fIdx} className="text-[10px] font-mono px-2 py-0.5 rounded bg-soc-card border border-soc-border text-amber-400">
                              {flag}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Expanded Redirect Results */}
                      {expanded && (
                        <div className="p-3 rounded bg-soc-bg border border-soc-border text-xs space-y-1.5 font-mono">
                          <div className="flex items-center justify-between text-[11px]">
                            <span className="text-soc-cyan font-bold">Redirect Hops: {expanded.hops_count}</span>
                            <span className="text-slate-400">Final HTTP Status: {expanded.last_status || '200 OK'}</span>
                          </div>
                          <div className="text-slate-300">
                            <strong>Final Destination:</strong> {expanded.final_defanged}
                          </div>
                          {expanded.chain && expanded.chain.length > 1 && (
                            <div className="space-y-0.5 pt-1 text-[10px] text-slate-400">
                              {expanded.chain.map((cUrl: string, cIdx: number) => (
                                <div key={cIdx}>↳ [{cIdx + 1}] {cUrl}</div>
                              ))}
                            </div>
                          )}
                          {expanded.aborted && (
                            <div className="text-rose-400 text-[11px] pt-1">
                              <strong>Halt:</strong> {expanded.abort_reason}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-xs text-soc-muted py-6 text-center">No hyperlinks extracted from body content.</p>
            )}
          </div>
        </div>
      )}

      {/* TAB CONTENT 4: Attachments */}
      {activeTab === 'attachments' && (
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Paperclip className="h-4 w-4 text-soc-accent" />
            Extracted File Attachments ({caseData.attachments.length})
          </h3>

          {caseData.attachments.length > 0 ? (
            <div className="space-y-3">
              {caseData.attachments.map((att) => (
                <div key={att.id} className="p-4 rounded-lg bg-soc-panel border border-soc-border space-y-3 text-xs">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-white font-mono text-sm">{att.filename}</span>
                      <RiskBadge level={att.risk_level} size="sm" />
                    </div>
                    <span className="font-mono text-soc-muted">{(att.size_bytes / 1024).toFixed(1)} KB</span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-slate-300 font-mono text-[11px]">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-500">SHA-256:</span>
                      <span className="text-slate-200 select-all truncate">{att.sha256_hash}</span>
                      <button onClick={() => handleCopyText(att.sha256_hash)} className="text-slate-400 hover:text-white">
                        <Copy className="h-3 w-3" />
                      </button>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-slate-500">MD5:</span>
                      <span className="text-slate-200 select-all">{att.md5_hash}</span>
                    </div>
                  </div>

                  {att.risk_factors && att.risk_factors.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 pt-1">
                      {att.risk_factors.map((rf, rIdx) => (
                        <span key={rIdx} className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                          {rf}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-soc-muted py-6 text-center">No attachments detected in this message.</p>
          )}
        </div>
      )}

      {/* TAB CONTENT 5: Explainable Risk Math */}
      {activeTab === 'risk_math' && (
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white">Explainable Risk Calculation Ledger</h3>
              <p className="text-xs text-soc-muted">Transparent point breakdown and indicator weights</p>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-slate-400">Total Risk Score:</span>
              <RiskBadge level={caseData.risk_level} score={caseData.risk_score} size="lg" />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-soc-panel border-b border-soc-border text-slate-400 font-medium">
                <tr>
                  <th className="py-2.5 px-3">Indicator</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Points</th>
                  <th className="py-2.5 px-3">Observed Evidence</th>
                  <th className="py-2.5 px-3">Source & Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border font-mono">
                {caseData.findings.map((f) => (
                  <tr key={f.id} className="hover:bg-soc-panel/40">
                    <td className="py-3 px-3 font-semibold text-white">{f.indicator_name}</td>
                    <td className="py-3 px-3 text-slate-400 uppercase text-[10px]">{f.category}</td>
                    <td className="py-3 px-3">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                        f.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300' :
                        f.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300' : 'bg-slate-700 text-slate-300'
                      }`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-rose-400 font-bold">+{f.points_added}</td>
                    <td className="py-3 px-3 text-slate-300 max-w-xs truncate">{f.observed_evidence}</td>
                    <td className="py-3 px-3 text-[11px] text-slate-400">{f.source} ({f.confidence})</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB CONTENT 6: Email Preview */}
      {activeTab === 'preview' && (
        <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Eye className="h-4 w-4 text-soc-accent" />
              Isolated Email Body Preview
            </h3>
            <span className="text-[11px] font-mono text-emerald-400 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
              Sandboxed Execution Barrier Active
            </span>
          </div>

          {caseData.raw_body_text ? (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 mb-2">Plain Text Content</h4>
              <pre className="p-4 rounded-lg bg-soc-bg border border-soc-border text-xs font-mono text-slate-300 whitespace-pre-wrap overflow-x-auto max-h-96">
                {caseData.raw_body_text}
              </pre>
            </div>
          ) : (
            <p className="text-xs text-soc-muted">No plain text body extracted.</p>
          )}

          {caseData.raw_body_html && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 mb-2">Sanitized HTML Render</h4>
              <iframe
                title="Sanitized Email Preview"
                srcDoc={caseData.raw_body_html}
                sandbox=""
                className="w-full h-96 rounded-lg border border-soc-border bg-white"
              />
            </div>
          )}
        </div>
      )}

      {/* TAB CONTENT 7: Notes & Timeline */}
      {activeTab === 'notes' && (
        <div className="space-y-6">
          {/* Add Note Form */}
          <form onSubmit={handleAddNote} className="rounded-xl border border-soc-border bg-soc-card p-4 space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Activity className="h-4 w-4 text-soc-accent" />
              Add Investigation Note
            </h3>
            <textarea
              rows={3}
              value={newNote}
              onChange={(e) => setNewNote(e.target.value)}
              placeholder="Record forensic observation, containment action, or escalation details..."
              className="w-full rounded-lg border border-soc-border bg-soc-panel p-3 text-xs text-white placeholder-slate-500 focus:border-soc-accent focus:outline-none"
            />
            <div className="flex justify-end">
              <button
                type="submit"
                disabled={submittingNote || !newNote.trim()}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-soc-accent hover:bg-blue-600 text-white text-xs font-semibold shadow-[0_0_15px_rgba(59,130,246,0.3)] transition-all disabled:opacity-50"
              >
                <Send className="h-3.5 w-3.5" />
                <span>Save Note</span>
              </button>
            </div>
          </form>

          {/* Timeline Feed */}
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
            <h3 className="text-sm font-semibold text-white">Chronological Forensic Log</h3>
            <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-soc-border">
              {caseData.notes.map((n) => (
                <div key={n.id} className="relative">
                  <div className="absolute -left-[27px] top-1.5 h-3.5 w-3.5 rounded-full border-2 border-soc-cyan bg-soc-card" />
                  <div className="p-3.5 rounded-lg bg-soc-panel border border-soc-border text-xs space-y-1">
                    <div className="flex items-center justify-between text-slate-400 font-mono text-[11px]">
                      <span className="font-bold text-white">{n.author_name}</span>
                      <span>{n.created_at.substring(0, 19).replace('T', ' ')}</span>
                    </div>
                    <p className="text-slate-300 font-sans leading-relaxed">{n.note_text}</p>
                    <span className="inline-block text-[10px] font-mono uppercase text-soc-cyan mt-1">
                      {n.action_type}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Status Change Confirmation Modal */}
      {pendingStatus && (
        <ConfirmationModal
          isOpen={modalOpen}
          title={`Confirm Case Status: ${pendingStatus.replace('_', ' ')}`}
          message={`Are you certain you want to mark this investigation as ${pendingStatus.replace('_', ' ')}? This establishes an official assessment in the forensic audit ledger.`}
          targetStatus={pendingStatus}
          onConfirm={(reason) => {
            executeStatusUpdate(pendingStatus, reason, true);
            setModalOpen(false);
          }}
          onCancel={() => setModalOpen(false)}
        />
      )}
    </div>
  );
};
