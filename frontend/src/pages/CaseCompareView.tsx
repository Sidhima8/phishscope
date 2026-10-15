import React, { useState, useEffect } from 'react';
import { GitCompare, AlertTriangle, ShieldAlert, ArrowLeft, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';
import { CaseListItem } from '../types';
import { RiskBadge } from '../components/RiskBadge';

interface CaseCompareViewProps {
  initialCaseIds?: number[];
  onBack: () => void;
  onOpenCase: (caseId: number) => void;
}

export const CaseCompareView: React.FC<CaseCompareViewProps> = ({ initialCaseIds = [], onBack, onOpenCase }) => {
  const [availableCases, setAvailableCases] = useState<CaseListItem[]>([]);
  const [selectedIds, setSelectedIds] = useState<number[]>(initialCaseIds);
  const [comparison, setComparison] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadAllCases();
  }, []);

  useEffect(() => {
    if (selectedIds.length >= 2) {
      runComparison(selectedIds);
    } else {
      setComparison(null);
    }
  }, [selectedIds]);

  const loadAllCases = async () => {
    try {
      const data = await api.listCases();
      setAvailableCases(data);
    } catch (e) {
      console.error(e);
    }
  };

  const runComparison = async (ids: number[]) => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.compareCases(ids);
      setComparison(res);
    } catch (err: any) {
      setError(err.message || 'Comparison failed');
    } finally {
      setLoading(false);
    }
  };

  const toggleCase = (id: number) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-soc-border">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-lg border border-soc-border bg-soc-panel hover:bg-soc-hover text-slate-300 hover:text-white transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div>
            <h2 className="text-xl font-bold text-white tracking-wide">Case Comparison & Correlation</h2>
            <p className="text-xs text-soc-muted">
              Correlate multiple phishing campaigns, shared threat infrastructure, and observable IOC overlap.
            </p>
          </div>
        </div>
      </div>

      {/* Case Selector Pills */}
      <div className="rounded-xl border border-soc-border bg-soc-card p-4 space-y-3">
        <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
          Select Cases to Correlate ({selectedIds.length} selected - minimum 2 required):
        </span>
        <div className="flex flex-wrap gap-2">
          {availableCases.map((c) => {
            const isSelected = selectedIds.includes(c.id);
            return (
              <button
                key={c.id}
                onClick={() => toggleCase(c.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-all ${
                  isSelected
                    ? 'border-soc-accent bg-soc-accent/20 text-white font-bold shadow-[0_0_12px_rgba(59,130,246,0.3)]'
                    : 'border-soc-border bg-soc-panel text-slate-400 hover:text-white'
                }`}
              >
                <span>{c.case_number}</span>
                <span className="text-[10px] text-soc-muted truncate max-w-[150px]">{c.subject}</span>
              </button>
            );
          })}
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-800/40 bg-rose-950/20 p-4 flex items-center gap-3 text-rose-300 text-xs">
          <AlertTriangle className="h-5 w-5 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Comparison Results */}
      {comparison && (
        <div className="space-y-6">
          {/* Summary Correlation Box */}
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <GitCompare className="h-4 w-4 text-soc-accent" />
                Infrastructure Overlap Summary
              </h3>
              <div className="flex items-center gap-2 text-xs font-mono text-soc-cyan bg-soc-panel px-3 py-1 rounded border border-soc-border">
                <span>Jaccard IOC Similarity:</span>
                <strong className="text-white">{(comparison.similarity_score * 100).toFixed(0)}%</strong>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed font-sans bg-soc-panel p-3.5 rounded-lg border border-soc-border">
              {comparison.analysis_notes}
            </p>

            {comparison.common_indicators && comparison.common_indicators.length > 0 && (
              <div className="pt-2">
                <span className="text-xs font-bold text-rose-400 block mb-2">Identical Shared Indicators (IOC Match):</span>
                <div className="space-y-1">
                  {comparison.common_indicators.map((ioc: string, idx: number) => (
                    <div key={idx} className="font-mono text-xs text-rose-300 bg-rose-950/30 p-2 rounded border border-rose-800/40 select-all">
                      {ioc}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Side-by-Side Comparison Matrix */}
          <div className="rounded-xl border border-soc-border bg-soc-card p-5 space-y-4">
            <h3 className="text-sm font-semibold text-white">Side-by-Side Forensic Matrix</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {comparison.cases.map((c: any) => (
                <div key={c.case_id} className="rounded-xl border border-soc-border bg-soc-panel p-4 space-y-3 text-xs">
                  <div className="flex items-center justify-between pb-2 border-b border-soc-border">
                    <button
                      onClick={() => onOpenCase(c.case_id)}
                      className="font-mono font-bold text-soc-accent hover:underline"
                    >
                      {c.case_number}
                    </button>
                    <RiskBadge level={c.risk_level} score={c.risk_score} size="sm" />
                  </div>

                  <div>
                    <span className="text-slate-400 block text-[10px]">Subject</span>
                    <span className="font-semibold text-white block mt-0.5 truncate">{c.subject}</span>
                  </div>

                  <div>
                    <span className="text-slate-400 block text-[10px]">Sender Domain</span>
                    <span className="font-mono text-soc-cyan block mt-0.5">{c.sender_domain || 'N/A'}</span>
                  </div>

                  <div>
                    <span className="text-slate-400 block text-[10px]">Evidence Hash</span>
                    <span className="font-mono text-slate-400 text-[10px] block mt-0.5 truncate">{c.sha256}</span>
                  </div>

                  <div>
                    <span className="text-slate-400 block text-[10px] mb-1">Observable Indicators ({c.indicators.length})</span>
                    <div className="space-y-1 max-h-36 overflow-y-auto font-mono text-[10px]">
                      {c.indicators.map((ind: string, idx: number) => (
                        <div key={idx} className="p-1 rounded bg-soc-card border border-soc-border text-slate-300 truncate">
                          {ind}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
