import React, { useState, useEffect } from 'react';
import {
  Search, Filter, GitCompare, RefreshCw, Eye,
  Trash2, AlertTriangle, ChevronRight, CheckSquare, Square
} from 'lucide-react';
import { CaseListItem, CaseStatus, RiskLevel } from '../types';
import { api } from '../services/api';
import { RiskBadge } from '../components/RiskBadge';
import { StatusBadge } from '../components/StatusBadge';

interface CasesListViewProps {
  onSelectCase: (caseId: number) => void;
  onCompareCases: (caseIds: number[]) => void;
}

export const CasesListView: React.FC<CasesListViewProps> = ({ onSelectCase, onCompareCases }) => {
  const [cases, setCases] = useState<CaseListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');

  // Multi-select for comparison
  const [selectedCaseIds, setSelectedCaseIds] = useState<number[]>([]);

  const fetchCases = async () => {
    try {
      setLoading(true);
      const data = await api.listCases({
        search: search || undefined,
        status: statusFilter !== 'ALL' ? statusFilter : undefined,
        risk_level: riskFilter !== 'ALL' ? riskFilter : undefined,
      });
      setCases(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Failed to load cases');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, [statusFilter, riskFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchCases();
  };

  const toggleSelectCase = (id: number) => {
    setSelectedCaseIds((prev) =>
      prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
    );
  };

  const selectAll = () => {
    if (selectedCaseIds.length === cases.length) {
      setSelectedCaseIds([]);
    } else {
      setSelectedCaseIds(cases.map((c) => c.id));
    }
  };

  const handleDelete = async (e: React.MouseEvent, id: number) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this case record?')) return;
    try {
      await api.deleteCase(id);
      setCases((prev) => prev.filter((c) => c.id !== id));
      setSelectedCaseIds((prev) => prev.filter((i) => i !== id));
    } catch (err: any) {
      alert(err.message || 'Delete failed');
    }
  };

  return (
    <div className="p-6 space-y-5">
      {/* Top Controls Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide">Investigation Cases</h2>
          <p className="text-xs text-soc-muted mt-0.5">
            {cases.length} investigation case(s) found in active repository
          </p>
        </div>

        {/* Compare Action Button */}
        {selectedCaseIds.length >= 2 && (
          <button
            onClick={() => onCompareCases(selectedCaseIds)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-soc-cyan hover:bg-cyan-500 text-slate-900 font-semibold text-xs shadow-[0_0_15px_rgba(6,182,212,0.35)] transition-all animate-bounce"
          >
            <GitCompare className="h-4 w-4" />
            <span>Compare Selected ({selectedCaseIds.length})</span>
          </button>
        )}
      </div>

      {/* Filter and Search Bar */}
      <div className="rounded-xl border border-soc-border bg-soc-card p-4 space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-soc-muted" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by Case Number, Subject, Sender Domain, or SHA-256..."
              className="w-full rounded-lg border border-soc-border bg-soc-panel pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:border-soc-accent focus:outline-none"
            />
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-medium">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-lg border border-soc-border bg-soc-panel px-3 py-2 text-xs text-white focus:border-soc-accent focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="NEW">New</option>
              <option value="ANALYSING">Analysing</option>
              <option value="NEEDS_REVIEW">Needs Review</option>
              <option value="CONFIRMED_MALICIOUS">Confirmed Malicious</option>
              <option value="BENIGN">Benign</option>
              <option value="CLOSED">Closed</option>
            </select>
          </div>

          {/* Risk Filter */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-medium">Risk:</span>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="rounded-lg border border-soc-border bg-soc-panel px-3 py-2 text-xs text-white focus:border-soc-accent focus:outline-none"
            >
              <option value="ALL">All Risk Levels</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-soc-panel hover:bg-soc-hover border border-soc-border text-xs font-semibold text-white transition-colors"
          >
            Apply Filters
          </button>
        </form>
      </div>

      {/* Cases Table */}
      <div className="rounded-xl border border-soc-border bg-soc-card overflow-hidden">
        {loading ? (
          <div className="flex h-64 items-center justify-center">
            <div className="flex flex-col items-center gap-2">
              <RefreshCw className="h-6 w-6 animate-spin text-soc-accent" />
              <p className="text-xs font-mono text-soc-muted">Querying case database...</p>
            </div>
          </div>
        ) : cases.length === 0 ? (
          <div className="py-16 text-center text-slate-400 space-y-2">
            <AlertTriangle className="mx-auto h-8 w-8 text-soc-muted" />
            <p className="text-sm font-semibold text-slate-300">No investigation cases match your filters.</p>
            <p className="text-xs text-soc-muted">Try resetting search keywords or upload a new email for analysis.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-soc-panel border-b border-soc-border text-slate-400 font-medium uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4 w-10">
                    <button onClick={selectAll} className="text-slate-400 hover:text-white">
                      {selectedCaseIds.length === cases.length && cases.length > 0 ? (
                        <CheckSquare className="h-4 w-4 text-soc-accent" />
                      ) : (
                        <Square className="h-4 w-4" />
                      )}
                    </button>
                  </th>
                  <th className="py-3 px-4">Case ID</th>
                  <th className="py-3 px-4">Subject & Sender</th>
                  <th className="py-3 px-4">Evidence SHA-256</th>
                  <th className="py-3 px-4">Risk Evaluation</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Ingested At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border">
                {cases.map((c) => {
                  const isSelected = selectedCaseIds.includes(c.id);
                  return (
                    <tr
                      key={c.id}
                      onClick={() => onSelectCase(c.id)}
                      className={`hover:bg-soc-hover/50 cursor-pointer transition-colors ${
                        isSelected ? 'bg-soc-accent/5' : ''
                      }`}
                    >
                      <td className="py-3.5 px-4" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => toggleSelectCase(c.id)}
                          className="text-slate-400 hover:text-white"
                        >
                          {isSelected ? (
                            <CheckSquare className="h-4 w-4 text-soc-accent" />
                          ) : (
                            <Square className="h-4 w-4" />
                          )}
                        </button>
                      </td>

                      <td className="py-3.5 px-4 font-mono font-semibold text-soc-accent">
                        {c.case_number}
                      </td>

                      <td className="py-3.5 px-4 max-w-xs">
                        <div className="font-semibold text-white truncate">{c.subject || 'No Subject'}</div>
                        <div className="text-[11px] text-soc-muted truncate font-mono mt-0.5">
                          {c.sender || 'Unknown Sender'}
                        </div>
                      </td>

                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                        {c.file_hash_sha256.substring(0, 16)}...
                      </td>

                      <td className="py-3.5 px-4">
                        <RiskBadge level={c.risk_level} score={c.risk_score} size="sm" />
                      </td>

                      <td className="py-3.5 px-4">
                        <StatusBadge status={c.status} size="sm" />
                      </td>

                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                        {c.created_at.substring(0, 19).replace('T', ' ')}
                      </td>

                      <td className="py-3.5 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => onSelectCase(c.id)}
                            title="Open Investigation Workspace"
                            className="p-1.5 rounded hover:bg-soc-panel text-slate-400 hover:text-soc-accent transition-colors"
                          >
                            <Eye className="h-4 w-4" />
                          </button>
                          <button
                            onClick={(e) => handleDelete(e, c.id)}
                            title="Delete Case"
                            className="p-1.5 rounded hover:bg-rose-950/40 text-slate-500 hover:text-rose-400 transition-colors"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
