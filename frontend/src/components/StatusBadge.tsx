import React from 'react';
import { CaseStatus } from '../types';
import { Loader2 } from 'lucide-react';

interface StatusBadgeProps {
  status: CaseStatus;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const getStyles = () => {
    switch (status) {
      case 'CONFIRMED_MALICIOUS':
        return 'bg-rose-950/40 text-rose-300 border-rose-800/40';
      case 'NEEDS_REVIEW':
        return 'bg-amber-950/40 text-amber-300 border-amber-800/40';
      case 'BENIGN':
        return 'bg-emerald-950/40 text-emerald-300 border-emerald-800/40';
      case 'ANALYSING':
        return 'bg-blue-950/40 text-blue-300 border-blue-800/40';
      case 'CLOSED':
        return 'bg-slate-800/40 text-slate-400 border-slate-700/40';
      case 'NEW':
      default:
        return 'bg-indigo-950/40 text-indigo-300 border-indigo-800/40';
    }
  };

  const formatText = () => {
    return status.replace('_', ' ');
  };

  const sizeClasses = size === 'sm' ? 'text-[11px] px-2 py-0.5' : 'text-xs px-2.5 py-1';

  return (
    <span className={`inline-flex items-center gap-1.5 rounded border font-medium uppercase tracking-wider ${getStyles()} ${sizeClasses}`}>
      {status === 'ANALYSING' && (
        <Loader2 className="h-3 w-3 animate-spin text-blue-400" />
      )}
      <span>{formatText()}</span>
    </span>
  );
};
