import React from 'react';
import { RiskLevel } from '../types';

interface RiskBadgeProps {
  level: RiskLevel;
  score?: number;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, score, size = 'md' }) => {
  const getStyles = () => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30 shadow-[0_0_12px_rgba(244,63,94,0.15)]';
      case 'HIGH':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30 shadow-[0_0_12px_rgba(245,158,11,0.15)]';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
      case 'LOW':
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    }
  };

  const getDotColor = () => {
    switch (level) {
      case 'CRITICAL': return 'bg-rose-400 animate-pulse';
      case 'HIGH': return 'bg-amber-400';
      case 'MEDIUM': return 'bg-yellow-400';
      case 'LOW': default: return 'bg-emerald-400';
    }
  };

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-xs px-2.5 py-1',
    lg: 'text-sm px-3.5 py-1.5 font-semibold'
  }[size];

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border font-mono uppercase tracking-wider ${getStyles()} ${sizeClasses}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${getDotColor()}`} />
      <span>{level}</span>
      {typeof score === 'number' && (
        <span className="opacity-80">({score}/100)</span>
      )}
    </span>
  );
};
