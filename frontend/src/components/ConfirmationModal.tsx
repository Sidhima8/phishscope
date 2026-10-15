import React, { useState } from 'react';
import { AlertTriangle, CheckCircle, X } from 'lucide-react';

interface ConfirmationModalProps {
  isOpen: boolean;
  title: string;
  message: string;
  targetStatus: string;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}

export const ConfirmationModal: React.FC<ConfirmationModalProps> = ({
  isOpen,
  title,
  message,
  targetStatus,
  onConfirm,
  onCancel,
}) => {
  const [reason, setReason] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);

  if (!isOpen) return null;

  const isMalicious = targetStatus === 'CONFIRMED_MALICIOUS';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="w-full max-w-lg rounded-xl border border-soc-border bg-soc-card p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-start justify-between pb-4 border-b border-soc-border">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-lg ${isMalicious ? 'bg-rose-500/10 text-rose-400' : 'bg-emerald-500/10 text-emerald-400'}`}>
              {isMalicious ? <AlertTriangle className="h-6 w-6" /> : <CheckCircle className="h-6 w-6" />}
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">{title}</h3>
              <p className="text-xs text-soc-muted">Forensic Confirmation Required</p>
            </div>
          </div>
          <button onClick={onCancel} className="text-soc-muted hover:text-white transition-colors">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="my-5 space-y-4">
          <p className="text-sm text-slate-300 leading-relaxed">
            {message}
          </p>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">
              Analyst Investigation Justification / Notes <span className="text-rose-400">*</span>
            </label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Provide evidence summary justifying this classification..."
              rows={3}
              className="w-full rounded-lg border border-soc-border bg-soc-bg px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-soc-accent focus:outline-none"
            />
          </div>

          <label className="flex items-start gap-2.5 cursor-pointer pt-1">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              className="mt-1 h-4 w-4 rounded border-soc-border bg-soc-bg text-soc-accent focus:ring-soc-accent focus:ring-offset-soc-card"
            />
            <span className="text-xs text-slate-400 leading-normal">
              I acknowledge that this action establishes a formal forensic finding in the investigation record.
            </span>
          </label>
        </div>

        <div className="flex justify-end gap-3 pt-4 border-t border-soc-border">
          <button
            onClick={onCancel}
            className="rounded-lg border border-soc-border px-4 py-2 text-sm font-medium text-slate-300 hover:bg-soc-hover transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => onConfirm(reason)}
            disabled={!acknowledged || !reason.trim()}
            className={`rounded-lg px-4 py-2 text-sm font-semibold text-white transition-all disabled:opacity-40 disabled:cursor-not-allowed ${
              isMalicious
                ? 'bg-rose-600 hover:bg-rose-500 shadow-[0_0_15px_rgba(225,29,72,0.4)]'
                : 'bg-emerald-600 hover:bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.4)]'
            }`}
          >
            Confirm Classification
          </button>
        </div>
      </div>
    </div>
  );
};
