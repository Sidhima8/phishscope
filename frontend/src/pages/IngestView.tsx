import React, { useState, useEffect } from 'react';
import {
  UploadCloud, FileText, Sparkles, CheckCircle2,
  AlertCircle, ShieldCheck, ArrowRight, Loader2, Play
} from 'lucide-react';
import { api } from '../services/api';
import { SampleScenario } from '../types';
import { RiskBadge } from '../components/RiskBadge';

interface IngestViewProps {
  onCaseCreated: (caseId: number) => void;
}

export const IngestView: React.FC<IngestViewProps> = ({ onCaseCreated }) => {
  const [activeTab, setActiveTab] = useState<'upload' | 'raw' | 'samples'>('samples');
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [rawText, setRawText] = useState('');
  const [caseTitle, setCaseTitle] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const [samples, setSamples] = useState<SampleScenario[]>([]);
  const [loadingSamples, setLoadingSamples] = useState(false);

  useEffect(() => {
    loadSamples();
  }, []);

  const loadSamples = async () => {
    try {
      setLoadingSamples(true);
      const data = await api.listSamples();
      setSamples(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingSamples(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setSelectedFiles(Array.from(e.target.files));
      setError(null);
    }
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedFiles.length === 0) {
      setError('Please select at least one .eml file.');
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);
      const result = await api.uploadEmlFiles(selectedFiles);
      if (result.cases && result.cases.length > 0) {
        onCaseCreated(result.cases[0].case_id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to upload email files');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRawSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawText.trim()) {
      setError('Please paste raw email headers and body content.');
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);
      const result = await api.ingestRawEmail(rawText, caseTitle || undefined);
      if (result.case_id) {
        onCaseCreated(result.case_id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to ingest raw email');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleIngestSample = async (sampleId: string) => {
    try {
      setIsSubmitting(true);
      setError(null);
      const result = await api.ingestSample(sampleId);
      if (result.case_id) {
        onCaseCreated(result.case_id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to ingest demonstration scenario');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-wide">Ingest Email Evidence</h2>
        <p className="text-xs text-soc-muted mt-1">
          Submit suspicious email artefacts for automated header inspection, DNS verification, threat intelligence correlation, and explainable risk evaluation.
        </p>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-800/40 bg-rose-950/20 p-4 flex items-center gap-3 text-rose-300 text-sm">
          <AlertCircle className="h-5 w-5 flex-shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-soc-border">
        <button
          onClick={() => setActiveTab('samples')}
          className={`flex items-center gap-2 px-5 py-3 text-sm font-semibold border-b-2 transition-all ${
            activeTab === 'samples'
              ? 'border-soc-accent text-white bg-soc-panel/30'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Sparkles className="h-4 w-4 text-soc-accent" />
          <span>Demo Scenarios (One-Click)</span>
        </button>

        <button
          onClick={() => setActiveTab('upload')}
          className={`flex items-center gap-2 px-5 py-3 text-sm font-semibold border-b-2 transition-all ${
            activeTab === 'upload'
              ? 'border-soc-accent text-white bg-soc-panel/30'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <UploadCloud className="h-4 w-4" />
          <span>Upload .EML Files</span>
        </button>

        <button
          onClick={() => setActiveTab('raw')}
          className={`flex items-center gap-2 px-5 py-3 text-sm font-semibold border-b-2 transition-all ${
            activeTab === 'raw'
              ? 'border-soc-accent text-white bg-soc-panel/30'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileText className="h-4 w-4" />
          <span>Paste Raw Email</span>
        </button>
      </div>

      {/* Tab 1: One-Click Demo Scenarios */}
      {activeTab === 'samples' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-soc-border bg-soc-card p-5">
            <h3 className="text-sm font-semibold text-white mb-1">Preloaded Real-World Investigation Scenarios</h3>
            <p className="text-xs text-slate-400 mb-4">
              Select any labelled sample to immediately trigger the genuine backend analysis engine and examine genuine findings.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {samples.map((s) => (
                <div
                  key={s.id}
                  className="rounded-xl border border-soc-border bg-soc-panel p-4 flex flex-col justify-between hover:border-soc-accent/50 transition-all group"
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-soc-cyan">{s.threat_category}</span>
                      <RiskBadge level={s.expected_risk} size="sm" />
                    </div>
                    <h4 className="text-sm font-semibold text-white group-hover:text-soc-accent transition-colors">
                      {s.name}
                    </h4>
                    <p className="text-xs font-mono text-soc-muted mt-1">{s.filename}</p>
                  </div>

                  <div className="mt-4 pt-3 border-t border-soc-border/60 flex items-center justify-between">
                    <span className="text-[11px] text-slate-400">Authentic test fixture</span>
                    <button
                      onClick={() => handleIngestSample(s.id)}
                      disabled={isSubmitting}
                      className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-soc-accent hover:bg-blue-600 text-white text-xs font-semibold shadow-[0_0_12px_rgba(59,130,246,0.25)] transition-all disabled:opacity-50"
                    >
                      {isSubmitting ? (
                        <>
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          <span>Analyzing...</span>
                        </>
                      ) : (
                        <>
                          <Play className="h-3.5 w-3.5 fill-current" />
                          <span>Ingest & Run</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Upload .EML */}
      {activeTab === 'upload' && (
        <form onSubmit={handleUploadSubmit} className="rounded-xl border border-soc-border bg-soc-card p-6 space-y-6">
          <div className="border-2 border-dashed border-soc-border rounded-xl p-8 text-center hover:border-soc-accent transition-colors bg-soc-panel/30">
            <UploadCloud className="mx-auto h-10 w-10 text-soc-accent mb-3" />
            <p className="text-sm font-semibold text-white">Choose or drag .eml files</p>
            <p className="text-xs text-soc-muted mt-1">Single file or multiple files in a batch (max 25MB each)</p>

            <input
              type="file"
              id="file-upload"
              accept=".eml,message/rfc822,text/plain"
              multiple
              onChange={handleFileChange}
              className="hidden"
            />
            <label
              htmlFor="file-upload"
              className="mt-4 inline-block px-4 py-2 rounded-lg bg-soc-panel border border-soc-border text-xs font-semibold text-white hover:bg-soc-hover cursor-pointer transition-colors"
            >
              Browse Files
            </label>
          </div>

          {selectedFiles.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Selected Files ({selectedFiles.length})
              </h4>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {selectedFiles.map((file, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2.5 rounded-lg bg-soc-panel border border-soc-border text-xs">
                    <span className="font-mono text-slate-300 truncate">{file.name}</span>
                    <span className="font-mono text-soc-muted">{(file.size / 1024).toFixed(1)} KB</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={isSubmitting || selectedFiles.length === 0}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-soc-accent hover:bg-blue-600 text-white text-xs font-semibold shadow-[0_0_15px_rgba(59,130,246,0.3)] transition-all disabled:opacity-50"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Ingesting Evidence...</span>
                </>
              ) : (
                <>
                  <span>Start Forensics Pipeline</span>
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </div>
        </form>
      )}

      {/* Tab 3: Paste Raw */}
      {activeTab === 'raw' && (
        <form onSubmit={handleRawSubmit} className="rounded-xl border border-soc-border bg-soc-card p-6 space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">
              Investigation Title (Optional)
            </label>
            <input
              type="text"
              value={caseTitle}
              onChange={(e) => setCaseTitle(e.target.value)}
              placeholder="e.g. Suspicious Wire Transfer Email from Supplier"
              className="w-full rounded-lg border border-soc-border bg-soc-panel px-3.5 py-2 text-sm text-white placeholder-slate-500 focus:border-soc-accent focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">
              Raw RFC 822 Email Content (Headers & Body) <span className="text-rose-400">*</span>
            </label>
            <textarea
              rows={12}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Received: from mail.example.com...&#10;From: attacker@suspicious.com&#10;To: target@company.com&#10;Subject: Security Alert&#10;&#10;Please verify your account immediately at http://evil.com/login"
              className="w-full rounded-lg border border-soc-border bg-soc-panel p-3 font-mono text-xs text-white placeholder-slate-600 focus:border-soc-accent focus:outline-none"
            />
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={isSubmitting || !rawText.trim()}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-soc-accent hover:bg-blue-600 text-white text-xs font-semibold shadow-[0_0_15px_rgba(59,130,246,0.3)] transition-all disabled:opacity-50"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Processing...</span>
                </>
              ) : (
                <>
                  <span>Ingest & Run Analysis</span>
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </div>
        </form>
      )}
    </div>
  );
};
