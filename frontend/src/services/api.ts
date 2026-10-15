import {
  CaseListItem, CaseDetail, DashboardMetrics,
  SampleScenario, IndicatorLookupResult
} from '../types';

const API_BASE = '/api/v1';

export const api = {
  // Dashboard
  async getDashboardMetrics(): Promise<DashboardMetrics> {
    const res = await fetch(`${API_BASE}/dashboard/metrics`);
    if (!res.ok) throw new Error('Failed to load dashboard metrics');
    return res.json();
  },

  // Cases
  async listCases(params?: { search?: string; status?: string; risk_level?: string; limit?: number; offset?: number }): Promise<CaseListItem[]> {
    const query = new URLSearchParams();
    if (params?.search) query.set('search', params.search);
    if (params?.status) query.set('status', params.status);
    if (params?.risk_level) query.set('risk_level', params.risk_level);
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.offset) query.set('offset', String(params.offset));

    const res = await fetch(`${API_BASE}/cases?${query.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch cases');
    return res.json();
  },

  async getCaseDetail(caseId: number): Promise<CaseDetail> {
    const res = await fetch(`${API_BASE}/cases/${caseId}`);
    if (!res.ok) throw new Error(`Failed to load case #${caseId}`);
    return res.json();
  },

  async updateCaseStatus(caseId: number, status: string, reason?: string, confirmedByAnalyst = false) {
    const res = await fetch(`${API_BASE}/cases/${caseId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, reason, confirmed_by_analyst: confirmedByAnalyst })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to update case status');
    }
    return res.json();
  },

  async assignCase(caseId: number, assignedToId: number | null) {
    const res = await fetch(`${API_BASE}/cases/${caseId}/assign`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assigned_to_id: assignedToId })
    });
    if (!res.ok) throw new Error('Failed to assign case');
    return res.json();
  },

  async compareCases(caseIds: number[]) {
    const res = await fetch(`${API_BASE}/cases/compare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ case_ids: caseIds })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Comparison failed');
    }
    return res.json();
  },

  async deleteCase(caseId: number) {
    const res = await fetch(`${API_BASE}/cases/${caseId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete case');
    return res.json();
  },

  // Ingestion
  async uploadEmlFiles(files: File[]) {
    const formData = new FormData();
    for (const f of files) {
      formData.append('files', f);
    }
    const res = await fetch(`${API_BASE}/ingest/upload`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Upload failed');
    }
    return res.json();
  },

  async ingestRawEmail(rawContent: string, title?: string) {
    const res = await fetch(`${API_BASE}/ingest/raw`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw_content: rawContent, title })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Ingestion failed');
    }
    return res.json();
  },

  async listSamples(): Promise<SampleScenario[]> {
    const res = await fetch(`${API_BASE}/ingest/samples`);
    if (!res.ok) throw new Error('Failed to load sample scenarios');
    return res.json();
  },

  async ingestSample(sampleId: string) {
    const res = await fetch(`${API_BASE}/ingest/sample/${sampleId}`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to trigger sample analysis');
    }
    return res.json();
  },

  // Notes
  async addNote(caseId: number, noteText: string, actionType = 'NOTE') {
    const res = await fetch(`${API_BASE}/notes/${caseId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note_text: noteText, action_type: actionType })
    });
    if (!res.ok) throw new Error('Failed to record note');
    return res.json();
  },

  // Threat Intel & Indicators
  async lookupIndicator(indicator: string): Promise<IndicatorLookupResult> {
    const res = await fetch(`${API_BASE}/indicators/lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator })
    });
    if (!res.ok) throw new Error('Indicator lookup failed');
    return res.json();
  },

  async expandUrl(url: string) {
    const res = await fetch(`${API_BASE}/indicators/expand-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!res.ok) throw new Error('Redirect expansion failed');
    return res.json();
  },

  async getIntegrationsStatus() {
    const res = await fetch(`${API_BASE}/integrations/status`);
    if (!res.ok) throw new Error('Failed to check integrations');
    return res.json();
  },

  // Export URLs
  getPdfReportUrl(caseId: number) {
    return `${API_BASE}/reports/${caseId}/pdf`;
  },

  getJsonExportUrl(caseId: number) {
    return `${API_BASE}/reports/${caseId}/json`;
  }
};
