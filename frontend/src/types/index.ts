export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type CaseStatus = 'NEW' | 'ANALYSING' | 'NEEDS_REVIEW' | 'CONFIRMED_MALICIOUS' | 'BENIGN' | 'CLOSED';
export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Finding {
  id: number;
  case_id: number;
  indicator_name: string;
  severity: FindingSeverity;
  category: string;
  observed_evidence: string;
  explanation: string;
  source: string;
  confidence: string;
  recommended_step?: string;
  points_added: number;
  created_at: string;
}

export interface Indicator {
  id: number;
  case_id: number;
  indicator_type: 'URL' | 'DOMAIN' | 'IP' | 'HASH' | 'EMAIL';
  raw_value: string;
  defanged_value: string;
  reputation: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  flags?: string[];
  redirect_chain?: string[];
  provider_results?: Record<string, any>;
  created_at: string;
}

export interface Attachment {
  id: number;
  case_id: number;
  filename: string;
  content_type?: string;
  size_bytes: number;
  sha256_hash: string;
  md5_hash: string;
  risk_level: RiskLevel;
  risk_factors?: string[];
  created_at: string;
}

export interface CaseNote {
  id: number;
  case_id: number;
  user_id?: number;
  author_name: string;
  note_text: string;
  action_type: string;
  created_at: string;
}

export interface CaseListItem {
  id: number;
  case_number: string;
  title: string;
  subject?: string;
  sender?: string;
  sender_domain?: string;
  file_hash_sha256: string;
  original_file_name?: string;
  status: CaseStatus;
  risk_score: number;
  risk_level: RiskLevel;
  confidence: string;
  created_at: string;
  updated_at: string;
  findings_count: number;
  indicators_count: number;
  attachments_count: number;
}

export interface CaseDetail {
  id: number;
  case_number: string;
  title: string;
  subject?: string;
  sender?: string;
  sender_domain?: string;
  recipients?: string[];
  file_hash_sha256: string;
  original_file_name?: string;
  
  raw_headers?: string;
  raw_body_text?: string;
  raw_body_html?: string;
  
  status: CaseStatus;
  risk_score: number;
  risk_level: RiskLevel;
  confidence: string;
  
  assigned_to_id?: number;
  created_at: string;
  updated_at: string;
  completed_at?: string;
  
  auth_summary?: {
    spf?: { recorded: string; verdict: string; dns_record_found: boolean; dns_record?: string; alignment: boolean };
    dkim?: { recorded: string; verdict: string; signature_present: boolean; selector?: string; domain?: string; dns_key_found: boolean; alignment: boolean };
    dmarc?: { recorded: string; verdict: string; dns_record_found: boolean; dns_record?: string; policy?: string };
    mismatches?: {
      reply_to_mismatch: boolean;
      return_path_mismatch: boolean;
      display_name_spoofing: boolean;
      spoofed_brand?: string;
      lookalike_domain: boolean;
      lookalike_brand?: string;
    };
  };
  
  mime_structure?: Record<string, any>;
  received_hops?: Array<{
    hop_index: number;
    raw: string;
    from_host: string;
    from_ip: string;
    by_host: string;
    protocol: string;
    date_str: string;
    is_private_ip: boolean;
    suspicious: boolean;
  }>;
  
  threat_intel_summary?: Record<string, any>;
  mitre_techniques?: Array<{ id: string; name: string; description: string }>;
  executive_summary?: string;
  
  completed_checks: number;
  failed_checks: number;
  unavailable_checks: number;

  findings: Finding[];
  indicators: Indicator[];
  attachments: Attachment[];
  notes: CaseNote[];
}

export interface DashboardMetrics {
  total_cases: number;
  pending_analysis: number;
  needs_review: number;
  high_critical_cases: number;
  benign_count: number;
  malicious_count: number;
  status_breakdown: {
    new: number;
    analysing: number;
    needs_review: number;
    confirmed_malicious: number;
    benign: number;
    closed: number;
  };
  risk_distribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  top_domains: Array<{ name: string; count: number; reputation: string }>;
  top_urls: Array<{ name: string; count: number; reputation: string }>;
  recent_activity: Array<{
    id: number;
    case_id: number;
    case_number: string;
    action_type: string;
    author: string;
    note_text: string;
    timestamp: string;
  }>;
  integrations: Array<{
    name: string;
    configured: boolean;
    status: string;
    latency_ms: number;
    description: string;
  }>;
}

export interface SampleScenario {
  id: string;
  name: string;
  filename: string;
  threat_category: string;
  expected_risk: RiskLevel;
}

export interface IndicatorLookupResult {
  indicator: string;
  defanged: string;
  type: string;
  reputation: string;
  summary: string;
  virustotal?: any;
  urlhaus?: any;
  rdap?: any;
  dns?: any;
  lookup_time: string;
}
