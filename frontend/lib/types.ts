export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type InvestigationStatus =
  | "pending"
  | "running"
  | "awaiting_approval"
  | "applying"
  | "verifying"
  | "completed"
  | "failed";
export type AgentStatus = "pending" | "running" | "completed" | "failed" | "skipped";
export type RemediationStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "applied"
  | "verified"
  | "failed";

export interface AgentFinding {
  title: string;
  severity: Severity;
  confidence: number;
  files: string[];
  line_ranges: string[];
  evidence: string[];
  recommendation: string;
  attack_path: string[];
  root_cause: string;
  evidence_excerpt?: string;
  file_line_start?: number;
  file_line_end?: number;
  technology?: string;
}

export interface AgentResult {
  agent: string;
  status: AgentStatus;
  duration_ms: number;
  findings: AgentFinding[];
  summary: string;
  error?: string;
}

export interface EvidenceItem {
  source: string;
  type: string;
  description: string;
  file?: string;
  line_range?: string;
  severity?: Severity;
}

export interface CorrelationResult {
  primary_finding: string;
  corroborating_evidence: EvidenceItem[];
  affected_files: string[];
  attack_path: string[];
  confidence: number;
}

export interface RootCauseAnalysis {
  symptom: string;
  root_cause: string;
  why_it_happens: string;
  impact: string;
  affected_components: string[];
  cwe_id?: string;
  cvss_score?: number;
}

export interface FilePatch {
  file_path: string;
  before: string;
  after: string;
  diff: string;
  explanation: string;
}

export interface RemediationProposal {
  id: string;
  status: RemediationStatus;
  summary: string;
  files_changed: string[];
  patches: FilePatch[];
  risk_level: string;
  risk_explanation: string;
  regression_test?: string;
  regression_test_file?: string;
}

export interface VerificationCheck {
  name: string;
  status: "passed" | "failed" | "skipped";
  detail: string;
}

export interface VerificationResult {
  overall_status: "verified" | "failed" | "partial";
  checks: VerificationCheck[];
  exploit_blocked: boolean;
  regression_passed: boolean;
  summary: string;
}

export interface TimelineEvent {
  timestamp: string;
  event: string;
  detail: string;
  actor: string;
}

export interface Investigation {
  id: string;
  title: string;
  issue_description: string;
  repository_path?: string;
  repository_url?: string;
  status: InvestigationStatus;
  severity?: Severity;
  created_at: string;
  updated_at: string;
  repository_info?: {
    project_type: string;
    languages: string[];
    frameworks: string[];
    entry_points: string[];
    api_routes: string[];
    auth_components: string[];
    total_files: number;
    relevant_files: string[];
  };
  agent_results: Record<string, AgentResult>;
  correlation?: CorrelationResult;
  root_cause?: RootCauseAnalysis;
  remediation?: RemediationProposal;
  verification?: VerificationResult;
  ai_reasoning?: AIReasoningData;
  timeline: TimelineEvent[];
  progress_pct: number;
}

export interface AIReasoningClaim {
  claim: string;
  status: "OBSERVED" | "INFERRED" | "RECOMMENDED" | "UNSUPPORTED";
  supporting_evidence_ids?: string[];
  confidence: number;
  limitation?: string;
}

export interface AIReasoningAttackStep {
  step: number;
  description: string;
  evidence_basis: string;
  observation_status: "OBSERVED" | "INFERRED";
}

export interface AIRagCitation {
  identifier: string;
  source: string;
  title: string;
  section: string;
  score: number;
}

export interface AIReasoningData {
  investigation_id?: string;
  provider_used?: string;
  model_used?: string;
  reasoning_latency_ms?: number;
  ran_in_deterministic_mode?: boolean;
  vulnerability_title?: string;
  primary_cwe?: string;
  primary_owasp?: string;
  severity_assessment?: string;
  severity_observation_status?: "OBSERVED" | "INFERRED";
  root_cause_summary?: string;
  root_cause_observation_status?: "OBSERVED" | "INFERRED";
  attack_path?: AIReasoningAttackStep[];
  grounded_claims?: AIReasoningClaim[];
  primary_remediation?: string;
  remediation_code_example?: string;
  recommended_tests?: Array<{ title: string; description: string; test_type?: string }>;
  rag_citations?: AIRagCitation[];
  evidence_gaps?: string[];
  cannot_determine?: string[];
  grounding_confidence?: number;
  evidence_sufficiency?: string;
  deterministic_override_applied?: boolean;
  deterministic_override_note?: string;
  verification_explanation?: string;
}

export interface InvestigationSummary {
  id: string;
  title: string;
  status: InvestigationStatus;
  severity?: Severity;
  created_at: string;
  progress_pct: number;
}

export interface ProgressEvent {
  investigation_id: string;
  event_type: string;
  agent?: string;
  message: string;
  progress_pct: number;
  data?: Record<string, unknown>;
}

export interface DashboardStats {
  active_investigations: number;
  critical_findings: number;
  issues_fixed: number;
  verified_remediations: number;
  total_investigations: number;
  demo_metrics: {
    avg_investigation_time_reduction_pct: number;
    manual_steps_before: number;
    automated_steps_after: number;
    avg_files_inspected_before: number;
    avg_relevant_files_securefix: number;
  };
}
