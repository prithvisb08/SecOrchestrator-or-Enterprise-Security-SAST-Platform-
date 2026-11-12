export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type FindingStatus = "OPEN" | "CONFIRMED" | "FALSE_POSITIVE" | "ACCEPTED_RISK" | "FIXED";

export interface SourceLocation {
  file_path: string;
  start_line: number;
  end_line: number;
  start_col?: number;
  end_col?: number;
  snippet?: string;
}

export interface TaintStep {
  step_number: number;
  type: "SOURCE" | "PROPAGATION" | "SANITIZER" | "SINK";
  location: SourceLocation;
  expression: string;
  description: string;
}

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  location: SourceLocation;
  taint_path?: TaintStep[];
  status: FindingStatus;
  remediation?: string;
  fingerprint: string;
}

export interface Project {
  project_id: string;
  repository_name: string;
  latest_scan_id: string;
  risk_score: number;
  open_findings: number;
  status: string;
}

export interface ScanRecord {
  scan_id: string;
  repository_id: string;
  created_at: string;
  duration_seconds: number;
  scanned_files_count: number;
  findings_count: number;
  composite_risk_score: number;
  status: "COMPLETED" | "PARTIAL" | "FAILED";
}

export interface SecurityPolicy {
  policy_id: string;
  name: string;
  block_on_critical: boolean;
  block_on_high: boolean;
  max_allowed_high: number;
  block_secrets: boolean;
  monitored_paths: string[];
}

export interface TrendEntry {
  scan_id: string;
  repository_id: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}
