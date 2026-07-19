export const API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export const WS_URL =
  process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";

export type Target = {
  id: string;
  value: string;
  type: string;
  created_at: string;
  tags: string[];
  notes: string | null;
};

export type Finding = {
  id: string;
  scan_id: string;
  title: string;
  severity: string;
  finding_type: string;
  cvss_score: number | null;
  cve_id: string | null;
  description: string | null;
  poc_request: string | null;
  poc_response: string | null;
  poc_curl: string | null;
  remediation: string | null;
  references: string[];
  raw_data: Record<string, unknown>;
  created_at: string;
};

export type ToolResult = {
  id: string;
  scan_id: string;
  tool_name: string;
  command: string;
  stdout: string | null;
  stderr: string | null;
  exit_code: number | null;
  duration_ms: number | null;
  status: string;
  parsed_output: Record<string, unknown>;
  created_at: string;
};

export type Scan = {
  id: string;
  target_id: string;
  mode: string;
  status: string;
  progress: number;
  current_tool: string | null;
  started_at: string | null;
  completed_at: string | null;
  configuration: Record<string, unknown>;
  error_message: string | null;
  target?: Target | null;
};

export type ScanWithDetails = Scan & {
  findings: Finding[];
  tool_results: ToolResult[];
};

export type DashboardStats = {
  total_scans: number;
  active_targets: number;
  vulnerabilities_found: number;
  running_scans: number;
  severity_breakdown: Record<string, number>;
  recent_scans: Scan[];
};

export type DeepScanOptions = {
  subdomain_enum: boolean;
  port_scan: boolean;
  directory_fuzz: boolean;
  tech_detect: boolean;
  safe_vuln_scan: boolean;
  crawl: boolean;
  threads: number;
  timeout: number;
};

export type AttackModeOptions = {
  sql_injection: boolean;
  xss: boolean;
  nuclei_exploit: boolean;
  threads: number;
  timeout: number;
  delay_ms: number;
  sqlmap_level: number;
  sqlmap_risk: number;
  authorized: boolean;
};

export type ProgressEvent = {
  scan_id: string;
  status: string;
  progress: number;
  current_tool: string | null;
  message: string;
  finding?: Partial<Finding> | null;
  tool_result?: Record<string, unknown> | null;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export function reportUrl(scanId: string, format: "json" | "html" = "json") {
  return `${API_URL}/api/scans/${scanId}/report?format=${format}`;
}

export const api = {
  dashboard: () => request<DashboardStats>("/api/dashboard"),
  listScans: () => request<Scan[]>("/api/scans"),
  getScan: (id: string) => request<ScanWithDetails>(`/api/scans/${id}`),
  getFinding: (scanId: string, findingId: string) =>
    request<Finding>(`/api/scans/${scanId}/findings/${findingId}`),
  startDeepScan: (body: {
    target: string;
    target_type?: string;
    options?: Partial<DeepScanOptions>;
  }) =>
    request<Scan>("/api/scans/deep", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  startAttackScan: (body: {
    target: string;
    target_type?: string;
    auth_header?: string | null;
    options?: Partial<AttackModeOptions>;
  }) =>
    request<Scan>("/api/scans/attack", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  cancelScan: (id: string) =>
    request<Scan>(`/api/scans/${id}/cancel`, { method: "POST" }),
  listTargets: () => request<Target[]>("/api/targets"),
  getReport: (id: string) =>
    request<Record<string, unknown>>(`/api/scans/${id}/report?format=json`),
};
