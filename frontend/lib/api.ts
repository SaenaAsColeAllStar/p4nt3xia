export const API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export const WS_URL =
  process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";

const TOKEN_KEY = "p4nt3xia_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (typeof window === "undefined") return;
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export type User = {
  id: string;
  username: string;
  email: string | null;
  role: string;
  is_active: boolean;
  created_at: string;
};

export type Target = {
  id: string;
  value: string;
  type: string;
  created_at: string;
  tags: string[];
  notes: string | null;
  scan_count?: number;
  last_scan_at?: string | null;
  last_scan_mode?: string | null;
  last_scan_status?: string | null;
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
  brute_force: boolean;
  ssrf: boolean;
  jwt_attack: boolean;
  command_injection: boolean;
  lfi: boolean;
  file_upload: boolean;
  idor: boolean;
  threads: number;
  timeout: number;
  delay_ms: number;
  sqlmap_level: number;
  sqlmap_risk: number;
  hydra_username: string;
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

export type PayloadTemplate = {
  id: string;
  name: string;
  category: string;
  description: string | null;
  method: string;
  path_template: string;
  headers: Record<string, string>;
  body_template: string | null;
  payloads: string[];
  match_status: number[];
  match_body_contains: string[];
  tags: string[];
  created_by: string | null;
  created_at: string;
  updated_at: string;
};

export type TemplateRunResult = {
  template_id: string;
  template_name: string;
  target: string;
  hits: Array<{
    payload: string;
    url: string;
    status_code: number;
    matched: boolean;
    body_snippet: string | null;
    poc_curl: string | null;
  }>;
  total_tested: number;
  matched_count: number;
};

export type ApiResponseOut = {
  method: string;
  url: string;
  status_code: number;
  elapsed_ms: number;
  response_headers: Record<string, string>;
  body: string;
  body_truncated: boolean;
  request_headers: Record<string, string>;
  poc_curl: string;
};

export type ParsedCurl = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
};

export type FridaDevice = { id: string; name: string; type: string };
export type FridaRunResult = {
  status: string;
  device_id: string;
  target: string;
  messages: string[];
  stdout: string | null;
  stderr: string | null;
  skip_reason: string | null;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
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
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export type ReportFormat = "json" | "html" | "pdf" | "markdown";

export function reportUrl(scanId: string, format: ReportFormat = "json") {
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
  createTarget: (body: {
    value: string;
    type?: string;
    tags?: string[];
    notes?: string | null;
  }) =>
    request<Target>("/api/targets", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateTarget: (
    id: string,
    body: {
      value?: string;
      type?: string;
      tags?: string[];
      notes?: string | null;
    }
  ) =>
    request<Target>(`/api/targets/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteTarget: (id: string) =>
    request<void>(`/api/targets/${id}`, { method: "DELETE" }),
  getTargetScans: (id: string) =>
    request<Scan[]>(`/api/targets/${id}/scans`),
  getReport: (id: string) =>
    request<Record<string, unknown>>(`/api/scans/${id}/report?format=json`),

  // Auth
  authStatus: () =>
    request<{ auth_enabled: boolean; user: User | null }>("/api/auth/status"),
  login: (username: string, password: string) =>
    request<{ access_token: string; user: User }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  register: (body: {
    username: string;
    password: string;
    email?: string;
    role?: string;
  }) =>
    request<User>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  me: () => request<User>("/api/auth/me"),
  listUsers: () => request<User[]>("/api/auth/users"),
  createUser: (body: {
    username: string;
    password: string;
    email?: string;
    role?: string;
  }) =>
    request<User>("/api/auth/users", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // Templates
  listTemplates: (category?: string) =>
    request<PayloadTemplate[]>(
      `/api/templates${category ? `?category=${encodeURIComponent(category)}` : ""}`
    ),
  createTemplate: (body: Partial<PayloadTemplate> & { name: string }) =>
    request<PayloadTemplate>("/api/templates", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateTemplate: (id: string, body: Partial<PayloadTemplate>) =>
    request<PayloadTemplate>(`/api/templates/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteTemplate: (id: string) =>
    request<void>(`/api/templates/${id}`, { method: "DELETE" }),
  runTemplate: (
    id: string,
    body: {
      target: string;
      auth_header?: string;
      authorized: boolean;
      timeout?: number;
      max_payloads?: number;
    }
  ) =>
    request<TemplateRunResult>(`/api/templates/${id}/run`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // API mode
  parseCurl: (curl: string) =>
    request<ParsedCurl>("/api/api-mode/parse", {
      method: "POST",
      body: JSON.stringify({ curl }),
    }),
  apiRequest: (body: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string | null;
    timeout?: number;
    authorized?: boolean;
  }) =>
    request<ApiResponseOut>("/api/api-mode/request", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  apiFromCurl: (curl: string, authorized = false) =>
    request<ApiResponseOut>(
      `/api/api-mode/from-curl?authorized=${authorized}`,
      {
        method: "POST",
        body: JSON.stringify({ curl }),
      }
    ),

  // Frida
  fridaStatus: () =>
    request<{
      available: boolean;
      device_count: number;
      sample_scripts: string[];
    }>("/api/frida/status"),
  fridaDevices: () => request<FridaDevice[]>("/api/frida/devices"),
  fridaSamples: () => request<Record<string, string>>("/api/frida/samples"),
  fridaRun: (body: {
    device_id?: string;
    target: string;
    spawn?: boolean;
    script: string;
    timeout?: number;
    authorized: boolean;
  }) =>
    request<FridaRunResult>("/api/frida/run", {
      method: "POST",
      body: JSON.stringify(body),
    }),
};
