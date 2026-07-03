export interface RequestConfig {
  method: string;
  headers: Record<string, string>;
  body_template: string;
  response_path: string;
}

export interface Model {
  id: string;
  name: string;
  provider: string;
  model_name: string;
  base_url: string | null;
  key_last4: string | null;
  is_default: boolean;
  request_config: RequestConfig | null;
  created_at: string;
}

export interface ModelCreate {
  name: string;
  provider: string;
  model_name?: string;
  api_key?: string;
  base_url?: string;
  request_config?: RequestConfig;
}

export interface ModelTestResult {
  ok: boolean;
  latency_ms: number;
  sample: string | null;
  error: string | null;
}

export interface SuccessRule {
  type: string;
  patterns: string[];
  refusal_markers: string[];
  expected?: string[];
}

export interface Attack {
  id: string;
  category: string;
  name: string;
  owasp: string;
  severity: string;
  description: string;
  prompt_template: string;
  success: SuccessRule;
  tags: string[];
}

export interface OwaspBucket {
  category: string;
  total: number;
  succeeded: number;
  success_pct: number;
}

export interface Recommendation {
  owasp: string;
  message: string;
}

export interface Run {
  id: string;
  model_id: string;
  model_label: string | null;
  status: "pending" | "running" | "completed" | "failed";
  created_at: string;
  completed_at: string | null;
  total: number;
  succeeded_count: number;
  score: number | null;
  risk_level: string | null;
  attack_success_pct: number | null;
  owasp_breakdown: OwaspBucket[] | null;
  recommendations: Recommendation[] | null;
  error: string | null;
}

export interface Result {
  id: string;
  attack_id: string;
  attack_name: string | null;
  category: string | null;
  owasp: string | null;
  severity: string | null;
  prompt_sent: string | null;
  response_text: string | null;
  succeeded: boolean;
  detection_method: string | null;
  confidence: number | null;
  latency_ms: number | null;
  error: string | null;
}

export interface RedTeamRound {
  round: number;
  strategy: string;
  attack_prompt: string;
  target_response: string;
  complied: boolean;
  reason: string;
  latency_ms: number;
}

export interface RedTeamSession {
  id: string;
  target_model_id: string;
  target_label: string | null;
  attacker_model_id: string | null;
  objective: string;
  max_rounds: number;
  status: "running" | "completed" | "failed";
  achieved: boolean;
  rounds_used: number;
  transcript: RedTeamRound[] | null;
  summary: string | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
}
