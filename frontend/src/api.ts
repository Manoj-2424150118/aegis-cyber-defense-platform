const BASE = import.meta.env.VITE_API_URL ?? "";

export interface Finding {
  points: number;
  code: string;
  message: string;
}

export interface LiveStepEvent {
  type: "step";
  index: number;
  label: string;
  status: string;
  findings: Finding[];
  running_score?: number;
  detail?: Record<string, unknown>;
}

export interface StreamHandlers {
  onStart?: (totalSteps: number) => void;
  onStep?: (step: LiveStepEvent) => void;
}

/** POST to an SSE endpoint and consume events as they arrive. Resolves
 * with the stream's final result payload. */
export async function streamPost<T>(path: string, body: unknown, handlers: StreamHandlers = {}): Promise<T> {
  const isForm = typeof FormData !== "undefined" && body instanceof FormData;
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: isForm ? undefined : { "Content-Type": "application/json" },
    body: isForm ? (body as FormData) : JSON.stringify(body),
  });
  if (!res.ok || !res.body) {
    const data = (await res.json().catch(() => ({}))) as { detail?: string };
    throw new Error(data.detail ?? `Request failed (${res.status})`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let result: T | undefined;
  let streamError = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split("\n\n");
    buffer = chunks.pop() ?? "";
    for (const chunk of chunks) {
      const line = chunk.split("\n").find((l) => l.startsWith("data: "));
      if (!line) continue;
      const evt = JSON.parse(line.slice(6)) as {
        type: string; total_steps?: number; result?: T; message?: string;
        index?: number; label?: string; status?: string; findings?: Finding[];
        running_score?: number; detail?: Record<string, unknown>;
      };
      if (evt.type === "start") handlers.onStart?.(evt.total_steps ?? 0);
      else if (evt.type === "step") handlers.onStep?.(evt as LiveStepEvent);
      else if (evt.type === "result") result = evt.result;
      else if (evt.type === "error") streamError = evt.message ?? "Analysis failed";
    }
  }
  if (streamError) throw new Error(streamError);
  if (result === undefined) throw new Error("The analysis ended without a result. Please retry.");
  return result;
}

async function post<T>(path: string, body: unknown, token?: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const data = (await res.json().catch(() => ({}))) as { detail?: string };
    throw new Error(data.detail ?? `Request failed (${res.status})`);
  }
  return (await res.json()) as T;
}

export const api = {
  checkUrl: (url: string) =>
    post<{ risk_score: number; verdict: string; findings: Finding[] }>("/api/tools/url", { url }),
  assessPassword: (password: string) =>
    post<{ score: number; label: string; entropy_bits: number; estimated_crack_time_offline: string; issues: string[] }>(
      "/api/tools/password/assess",
      { password },
    ),
  breachCheck: (password: string) =>
    post<{ breached: boolean; occurrences: number | null; source: string; note: string }>(
      "/api/tools/password/breach",
      { password },
    ),
  generate: () =>
    post<{ password: string; passphrase: string }>("/api/tools/password/generate", { length: 20, symbols: true }),
  checkEmail: (headers: string, body: string) =>
    post<{ risk_score: number; verdict: string; findings: Finding[] }>("/api/tools/email", { headers, body }),
  webAudit: (url: string) =>
    post<{ score: number; grade: string; reachable: boolean; findings: Finding[] }>("/api/tools/web-audit", { url }),
  async scanFile(file: File) {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch(`${BASE}/api/tools/file`, { method: "POST", body: form });
    if (!res.ok) throw new Error(`Scan failed (${res.status})`);
    return (await res.json()) as {
      filename: string; detected_type: string; sha256: string; entropy: number;
      risk_score: number; verdict: string; findings: Finding[];
    };
  },
  // ── Live-streamed variants (agent view) ──
  checkUrlStream: (url: string, h?: StreamHandlers) =>
    streamPost<{ risk_score: number; verdict: string; findings: Finding[] }>("/api/tools/url/stream", { url }, h),
  checkEmailStream: (headers: string, body: string, h?: StreamHandlers) =>
    streamPost<{ risk_score: number; verdict: string; findings: Finding[] }>("/api/tools/email/stream", { headers, body }, h),
  passwordStream: (password: string, h?: StreamHandlers) =>
    streamPost<{
      score: number; label: string; entropy_bits: number; estimated_crack_time_offline: string; issues: string[];
      breach: { breached: boolean; occurrences: number | null; source: string; note: string };
    }>("/api/tools/password/stream", { password }, h),
  webAuditStream: (url: string, h?: StreamHandlers) =>
    streamPost<{ score: number; grade: string; reachable: boolean; findings: Finding[] }>("/api/tools/web-audit/stream", { url }, h),
  scanFileStream: (file: File, h?: StreamHandlers) => {
    const form = new FormData();
    form.append("file", file);
    return streamPost<{
      filename: string; detected_type: string; sha256: string; entropy: number;
      risk_score: number; verdict: string; findings: Finding[];
    }>("/api/tools/file/stream", form, h);
  },
  register: (email: string, password: string) =>
    post<{ access_token: string }>("/api/auth/register", { email, password }),
  login: (email: string, password: string) =>
    post<{ access_token: string }>("/api/auth/login", { email, password }),
  vaultCreate: (token: string, title: string, secret: string, master_password: string) =>
    post<{ id: number; title: string }>("/api/vault", { title, secret, master_password }, token),
  async vaultList(token: string) {
    const res = await fetch(`${BASE}/api/vault`, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error("Could not load vault");
    return (await res.json()) as { id: number; title: string }[];
  },
  vaultOpen: (token: string, id: number, master_password: string) =>
    post<{ secret: string }>(`/api/vault/${id}/open`, { master_password }, token),
};
