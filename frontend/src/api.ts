const BASE = import.meta.env.VITE_API_URL ?? "";

/* ── Lookup-target validation (mirrors backend/app/validation.py) ─────
 * The regexes are the corrected form of the commonly-copied snippet: the
 * label group needs a non-capturing group, otherwise the pattern is a
 * syntax error. The IPv4 check also verifies octet range, which the
 * regex alone cannot (it accepts 999.999.999.999). */
export const DOMAIN_REGEX = /^(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$/;
export const IP_REGEX = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;

export function isValidIpv4(host: string): boolean {
  return IP_REGEX.test(host) && host.split(".").every((o) => Number(o) <= 255);
}

export function isValidDomain(host: string): boolean {
  return DOMAIN_REGEX.test(host.replace(/\.$/, ""));
}

export function isValidHost(host: string): boolean {
  if (!host || host.length > 253 || /\s/.test(host)) return false;
  // IPv6 literals arrive bracket-stripped from the URL parser (the
  // parser has already removed any port, so a colon means IPv6 here).
  if (host.includes(":")) return /^[0-9a-fA-F:]+$/.test(host);
  return isValidIpv4(host) || isValidDomain(host);
}

/** Validate a user-typed link/audit target before any request is made.
 * Returns a human-readable error, or null when the target is well-formed.
 * Non-HTTP schemes are left for the analyser in "score" mode (it flags
 * javascript:/data: links as findings); audit mode rejects them. */
export function validateLookupTarget(raw: string, mode: "score" | "audit"): string | null {
  const value = raw.trim();
  if (!value) return "Enter a link to check.";
  if (/\s/.test(value)) return "Links must not contain spaces.";
  const scheme = value.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/)?.[1]?.toLowerCase();
  if (scheme && scheme !== "http" && scheme !== "https") {
    return mode === "audit"
      ? "Only http/https websites can be audited."
      : null; // the URL analyser scores dangerous schemes as a finding
  }
  let host = "";
  try {
    host = new URL(value.includes("://") ? value : `https://${value}`).hostname.toLowerCase();
  } catch {
    return "That doesn't look like a valid link.";
  }
  if (!host) return "The link has no host to look up.";
  if (!isValidHost(host)) return `'${host}' is not a valid domain name or IP address.`;
  return null;
}

/* ── Resilient fetch layer ────────────────────────────────────────────
 * The live demo runs on a free tier that spins down when idle, so the
 * first request after a nap can take ~50s or fail outright. Every call
 * gets an AbortController timeout (no more silent hangs), and safe
 * analysis calls retry once on network errors / 502–504 gateway states
 * — exactly the cold-start signature — before surfacing a friendly,
 * actionable error instead of a raw TypeError. */
const REQUEST_TIMEOUT_MS = 20_000;
const STREAM_CONNECT_TIMEOUT_MS = 75_000; // covers a full cold start
const RETRY_DELAY_MS = 1_500;

export class ColdStartError extends Error {}

function friendlyError(err: unknown): Error {
  if (err instanceof ColdStartError) return err;
  if (err instanceof DOMException && err.name === "AbortError") {
    return new ColdStartError(
      "The server took too long to respond — the free demo may be waking up from sleep. Wait a few seconds and try again.",
    );
  }
  if (err instanceof TypeError) {
    return new ColdStartError(
      "Couldn't reach the server — the free demo may be waking up from sleep. Wait a few seconds and try again.",
    );
  }
  return err instanceof Error ? err : new Error("Request failed");
}

interface FetchOptions {
  timeoutMs: number;
  retryColdStart?: boolean;
}

async function fetchWithTimeout(url: string, init: RequestInit, opts: FetchOptions): Promise<Response> {
  const attempts = opts.retryColdStart ? 2 : 1;
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
    try {
      const res = await fetch(url, { ...init, signal: controller.signal });
      clearTimeout(timer);
      // Gateway states from a still-booting instance: retry once.
      if (opts.retryColdStart && attempt < attempts && [502, 503, 504].includes(res.status)) {
        await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
        continue;
      }
      return res;
    } catch (err) {
      clearTimeout(timer);
      lastError = err;
      if (attempt < attempts) {
        await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
        continue;
      }
    }
  }
  throw friendlyError(lastError);
}

/** FastAPI error bodies come in three shapes: our own endpoints raise
 * {detail: "message"}, but request-validation failures (422) return
 * {detail: [{loc, msg, …}]} and a few paths return an object. Passing
 * any of those straight into `new Error(...)` renders the infamous
 * "[object Object]" — so normalise every shape to readable text here,
 * once, for every caller. */
export function detailToMessage(detail: unknown, status: number): string {
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    const parts = detail
      .map((d) => {
        const e = d as { loc?: unknown; msg?: string };
        const field = Array.isArray(e.loc) ? e.loc.filter((p) => p !== "body").join(".") : "";
        return e.msg ? (field ? `${field}: ${e.msg}` : e.msg) : "";
      })
      .filter(Boolean);
    if (parts.length) return parts.join(" · ");
  }
  if (detail && typeof detail === "object") {
    const o = detail as { msg?: string; message?: string };
    if (o.msg) return o.msg;
    if (o.message) return o.message;
  }
  return `Request failed (${status})`;
}

export interface Finding {
  points: number;
  code: string;
  message: string;
  fix?: string;
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
 * with the stream's final result payload. The timeout guards only the
 * connect phase (cold starts); once events flow, the stream runs to
 * completion. */
export async function streamPost<T>(path: string, body: unknown, handlers: StreamHandlers = {}): Promise<T> {
  const isForm = typeof FormData !== "undefined" && body instanceof FormData;
  const res = await fetchWithTimeout(
    `${BASE}${path}`,
    {
      method: "POST",
      headers: isForm ? undefined : { "Content-Type": "application/json" },
      body: isForm ? (body as FormData) : JSON.stringify(body),
    },
    { timeoutMs: STREAM_CONNECT_TIMEOUT_MS, retryColdStart: true },
  );
  if (!res.ok || !res.body) {
    const data = (await res.json().catch(() => ({}))) as { detail?: unknown };
    throw new Error(detailToMessage(data.detail, res.status));
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

async function post<T>(path: string, body: unknown, token?: string, retryColdStart = true): Promise<T> {
  // Analysis calls are idempotent, so they retry once through a cold
  // start. State-changing calls (register, vault writes) pass
  // retryColdStart=false: if the network drops after the server acted,
  // a blind retry could duplicate the write.
  const res = await fetchWithTimeout(
    `${BASE}${path}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(body),
    },
    { timeoutMs: REQUEST_TIMEOUT_MS, retryColdStart },
  );
  if (!res.ok) {
    const data = (await res.json().catch(() => ({}))) as { detail?: unknown };
    throw new Error(detailToMessage(data.detail, res.status));
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
  checkMessage: (text: string) =>
    post<{ risk_score: number; verdict: string; findings: Finding[]; links_found: string[] }>("/api/tools/message", { text }),
  checkDomain: (domain: string) =>
    post<{ domain: string; score: number; grade: string; findings: Finding[] }>("/api/tools/domain", { domain }),
  inspectTls: (host: string) =>
    post<{
      host: string; score: number; grade: string; reachable?: boolean;
      facts: { issuer?: string; subject?: string; san?: string[]; not_after?: string; days_left?: number | null; protocol?: string | null; verified?: boolean };
      findings: Finding[];
    }>("/api/tools/tls", { host }),
  async scanFile(file: File) {
    const form = new FormData();
    form.append("file", file);
    const res = await fetchWithTimeout(
      `${BASE}/api/tools/file`,
      { method: "POST", body: form },
      { timeoutMs: REQUEST_TIMEOUT_MS, retryColdStart: true },
    );
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
  checkMessageStream: (text: string, h?: StreamHandlers) =>
    streamPost<{ risk_score: number; verdict: string; findings: Finding[]; links_found: string[] }>("/api/tools/message/stream", { text }, h),
  checkDomainStream: (domain: string, h?: StreamHandlers) =>
    streamPost<{ domain: string; score: number; grade: string; findings: Finding[] }>("/api/tools/domain/stream", { domain }, h),
  inspectTlsStream: (host: string, h?: StreamHandlers) =>
    streamPost<{
      host: string; score: number; grade: string; reachable?: boolean;
      facts: { issuer?: string; subject?: string; san?: string[]; not_after?: string; days_left?: number | null; protocol?: string | null; verified?: boolean };
      findings: Finding[];
    }>("/api/tools/tls/stream", { host }, h),
  scanFileStream: (file: File, h?: StreamHandlers) => {
    const form = new FormData();
    form.append("file", file);
    return streamPost<{
      filename: string; detected_type: string; sha256: string; entropy: number;
      risk_score: number; verdict: string; findings: Finding[];
    }>("/api/tools/file/stream", form, h);
  },
  register: (email: string, password: string) =>
    post<{ access_token: string }>("/api/auth/register", { email, password }, undefined, false),
  login: (email: string, password: string) =>
    post<{ access_token: string }>("/api/auth/login", { email, password }, undefined, false),
  vaultCreate: (token: string, title: string, secret: string, master_password: string) =>
    post<{ id: number; title: string }>("/api/vault", { title, secret, master_password }, token, false),
  async vaultList(token: string) {
    const res = await fetchWithTimeout(
      `${BASE}/api/vault`,
      { headers: { Authorization: `Bearer ${token}` } },
      { timeoutMs: REQUEST_TIMEOUT_MS, retryColdStart: true },
    );
    if (!res.ok) {
      const data = (await res.json().catch(() => ({}))) as { detail?: unknown };
      throw new Error(detailToMessage(data.detail, res.status));
    }
    return (await res.json()) as { id: number; title: string }[];
  },
  vaultOpen: (token: string, id: number, master_password: string) =>
    post<{ secret: string }>(`/api/vault/${id}/open`, { master_password }, token, false),
};
