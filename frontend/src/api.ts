const BASE = import.meta.env.VITE_API_URL ?? "";

export interface Finding {
  points: number;
  code: string;
  message: string;
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
