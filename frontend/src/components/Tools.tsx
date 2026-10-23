import { useState } from "react";
import { api } from "../api";
import { ErrorNote, FindingsList, ScoreMeter, verdictClass } from "./Shared";

export function UrlChecker() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.checkUrl>> | null>(null);
  async function run(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setError("");
    try { setResult(await api.checkUrl(url)); }
    catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
    finally { setBusy(false); }
  }
  return (
    <section className="card">
      <h2>🔗 Phishing Link Checker</h2>
      <p className="hint">Paste any link from SMS, WhatsApp or email before you open it.</p>
      <form onSubmit={run} className="row">
        <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://suspicious-link.example/login" required aria-label="URL to check" />
        <button disabled={busy}>{busy ? "Checking…" : "Check link"}</button>
      </form>
      <ErrorNote error={error} />
      {result && (
        <div>
          <p>Risk score <strong className={verdictClass(result.risk_score)}>{result.risk_score}/100 — {result.verdict}</strong></p>
          <ScoreMeter score={100 - result.risk_score} invert={false} />
          <FindingsList findings={result.findings} />
        </div>
      )}
    </section>
  );
}

export function PasswordLab() {
  const [password, setPassword] = useState("");
  const [assess, setAssess] = useState<Awaited<ReturnType<typeof api.assessPassword>> | null>(null);
  const [breach, setBreach] = useState<Awaited<ReturnType<typeof api.breachCheck>> | null>(null);
  const [generated, setGenerated] = useState<{ password: string; passphrase: string } | null>(null);
  const [error, setError] = useState("");
  async function run() {
    setError("");
    try {
      setAssess(await api.assessPassword(password));
      setBreach(await api.breachCheck(password));
    } catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
  }
  return (
    <section className="card">
      <h2>🔑 Password Lab</h2>
      <p className="hint">Strength, crack-time and breach exposure. Breach checks use k-anonymity — your password never leaves this page in full.</p>
      <div className="row">
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Type a password to test it" aria-label="Password to assess" />
        <button onClick={run} disabled={!password}>Assess</button>
        <button className="secondary" onClick={async () => setGenerated(await api.generate())}>Generate strong one</button>
      </div>
      <ErrorNote error={error} />
      {assess && (
        <div>
          <p>Strength <strong>{assess.score}/100 — {assess.label}</strong> · {assess.entropy_bits} bits of entropy · offline crack time: {assess.estimated_crack_time_offline}</p>
          <ScoreMeter score={assess.score} />
          <ul className="findings">{assess.issues.map((i, k) => <li key={k}>{i}</li>)}</ul>
        </div>
      )}
      {breach && <p className={breach.breached ? "bad" : "good"}>{breach.breached ? `⚠️ Found in data breaches${breach.occurrences ? ` (${breach.occurrences.toLocaleString()} times)` : ""}. Change it everywhere you used it.` : "✓ Not found in the breach corpus."} <span className="hint">({breach.source})</span></p>}
      {generated && (
        <div className="generated">
          <p>Password: <code>{generated.password}</code></p>
          <p>Passphrase: <code>{generated.passphrase}</code></p>
        </div>
      )}
    </section>
  );
}

export function FileScanner() {
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.scanFile>> | null>(null);
  const [error, setError] = useState("");
  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setError("");
    try { setResult(await api.scanFile(file)); }
    catch (err) { setError(err instanceof Error ? err.message : "Scan failed"); }
  }
  return (
    <section className="card">
      <h2>🦠 File Malware Scanner</h2>
      <p className="hint">Static triage: real file type vs extension, entropy, embedded droppers and archive bombs. Files are analysed in memory, never executed.</p>
      <input type="file" onChange={onFile} aria-label="File to scan" />
      <ErrorNote error={error} />
      {result && (
        <div>
          <p><strong>{result.filename}</strong> — detected as {result.detected_type} · risk <strong className={verdictClass(result.risk_score)}>{result.risk_score}/100 — {result.verdict}</strong></p>
          <p className="hash">SHA-256: {result.sha256}</p>
          <FindingsList findings={result.findings} />
        </div>
      )}
    </section>
  );
}

export function EmailAnalyzer() {
  const [headers, setHeaders] = useState("");
  const [body, setBody] = useState("");
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.checkEmail>> | null>(null);
  const [error, setError] = useState("");
  async function run() {
    setError("");
    try { setResult(await api.checkEmail(headers, body)); }
    catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
  }
  return (
    <section className="card">
      <h2>✉️ Phishing Email Analyser</h2>
      <p className="hint">Paste the email headers (View source / Show original) and body. We check SPF/DKIM/DMARC, sender mismatches and social-engineering language.</p>
      <textarea value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder="From: …&#10;Authentication-Results: …" rows={4} aria-label="Email headers" />
      <textarea value={body} onChange={(e) => setBody(e.target.value)} placeholder="Email body text or HTML…" rows={4} aria-label="Email body" />
      <button onClick={run}>Analyse email</button>
      <ErrorNote error={error} />
      {result && (
        <div>
          <p>Risk <strong className={verdictClass(result.risk_score)}>{result.risk_score}/100 — {result.verdict}</strong></p>
          <FindingsList findings={result.findings} />
        </div>
      )}
    </section>
  );
}

export function WebAudit() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.webAudit>> | null>(null);
  const [error, setError] = useState("");
  async function run(e: React.FormEvent) {
    e.preventDefault(); setError("");
    try { setResult(await api.webAudit(url)); }
    catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
  }
  return (
    <section className="card">
      <h2>🌐 Website Safety Audit</h2>
      <p className="hint">Before you type a card number anywhere: is the site itself hardened? Grades HTTPS, HSTS, CSP, clickjacking and cookie protections.</p>
      <form onSubmit={run} className="row">
        <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://shop.example.com" required aria-label="Website to audit" />
        <button>Audit site</button>
      </form>
      <ErrorNote error={error} />
      {result && (
        <div>
          <p className="grade">Grade <strong>{result.grade}</strong> — {result.score}/100 {result.reachable ? "" : "(unreachable)"}</p>
          <FindingsList findings={result.findings} />
        </div>
      )}
    </section>
  );
}
