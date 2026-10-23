import { useState } from "react";
import { api } from "../api";
import { copyText, ErrorNote, FindingsList, ScoreMeter, Spinner, StrengthMeter, VerdictBadge } from "./Shared";

const PHISH_URL = "http://192.168.10.5/paypa1-secure-login.xyz/verify?account=suspended";
const SAFE_URL = "https://www.google.com";
const PHISH_HEADERS = `From: "PayPal Support" <support@paypa1-secure.xyz>
Reply-To: help@totally-different.ru
Return-Path: <bounce@mailer-other.net>
Authentication-Results: mx.example.com; spf=fail dkim=fail dmarc=fail`;
const PHISH_BODY = "Urgent! Your account will be closed within 24 hours. Confirm your password and enter your OTP immediately to restore access.";

export function UrlChecker() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.checkUrl>> | null>(null);
  async function run(value: string) {
    setBusy(true); setError("");
    try { setResult(await api.checkUrl(value)); }
    catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
    finally { setBusy(false); }
  }
  return (
    <section className="card" id="tool-url">
      <div className="card-head"><h2>🔗 Phishing Link Checker</h2><span className="tag">Module 01</span></div>
      <p className="hint">Paste any link from SMS, WhatsApp or email before you open it. 14 weighted signals — typosquatting, homographs, IP hosts, hidden destinations — each one explained.</p>
      <form onSubmit={(e) => { e.preventDefault(); void run(url); }} className="row">
        <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://suspicious-link.example/login" required aria-label="URL to check" />
        <button disabled={busy}>{busy ? <><Spinner /> Checking…</> : "Check link"}</button>
      </form>
      <div className="samples">
        <button type="button" className="sample" onClick={() => { setUrl(PHISH_URL); void run(PHISH_URL); }}>Try a phishing sample</button>
        <button type="button" className="sample" onClick={() => { setUrl(SAFE_URL); void run(SAFE_URL); }}>Try a safe sample</button>
      </div>
      <ErrorNote error={error} />
      {result && (
        <div className="result">
          <div className="result-head"><span>Risk assessment</span><VerdictBadge score={result.risk_score} verdict={result.verdict} /></div>
          <ScoreMeter score={100 - result.risk_score} />
          <FindingsList findings={result.findings} />
        </div>
      )}
    </section>
  );
}

export function PasswordLab() {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [assess, setAssess] = useState<Awaited<ReturnType<typeof api.assessPassword>> | null>(null);
  const [breach, setBreach] = useState<Awaited<ReturnType<typeof api.breachCheck>> | null>(null);
  const [generated, setGenerated] = useState<{ password: string; passphrase: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  async function run() {
    setBusy(true); setError("");
    try {
      setAssess(await api.assessPassword(password));
      setBreach(await api.breachCheck(password));
    } catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
    finally { setBusy(false); }
  }
  return (
    <section className="card" id="tool-password">
      <div className="card-head"><h2>🔑 Password Lab</h2><span className="tag">Module 02</span></div>
      <p className="hint">Strength, crack-time and breach exposure. Breach checks use k-anonymity — only 5 characters of the password's hash ever leave your browser.</p>
      <div className="row">
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Type a password to test it" aria-label="Password to assess" autoComplete="off" />
        <button onClick={run} disabled={!password || busy}>{busy ? <><Spinner /> Assessing…</> : "Assess"}</button>
        <button className="secondary" onClick={async () => setGenerated(await api.generate())}>Generate strong one</button>
      </div>
      <ErrorNote error={error} />
      {assess && (
        <div className="result">
          <div className="result-head"><span>Strength — {assess.label}</span><span className="badge info">{assess.score}/100</span></div>
          <StrengthMeter score={assess.score} />
          <p className="meta">{assess.entropy_bits} bits of entropy · offline crack time: <strong>{assess.estimated_crack_time_offline}</strong></p>
          <ul className="findings">{assess.issues.map((i, k) => <li key={k}><span className="finding-points ok">•</span><span>{i}</span></li>)}</ul>
        </div>
      )}
      {breach && <p className={breach.breached ? "breach bad" : "breach good"}>{breach.breached ? `⚠️ This password appears in public data breaches${breach.occurrences ? ` (${breach.occurrences.toLocaleString()} times)` : ""}. Change it everywhere you have used it.` : "✓ Not found in the breach corpus."} <span className="hint">Source: {breach.source}</span></p>}
      {generated && (
        <div className="generated">
          <p>Password <code>{generated.password}</code> <button type="button" className="copy" onClick={() => copyText(generated.password, setCopied)}>{copied ? "Copied ✓" : "Copy"}</button></p>
          <p>Passphrase <code>{generated.passphrase}</code> <button type="button" className="copy" onClick={() => copyText(generated.passphrase, setCopied)}>{copied ? "Copied ✓" : "Copy"}</button></p>
        </div>
      )}
    </section>
  );
}

export function FileScanner() {
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.scanFile>> | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setError(""); setBusy(true);
    try { setResult(await api.scanFile(file)); }
    catch (err) { setError(err instanceof Error ? err.message : "Scan failed"); }
    finally { setBusy(false); }
  }
  return (
    <section className="card" id="tool-file">
      <div className="card-head"><h2>🦠 File Malware Scanner</h2><span className="tag">Module 03</span></div>
      <p className="hint">Static triage the way a SOC analyst starts: real file type vs extension, entropy, embedded droppers, archive bombs. Files are analysed in memory — never executed, never stored.</p>
      <label className="drop">
        <input type="file" onChange={onFile} aria-label="File to scan" />
        {busy ? <><Spinner /> Scanning…</> : "Choose a file to scan (max 10 MB)"}
      </label>
      <ErrorNote error={error} />
      {result && (
        <div className="result">
          <div className="result-head"><span>{result.filename} · {result.detected_type}</span><VerdictBadge score={result.risk_score} verdict={result.verdict} /></div>
          <p className="hash">SHA-256 {result.sha256} <button type="button" className="copy" onClick={() => copyText(result.sha256, setCopied)}>{copied ? "Copied ✓" : "Copy"}</button></p>
          <FindingsList findings={result.findings} />
        </div>
      )}
    </section>
  );
}

export function EmailAnalyzer() {
  const [headers, setHeaders] = useState("");
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.checkEmail>> | null>(null);
  const [error, setError] = useState("");
  async function run(h: string, b: string) {
    setError(""); setBusy(true);
    try { setResult(await api.checkEmail(h, b)); }
    catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
    finally { setBusy(false); }
  }
  return (
    <section className="card" id="tool-email">
      <div className="card-head"><h2>✉️ Phishing Email Analyser</h2><span className="tag">Module 04</span></div>
      <p className="hint">Paste the email headers (Show original / View source) and body. Aegis verifies SPF, DKIM and DMARC, hunts sender mismatches and scores the social engineering.</p>
      <textarea value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder={"From: …\nAuthentication-Results: …"} rows={4} aria-label="Email headers" />
      <textarea value={body} onChange={(e) => setBody(e.target.value)} placeholder="Email body text or HTML…" rows={4} aria-label="Email body" />
      <div className="row">
        <button onClick={() => run(headers, body)} disabled={busy}>{busy ? <><Spinner /> Analysing…</> : "Analyse email"}</button>
        <button type="button" className="sample" onClick={() => { setHeaders(PHISH_HEADERS); setBody(PHISH_BODY); void run(PHISH_HEADERS, PHISH_BODY); }}>Load a phishing sample</button>
      </div>
      <ErrorNote error={error} />
      {result && (
        <div className="result">
          <div className="result-head"><span>Email risk</span><VerdictBadge score={result.risk_score} verdict={result.verdict} /></div>
          <ScoreMeter score={100 - result.risk_score} />
          <FindingsList findings={result.findings} />
        </div>
      )}
    </section>
  );
}

export function WebAudit() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.webAudit>> | null>(null);
  const [error, setError] = useState("");
  async function run(e: React.FormEvent) {
    e.preventDefault(); setError(""); setBusy(true);
    try { setResult(await api.webAudit(url)); }
    catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
    finally { setBusy(false); }
  }
  return (
    <section className="card" id="tool-web">
      <div className="card-head"><h2>🌐 Website Safety Audit</h2><span className="tag">Module 05</span></div>
      <p className="hint">Before you type a card number anywhere: is the site itself hardened? Grades HTTPS, HSTS, CSP, clickjacking and cookie protections. SSRF-guarded — internal addresses are refused.</p>
      <form onSubmit={run} className="row">
        <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://shop.example.com" required aria-label="Website to audit" />
        <button disabled={busy}>{busy ? <><Spinner /> Auditing…</> : "Audit site"}</button>
      </form>
      <ErrorNote error={error} />
      {result && (
        <div className="result">
          <div className="result-head"><span>Security grade</span><span className="grade-badge">{result.grade}</span></div>
          <p className="meta">{result.score}/100 {result.reachable ? "" : "· site unreachable or blocked the audit"}</p>
          <FindingsList findings={result.findings} />
        </div>
      )}
    </section>
  );
}
