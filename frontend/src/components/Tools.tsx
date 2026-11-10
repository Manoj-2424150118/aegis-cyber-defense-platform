import { useEffect, useState } from "react";
import { api, validateLookupTarget, type RedirectTrace } from "../api";
import { copyText, ErrorNote, FindingsList, HERO_SCAN_EVENT, PasswordInput, ResultActions, ScanTimeline, ScoreMeter, Spinner, StrengthMeter, summaryText, useLiveScan, VerdictBadge } from "./Shared";
import { FileSearchIcon, GlobeIcon, KeyIcon, LinkIcon, LockIcon, MailIcon, MessageIcon, ServerIcon, UploadIcon, XIcon } from "./icons";

const PHISH_URL = "http://192.168.10.5/paypa1-secure-login.xyz/verify?account=suspended";
const SAFE_URL = "https://www.google.com";
const PHISH_HEADERS = `From: "PayPal Support" <support@paypa1-secure.xyz>
Reply-To: help@totally-different.ru
Return-Path: <bounce@mailer-other.net>
Authentication-Results: mx.example.com; spf=fail dkim=fail dmarc=fail`;
const PHISH_BODY = "Urgent! Your account will be closed within 24 hours. Confirm your password and enter your OTP immediately to restore access.";

export function UrlChecker() {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [trace, setTrace] = useState<RedirectTrace | null>(null);
  const [tracing, setTracing] = useState(false);
  const [traceError, setTraceError] = useState("");
  const [copiedClean, setCopiedClean] = useState(false);
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.checkUrl>> | null>(null);
  type R = Awaited<ReturnType<typeof api.checkUrl>>;
  const scan = useLiveScan<R>();
  // The hero scan box hands its value over through this event.
  useEffect(() => {
    const handler = (e: Event) => {
      const value = (e as CustomEvent<string>).detail;
      if (value) { setUrl(value); void run(value); }
    };
    window.addEventListener(HERO_SCAN_EVENT, handler);
    return () => window.removeEventListener(HERO_SCAN_EVENT, handler);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  async function run(value: string) {
    setError(""); setResult(null); setTrace(null); setTraceError("");
    const invalid = validateLookupTarget(value, "score");
    if (invalid) { setError(invalid); return; }
    try {
      const r = await scan.run((h) => api.checkUrlStream(value, h));
      if (r) setResult(r);
    } catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
  }
  async function runTrace() {
    setTracing(true); setTraceError(""); setTrace(null);
    try {
      setTrace(await api.resolveUrl(url));
    } catch (err) { setTraceError(err instanceof Error ? err.message : "Trace failed"); }
    finally { setTracing(false); }
  }
  return (
    <section className="card" id="tool-url">
      <div className="card-head">
        <span className="tile"><LinkIcon size={20} /></span>
        <h2>Phishing Link Checker</h2>
        <span className="tag">Links</span>
      </div>
      <p className="hint">Paste any link before you open it. It is checked live, signal by signal.</p>
      <form onSubmit={(e) => { e.preventDefault(); void run(url); }}>
        <div className="field">
          <span id="url-label">Link to check</span>
          <div className="row">
            <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://suspicious-link.example/login" required aria-labelledby="url-label" />
            <button disabled={scan.running}>{scan.running ? <><Spinner /> Checking…</> : "Check link"}</button>
          </div>
        </div>
      </form>
      <div className="samples">
        <button type="button" className="sample" onClick={() => { setUrl(PHISH_URL); void run(PHISH_URL); }}>Try a phishing sample</button>
        <button type="button" className="sample" onClick={() => { setUrl(SAFE_URL); void run(SAFE_URL); }}>Try a safe sample</button>
      </div>
      {scan.steps.length === 0 && <ErrorNote error={error} />}
      <ScanTimeline scan={scan} error={error} />
      {result && (
        <div className="result">
          <div className="result-head"><span>Risk assessment</span><VerdictBadge score={result.risk_score} verdict={result.verdict} /></div>
          <ScoreMeter score={100 - result.risk_score} />
          <FindingsList findings={result.findings} />
          {result.trackers && result.trackers.length > 0 && (
            <div className="trace-box">
              <p className="trace-title">Trackers in this link</p>
              <ul className="findings">
                {result.trackers.map((t, i) => (
                  <li key={i}><span className="sev-dot hit" aria-hidden="true" /><span>{t.type === "parameter" ? <>Tracking parameter: <code>{t.name}</code></> : t.type === "redirect-wrapper" ? <>Redirect wrapper: <code>{t.name}</code></> : <>Wrapped destination: <code>{t.name}</code></>}</span></li>
                ))}
              </ul>
              {result.cleaned_url && (
                <form className="row" onSubmit={(e) => e.preventDefault()}>
                  <input readOnly value={result.cleaned_url} aria-label="Cleaned link without trackers" />
                  <button type="button" onClick={() => void copyText(result.cleaned_url!, setCopiedClean)}>{copiedClean ? "Copied" : "Copy clean link"}</button>
                </form>
              )}
            </div>
          )}
          <div className="samples">
            <button type="button" className="sample" disabled={tracing} onClick={() => void runTrace()}>{tracing ? "Tracing…" : "Trace where this link really goes"}</button>
          </div>
          <ResultActions title="summary" summary={summaryText(result.verdict, result.risk_score, result.findings)} data={result} />
          <ErrorNote error={traceError} />
          {trace && (
            <div className="trace-box">
              <p className="trace-title">Redirect chain — {trace.hops} hop{trace.hops === 1 ? "" : "s"}{trace.crossed_domains ? " · crossed domains" : ""}</p>
              <ol className="chain">
                {trace.chain.map((s, i) => <li key={i}><code>{s.status}</code> <span>{s.url}</span></li>)}
              </ol>
              {trace.error
                ? <p className="hint">{trace.error}</p>
                : <p className="hint">Final destination: <strong>{trace.final_verdict}</strong> ({trace.final_risk_score}/100 risk)</p>}
            </div>
          )}
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
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  type R = Awaited<ReturnType<typeof api.passwordStream>>;
  const scan = useLiveScan<R>();
  async function run() {
    setError(""); setAssess(null); setBreach(null);
    try {
      const r = await scan.run((h) => api.passwordStream(password, h));
      if (r) {
        const { breach: b, ...rest } = r;
        setAssess(rest);
        setBreach(b);
      }
    } catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
  }
  return (
    <section className="card" id="tool-password">
      <div className="card-head">
        <span className="tile"><KeyIcon size={20} /></span>
        <h2>Password Lab</h2>
        <span className="tag">Passwords</span>
      </div>
      <p className="hint">Strength, crack-time and breach exposure, streamed live. Only 5 hash characters ever leave your browser for the breach check.</p>
      <div className="field">
        <span id="pw-label">Password to test</span>
        <div className="row">
          <PasswordInput value={password} onChange={setPassword} placeholder="Type a password to test it" ariaLabel="Password to assess" />
          <button onClick={run} disabled={!password || scan.running}>{scan.running ? <><Spinner /> Assessing…</> : "Assess"}</button>
        </div>
      </div>
      <div className="samples">
        <button type="button" className="sample" onClick={async () => setGenerated(await api.generate())}>Generate a strong one</button>
      </div>
      {scan.steps.length === 0 && <ErrorNote error={error} />}
      <ScanTimeline scan={scan} error={error} />
      {assess && (
        <div className="result">
          <div className="result-head"><span>Strength — {assess.label}</span><span className="badge info">{assess.score}/100</span></div>
          <StrengthMeter score={assess.score} />
          <p className="meta">{assess.entropy_bits} bits of entropy · offline crack time: <strong>{assess.estimated_crack_time_offline}</strong></p>
          <ul className="findings">{assess.issues.map((i, k) => <li key={k}><span className="sev-dot ok" aria-hidden="true" /><span>{i}</span></li>)}</ul>
        </div>
      )}
      {breach && <p className={breach.breached ? "breach bad" : "breach good"}>{breach.breached ? `This password appears in public data breaches${breach.occurrences ? ` (${breach.occurrences.toLocaleString()} times)` : ""}. Change it everywhere you have used it.` : "Not found in the breach corpus."} <span className="hint">Source: {breach.source}</span></p>}
      {generated && (
        <div className="generated">
          <p>Password <code>{generated.password}</code> <button type="button" className="copy" onClick={() => copyText(generated.password, setCopied)}>{copied ? "Copied" : "Copy"}</button></p>
          <p>Passphrase <code>{generated.passphrase}</code> <button type="button" className="copy" onClick={() => copyText(generated.passphrase, setCopied)}>{copied ? "Copied" : "Copy"}</button></p>
        </div>
      )}
    </section>
  );
}

export function FileScanner() {
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.scanFile>> | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const [fileMeta, setFileMeta] = useState<{ name: string; size: number } | null>(null);
  type R = Awaited<ReturnType<typeof api.scanFile>>;
  const scan = useLiveScan<R>();
  async function scanFile(file: File) {
    setError(""); setResult(null);
    setFileMeta({ name: file.name, size: file.size });
    try {
      const r = await scan.run((h) => api.scanFileStream(file, h));
      if (r) setResult(r);
    } catch (err) { setError(err instanceof Error ? err.message : "Scan failed"); }
  }
  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) void scanFile(file);
    e.target.value = "";
  }
  return (
    <section className="card" id="tool-file">
      <div className="card-head">
        <span className="tile"><FileSearchIcon size={20} /></span>
        <h2>File Malware Scanner</h2>
        <span className="tag">Files</span>
      </div>
      <p className="hint">Static malware triage, stage by stage. Files are analysed in memory — never executed, never stored.</p>
      <label
        className={`drop${dragging ? " dragging" : ""}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files?.[0]; if (f) void scanFile(f); }}
      >
        <input type="file" onChange={onFile} aria-label="File to scan" />
        <UploadIcon size={22} />
        {scan.running ? <><Spinner /> Scanning…</> : "Drop a file here, or click to browse"}
        <span className="drop-meta">Maximum 10 MB · analysed in memory only</span>
      </label>
      {fileMeta && (
        <div className="file-chip">
          <span className="file-name">{fileMeta.name}</span>
          <span className="file-size">{(fileMeta.size / 1024).toFixed(1)} KB</span>
          <button type="button" className="copy" onClick={() => { setFileMeta(null); setResult(null); }} aria-label="Remove file">
            <XIcon size={13} />
          </button>
        </div>
      )}
      {scan.steps.length === 0 && <ErrorNote error={error} />}
      <ScanTimeline scan={scan} error={error} />
      {result && (
        <div className="result">
          <div className="result-head"><span>{result.filename} · {result.detected_type}</span><VerdictBadge score={result.risk_score} verdict={result.verdict} /></div>
          <p className="hash">SHA-256 {result.sha256} <button type="button" className="copy" onClick={() => copyText(result.sha256, setCopied)}>{copied ? "Copied" : "Copy"}</button></p>
          <FindingsList findings={result.findings} />
          <ResultActions title="summary" summary={summaryText(result.verdict, result.risk_score, result.findings)} data={result} />
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
  type R = Awaited<ReturnType<typeof api.checkEmail>>;
  const scan = useLiveScan<R>();
  async function run(h: string, b: string) {
    setError(""); setResult(null);
    try {
      const r = await scan.run((hh) => api.checkEmailStream(h, b, hh));
      if (r) setResult(r);
    } catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
  }
  return (
    <section className="card" id="tool-email">
      <div className="card-head">
        <span className="tile"><MailIcon size={20} /></span>
        <h2>Phishing Email Analyser</h2>
        <span className="tag">Email</span>
      </div>
      <p className="hint">Paste the headers and body. Authentication, spoofing and social engineering are checked live.</p>
      <div className="field" style={{ marginBottom: 12 }}>
        <span id="emh-label">Email headers</span>
        <textarea value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder={"From: …\nAuthentication-Results: …"} rows={4} aria-labelledby="emh-label" />
      </div>
      <div className="field" style={{ marginBottom: 12 }}>
        <span id="emb-label">Email body</span>
        <textarea value={body} onChange={(e) => setBody(e.target.value)} placeholder="Email body text or HTML…" rows={4} aria-labelledby="emb-label" />
      </div>
      <div className="row">
        <button onClick={() => run(headers, body)} disabled={scan.running}>{scan.running ? <><Spinner /> Analysing…</> : "Analyse email"}</button>
        <button type="button" className="sample" onClick={() => { setHeaders(PHISH_HEADERS); setBody(PHISH_BODY); void run(PHISH_HEADERS, PHISH_BODY); }}>Load a phishing sample</button>
      </div>
      {scan.steps.length === 0 && <ErrorNote error={error} />}
      <ScanTimeline scan={scan} error={error} />
      {result && (
        <div className="result">
          <div className="result-head"><span>Email risk</span><VerdictBadge score={result.risk_score} verdict={result.verdict} /></div>
          <ScoreMeter score={100 - result.risk_score} />
          <FindingsList findings={result.findings} />
          <ResultActions title="summary" summary={summaryText(result.verdict, result.risk_score, result.findings)} data={result} />
        </div>
      )}
    </section>
  );
}

const SCAM_MESSAGE = "Dear customer, your bank account will be blocked today due to pending KYC. Verify immediately at http://secure-kyc-update.xyz/verify and share the OTP sent to your mobile to avoid suspension.";
const ARREST_MESSAGE = "This is CBI cyber cell. A parcel booked in your name contained narcotics. You are under digital arrest — pay the verification amount to UPI ID officer.pay@okhdfc immediately to clear your case.";

export function MessageChecker() {
  const [text, setText] = useState("");
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.checkMessage>> | null>(null);
  const [error, setError] = useState("");
  type R = Awaited<ReturnType<typeof api.checkMessage>>;
  const scan = useLiveScan<R>();
  async function run(value: string) {
    setError(""); setResult(null);
    if (!value.trim()) { setError("Paste a message to check."); return; }
    try {
      const r = await scan.run((h) => api.checkMessageStream(value, h));
      if (r) setResult(r);
    } catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
  }
  return (
    <section className="card" id="tool-message">
      <div className="card-head">
        <span className="tile"><MessageIcon size={20} /></span>
        <h2>Scam Message Checker</h2>
        <span className="tag">Messages</span>
      </div>
      <p className="hint">Paste a suspicious SMS or WhatsApp message — scam playbooks, OTP fishing and every link inside.</p>
      <div className="field" style={{ marginBottom: 12 }}>
        <span id="msg-label">Message to check</span>
        <textarea value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste the full message here…" rows={5} aria-labelledby="msg-label" />
      </div>
      <div className="row">
        <button onClick={() => run(text)} disabled={scan.running}>{scan.running ? <><Spinner /> Checking…</> : "Check message"}</button>
      </div>
      <div className="samples">
        <button type="button" className="sample" onClick={() => { setText(SCAM_MESSAGE); void run(SCAM_MESSAGE); }}>Try: KYC scam</button>
        <button type="button" className="sample" onClick={() => { setText(ARREST_MESSAGE); void run(ARREST_MESSAGE); }}>Try: digital arrest</button>
      </div>
      {scan.steps.length === 0 && <ErrorNote error={error} />}
      <ScanTimeline scan={scan} error={error} />
      {result && (
        <div className="result">
          <div className="result-head"><span>Message risk</span><VerdictBadge score={result.risk_score} verdict={result.verdict} /></div>
          <ScoreMeter score={100 - result.risk_score} />
          {result.links_found.length > 0 && <p className="meta">Links found &amp; scored: {result.links_found.join(" · ")}</p>}
          <FindingsList findings={result.findings} />
          <ResultActions title="summary" summary={summaryText(result.verdict, result.risk_score, result.findings)} data={result} />
        </div>
      )}
    </section>
  );
}

export function DomainChecker() {
  const [domain, setDomain] = useState("");
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.checkDomain>> | null>(null);
  const [error, setError] = useState("");
  type R = Awaited<ReturnType<typeof api.checkDomain>>;
  const scan = useLiveScan<R>();
  async function run(e: React.FormEvent) {
    e.preventDefault(); setError(""); setResult(null);
    const invalid = validateLookupTarget(domain, "audit");
    if (invalid) { setError(invalid); return; }
    try {
      const r = await scan.run((h) => api.checkDomainStream(domain, h));
      if (r) setResult(r);
    } catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
  }
  return (
    <section className="card" id="tool-domain">
      <div className="card-head">
        <span className="tile"><ServerIcon size={20} /></span>
        <h2>Domain Security Checker</h2>
        <span className="tag">Domains</span>
      </div>
      <p className="hint">Can anyone email as this domain? SPF, DMARC, CAA and DNS health — graded live.</p>
      <form onSubmit={run}>
        <div className="field">
          <span id="dom-label">Domain</span>
          <div className="row">
            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" required aria-labelledby="dom-label" />
            <button disabled={scan.running}>{scan.running ? <><Spinner /> Checking…</> : "Check domain"}</button>
          </div>
        </div>
      </form>
      {scan.steps.length === 0 && <ErrorNote error={error} />}
      <ScanTimeline scan={scan} error={error} />
      {result && (
        <div className="result">
          <div className="result-head"><span>Spoof-resistance grade</span><span className="grade-badge">{result.grade}</span></div>
          <p className="meta">{result.domain} · {result.score}/100</p>
          <FindingsList findings={result.findings} />
          <ResultActions title="summary" summary={summaryText(`grade ${result.grade}`, result.score, result.findings)} data={result} />
        </div>
      )}
    </section>
  );
}

export function TlsInspector() {
  const [host, setHost] = useState("");
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.inspectTls>> | null>(null);
  const [error, setError] = useState("");
  type R = Awaited<ReturnType<typeof api.inspectTls>>;
  const scan = useLiveScan<R>();
  async function run(e: React.FormEvent) {
    e.preventDefault(); setError(""); setResult(null);
    const invalid = validateLookupTarget(host, "audit");
    if (invalid) { setError(invalid); return; }
    try {
      const r = await scan.run((h) => api.inspectTlsStream(host, h));
      if (r) setResult(r);
    } catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
  }
  return (
    <section className="card" id="tool-tls">
      <div className="card-head">
        <span className="tile"><LockIcon size={20} /></span>
        <h2>TLS Certificate Inspector</h2>
        <span className="tag">Certificates</span>
      </div>
      <p className="hint">Issuer, expiry, hostname coverage and protocol — graded from a real TLS handshake.</p>
      <form onSubmit={run}>
        <div className="field">
          <span id="tls-label">Host</span>
          <div className="row">
            <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="https://shop.example.com" required aria-labelledby="tls-label" />
            <button disabled={scan.running}>{scan.running ? <><Spinner /> Inspecting…</> : "Inspect TLS"}</button>
          </div>
        </div>
      </form>
      {scan.steps.length === 0 && <ErrorNote error={error} />}
      <ScanTimeline scan={scan} error={error} />
      {result && (
        <div className="result">
          <div className="result-head"><span>Certificate grade</span><span className="grade-badge">{result.grade}</span></div>
          <p className="meta">
            {result.host} · {result.score}/100
            {result.facts?.issuer ? ` · Issued by ${result.facts.issuer}` : ""}
            {typeof result.facts?.days_left === "number" ? ` · ${result.facts.days_left} days left` : ""}
            {result.facts?.protocol ? ` · ${result.facts.protocol}` : ""}
            {result.facts?.verified === false ? " · chain did not verify" : ""}
          </p>
          <FindingsList findings={result.findings} />
          <ResultActions title="summary" summary={summaryText(`grade ${result.grade}`, result.score, result.findings)} data={result} />
        </div>
      )}
    </section>
  );
}

export function WebAudit() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.webAudit>> | null>(null);
  const [error, setError] = useState("");
  type R = Awaited<ReturnType<typeof api.webAudit>>;
  const scan = useLiveScan<R>();
  async function run(e: React.FormEvent) {
    e.preventDefault(); setError(""); setResult(null);
    const invalid = validateLookupTarget(url, "audit");
    if (invalid) { setError(invalid); return; }
    try {
      const r = await scan.run((h) => api.webAuditStream(url, h));
      if (r) setResult(r);
    } catch (err) { setError(err instanceof Error ? err.message : "Failed"); }
  }
  return (
    <section className="card" id="tool-web">
      <div className="card-head">
        <span className="tile"><GlobeIcon size={20} /></span>
        <h2>Website Safety Audit</h2>
        <span className="tag">Websites</span>
      </div>
      <p className="hint">Grades a site's HTTPS, headers and cookies — live. Internal addresses are refused.</p>
      <form onSubmit={run}>
        <div className="field">
          <span id="web-label">Website</span>
          <div className="row">
            <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://shop.example.com" required aria-labelledby="web-label" />
            <button disabled={scan.running}>{scan.running ? <><Spinner /> Auditing…</> : "Audit site"}</button>
          </div>
        </div>
      </form>
      {scan.steps.length === 0 && <ErrorNote error={error} />}
      <ScanTimeline scan={scan} error={error} />
      {result && (
        <div className="result">
          <div className="result-head"><span>Security grade</span><span className="grade-badge">{result.grade}</span></div>
          <p className="meta">{result.score}/100 {result.reachable ? "" : "· site unreachable or blocked the audit"}</p>
          <FindingsList findings={result.findings} />
          <ResultActions title="summary" summary={summaryText(`grade ${result.grade}`, result.score, result.findings)} data={result} />
        </div>
      )}
    </section>
  );
}
