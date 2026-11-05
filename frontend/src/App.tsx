import { useEffect, useRef, useState } from "react";
import { DomainChecker, EmailAnalyzer, FileScanner, MessageChecker, PasswordLab, TlsInspector, UrlChecker, WebAudit } from "./components/Tools";
import { VaultPanel } from "./components/VaultPanel";
import { HERO_SCAN_EVENT } from "./components/Shared";

const COVERAGE = [
  { icon: "🎣", threat: "Phishing links", defense: "URL Analyser", anchor: "tool-url", blurb: "Scores any link for typosquats, IP hosts, shorteners and credential-harvest signals." },
  { icon: "🔓", threat: "Weak & breached passwords", defense: "Password Lab", anchor: "tool-password", blurb: "Strength, crack-time and breach exposure — checked with k-anonymity, never in plain text." },
  { icon: "🦠", threat: "Malware attachments", defense: "File Scanner", anchor: "tool-file", blurb: "Static triage of suspicious files in memory. Never executed, never stored." },
  { icon: "✉️", threat: "Phishing & CEO-fraud email", defense: "Email Analyser", anchor: "tool-email", blurb: "SPF/DKIM/DMARC, spoofing and social-engineering language, signal by signal." },
  { icon: "💬", threat: "Scam SMS & WhatsApp messages", defense: "Scam Message Checker", anchor: "tool-message", blurb: "Digital-arrest, KYC, UPI and task-scam playbooks — plus every link inside the message, scored." },
  { icon: "🕵️", threat: "Unsafe websites", defense: "Website Audit", anchor: "tool-web", blurb: "Grades HTTPS, security headers and cookie flags — and shows the owner how to fix them." },
  { icon: "🌍", threat: "Spoofable domains", defense: "Domain Security Checker", anchor: "tool-domain", blurb: "Can anyone email as this domain? SPF, DMARC, CAA and DNS health, graded from live records." },
  { icon: "🔒", threat: "Bad TLS certificates", defense: "TLS Inspector", anchor: "tool-tls", blurb: "Issuer, expiry runway, hostname coverage and protocol version — from a real handshake." },
  { icon: "🗄️", threat: "Stolen secrets", defense: "Encrypted Vault", anchor: "tool-vault", blurb: "AES-256-GCM encryption with an Argon2id-derived key — the server stores only ciphertext, never the key." },
] as const;

const TOOL_NAV = [
  { label: "🔗 Link Checker", anchor: "tool-url" },
  { label: "🔑 Password Lab", anchor: "tool-password" },
  { label: "🦠 File Scanner", anchor: "tool-file" },
  { label: "✉️ Email Analyser", anchor: "tool-email" },
  { label: "💬 Message Checker", anchor: "tool-message" },
  { label: "🌐 Website Audit", anchor: "tool-web" },
  { label: "🌍 Domain Checker", anchor: "tool-domain" },
  { label: "🔒 TLS Inspector", anchor: "tool-tls" },
  { label: "🗄️ Vault", anchor: "tool-vault" },
] as const;

const PROOF = ["9 live security tools", "Live agent view", "No sign-up needed", "Files never stored", "Open source · MIT"] as const;

type ThemeMode = "auto" | "light" | "dark";

/** Auto theme follows the clock: light 07:00–19:00 local, dark at night. */
function resolvedTheme(mode: ThemeMode): "light" | "dark" {
  if (mode !== "auto") return mode;
  const h = new Date().getHours();
  return h >= 7 && h < 19 ? "light" : "dark";
}

function ThemeToggle() {
  const [mode, setMode] = useState<ThemeMode>(
    () => (document.documentElement.dataset.themeMode as ThemeMode) || "auto",
  );
  const [tick, setTick] = useState(0);
  useEffect(() => {
    document.documentElement.dataset.theme = resolvedTheme(mode);
    document.documentElement.dataset.themeMode = mode;
    try { localStorage.setItem("aegis-theme", mode); } catch { /* storage unavailable */ }
  }, [mode, tick]);
  useEffect(() => {
    if (mode !== "auto") return;
    const t = setInterval(() => setTick((x) => x + 1), 60_000); // flip at 07:00 / 19:00 without a reload
    return () => clearInterval(t);
  }, [mode]);
  const next: ThemeMode = mode === "auto" ? "light" : mode === "light" ? "dark" : "auto";
  const label = mode === "auto" ? "🌓 Auto" : mode === "light" ? "☀️ Light" : "🌙 Dark";
  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={() => setMode(next)}
      title="Theme — Auto follows day & night (light 7am–7pm). Click to switch to Light or Dark."
      aria-label={`Theme is ${mode}. Switch to ${next}.`}
    >
      {label}
    </button>
  );
}

const FAQS = [
  {
    q: "Is Aegis really free?",
    a: "Yes — free and open source under the MIT licence. No account is needed for any check; an account only unlocks the encrypted vault and scan history.",
  },
  {
    q: "What happens to files I scan?",
    a: "They are analysed in memory on the server and discarded when the scan finishes. Files are never executed and never written to disk or stored.",
  },
  {
    q: "How does the breach check work without sending my password?",
    a: "It uses k-anonymity: only the first 5 characters of your password's SHA-1 hash leave the browser, and the match is completed locally against the returned suffixes — the same model Have I Been Pwned uses.",
  },
  {
    q: "Can I trust the verdicts?",
    a: "Every verdict is explainable: each finding lists the exact signal, its weight, and a suggested fix. Aegis is a heuristic first line of defence — treat a clean result as 'no known signals found', not a guarantee, and keep your OS, browser and antivirus updated.",
  },
] as const;

const REPO = "https://github.com/Manoj-2424150118/aegis-cyber-defense-platform";
const PHISH_SAMPLE = "http://192.168.10.5/paypal/login/verify";
const SAFE_SAMPLE = "https://www.google.com";

function dispatchHeroScan(url: string) {
  window.dispatchEvent(new CustomEvent(HERO_SCAN_EVENT, { detail: url }));
  document.getElementById("tool-url")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

export default function App() {
  const [heroUrl, setHeroUrl] = useState("");
  const [version, setVersion] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const heroInputRef = useRef<HTMLInputElement>(null);

  // "/" from anywhere jumps to the hero scan box — the keyboard
  // shortcut every power-user tool (GitHub, CyberChef) trains you on.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (document.activeElement?.tagName ?? "").toUpperCase();
      if (e.key === "/" && tag !== "INPUT" && tag !== "TEXTAREA") {
        e.preventDefault();
        window.scrollTo({ top: 0, behavior: "smooth" });
        heroInputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const TOOLS = [
    { id: "tool-url", name: "Phishing Link Checker", kw: "url link phishing website address", node: <UrlChecker /> },
    { id: "tool-password", name: "Password Lab", kw: "password strength breach generator passphrase", node: <PasswordLab /> },
    { id: "tool-file", name: "File Malware Scanner", kw: "file malware virus attachment scan upload", node: <FileScanner /> },
    { id: "tool-email", name: "Phishing Email Analyser", kw: "email phishing bec headers spf dkim dmarc", node: <EmailAnalyzer /> },
    { id: "tool-message", name: "Scam Message Checker", kw: "sms whatsapp message scam text telegram upi kyc digital arrest", node: <MessageChecker /> },
    { id: "tool-web", name: "Website Safety Audit", kw: "website audit headers https cookies security grade", node: <WebAudit /> },
    { id: "tool-domain", name: "Domain Security Checker", kw: "domain dns spf dmarc caa email spoofing mx", node: <DomainChecker /> },
    { id: "tool-tls", name: "TLS Certificate Inspector", kw: "tls ssl certificate https expiry issuer handshake", node: <TlsInspector /> },
    { id: "tool-vault", name: "Encrypted Vault", kw: "vault secrets password manager encryption storage", node: <VaultPanel /> },
  ];
  const visibleTools = TOOLS.filter((t) => `${t.name} ${t.kw}`.toLowerCase().includes(filter.trim().toLowerCase()));

  // Live platform status — real data from /health, shown in the nav.
  useEffect(() => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10_000);
    fetch("/health", { signal: ctrl.signal })
      .then((r) => (r.ok ? r.json() : null))
      .then((d: { version?: string } | null) => setVersion(d?.version ?? null))
      .catch(() => setVersion(null))
      .finally(() => clearTimeout(timer));
    return () => ctrl.abort();
  }, []);

  // Scroll-reveal: sections rise in as they enter the viewport.
  useEffect(() => {
    const els = Array.from(document.querySelectorAll(".reveal"));
    if (!("IntersectionObserver" in window)) {
      els.forEach((e) => e.classList.add("visible"));
      return;
    }
    const io = new IntersectionObserver(
      (entries) => entries.forEach((en) => {
        if (en.isIntersecting) {
          en.target.classList.add("visible");
          io.unobserve(en.target);
        }
      }),
      { threshold: 0.1 },
    );
    els.forEach((e) => io.observe(e));
    return () => io.disconnect();
  }, []);

  return (
    <div className="page">
      <nav className="nav">
        <a className="brand" href="#top" aria-label="Aegis home">
          <span className="brand-mark">🛡️</span>
          <span>Aegis</span>
        </a>
        <div className="nav-links">
          <a href="#tools">Tools</a>
          <a href="#coverage">Coverage</a>
          <a href="#how">How it works</a>
          <a href="#faq">FAQ</a>
          <a href={REPO} target="_blank" rel="noopener noreferrer">GitHub ↗</a>
          <ThemeToggle />
          <span className="live-pill" title="Live platform status">
            <span className={version ? "live-dot" : "live-dot off"}>●</span>
            {version ? ` Live · v${version}` : " Live demo"}
          </span>
        </div>
      </nav>

      <header className="hero" id="top">
        <p className="hero-badge">Free · Open source · MIT</p>
        <h1>Check it <span className="grad">before it hurts you.</span></h1>
        <p className="sub">
          One place for every check that matters: links, emails, messages, files, passwords,
          websites, domains and certificates — analysed live by an agent that shows its work
          and tells you exactly how to fix what it finds.
        </p>
        <form
          className="hero-scan"
          onSubmit={(e) => { e.preventDefault(); if (heroUrl.trim()) dispatchHeroScan(heroUrl.trim()); }}
        >
          <input
            ref={heroInputRef}
            value={heroUrl}
            onChange={(e) => setHeroUrl(e.target.value)}
            placeholder="Paste a suspicious link — https://…  ( press / )"
            aria-label="Link to check"
          />
          <button type="submit">Check it now</button>
        </form>
        <div className="hero-samples">
          <span>Try:</span>
          <button type="button" className="sample" onClick={() => { setHeroUrl(PHISH_SAMPLE); dispatchHeroScan(PHISH_SAMPLE); }}>a phishing link</button>
          <button type="button" className="sample" onClick={() => { setHeroUrl(SAFE_SAMPLE); dispatchHeroScan(SAFE_SAMPLE); }}>a safe link</button>
        </div>
        <div className="proof-strip" aria-label="Platform facts">
          {PROOF.map((p) => <span key={p} className="proof-chip">{p}</span>)}
        </div>
      </header>

      <section id="coverage" className="section reveal">
        <h2 className="section-title">What it covers</h2>
        <p className="section-sub">Nine tools, one platform — pick a threat and jump straight to its tool.</p>
        <div className="coverage-grid">
          {COVERAGE.map((c) => (
            <a key={c.threat} className="coverage-card" href={`#${c.anchor}`}>
              <span className="coverage-icon">{c.icon}</span>
              <strong>{c.threat}</strong>
              <span className="coverage-defense">{c.defense}</span>
              <span className="coverage-blurb">{c.blurb}</span>
              <span className="coverage-arrow">Open tool →</span>
            </a>
          ))}
        </div>
      </section>

      <section id="tools" className="section">
        <h2 className="section-title">The tools</h2>
        <p className="section-sub">No account needed. Every check runs live in front of you, and every finding comes with a suggested fix.</p>
        <div className="tool-nav" aria-label="Jump to a tool">
          {TOOL_NAV.map((t) => <a key={t.anchor} href={`#${t.anchor}`}>{t.label}</a>)}
        </div>
        <div className="tool-filter">
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter tools — try 'password', 'dns', 'scam'…"
            aria-label="Filter tools"
          />
          {filter.trim() && <span className="filter-count">{visibleTools.length} of {TOOLS.length} tools</span>}
        </div>
        <div className="grid">
          {visibleTools.map((t) => (
            <div key={t.id} className="tool-cell" id={t.id === "tool-vault" ? "tool-vault" : undefined}>{t.node}</div>
          ))}
          {visibleTools.length === 0 && <p className="meta">No tool matches “{filter}”. Try a shorter word — or clear the filter to see all nine.</p>}
        </div>
      </section>

      <section id="how" className="section reveal">
        <h2 className="section-title">How it works</h2>
        <p className="section-sub">The same flow for every tool — no black boxes.</p>
        <div className="steps">
          <div className="step-card">
            <span className="step-num">01</span>
            <strong>Paste, drop or type</strong>
            <p>A link, an email, a file, a password, a website — whatever reached you and made you pause.</p>
          </div>
          <div className="step-card">
            <span className="step-num">02</span>
            <strong>The agent analyses live</strong>
            <p>Each engine runs its stages in the open, streaming every signal it checks into the live console.</p>
          </div>
          <div className="step-card">
            <span className="step-num">03</span>
            <strong>Get a score + the fix</strong>
            <p>A plain-language verdict, the evidence behind it, and a suggested fix for every single finding.</p>
          </div>
        </div>
      </section>

      <section id="faq" className="section reveal">
        <h2 className="section-title">Questions</h2>
        <p className="section-sub">The things people ask before they trust a security tool.</p>
        <div className="faq-list">
          {FAQS.map((f) => (
            <details key={f.q} className="faq-item">
              <summary>{f.q}</summary>
              <p>{f.a}</p>
            </details>
          ))}
        </div>
      </section>

      <section className="oss-band reveal">
        <p>
          <strong>Open source, free forever.</strong> Aegis is MIT-licensed — read the code,
          fork it, self-host it, or improve it. Contributions are welcome.
        </p>
        <a className="btn ghost" href={REPO} target="_blank" rel="noopener noreferrer">Contribute on GitHub ↗</a>
      </section>

      <footer>
        <p>
          Built by <a href="https://manoj-2424150118.github.io" target="_blank" rel="noopener noreferrer">Manoj Kumar Sharma</a> — Cybersecurity &amp; Software Professional
        </p>
        <p className="foot-note">
          Aegis never executes uploaded files and never stores plaintext secrets; breach checks use k-anonymity.
          Heuristic scanning is a first line of defence — keep your OS, browser and antivirus updated too.
        </p>
      </footer>
    </div>
  );
}
