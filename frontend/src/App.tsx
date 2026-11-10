import { useEffect, useRef, useState } from "react";
import { api, type SmartScanResult, type Trending } from "./api";
import { DomainChecker, EmailAnalyzer, FileScanner, MessageChecker, PasswordLab, SecretScanner, TlsInspector, UrlChecker, WebAudit } from "./components/Tools";
import { VaultPanel } from "./components/VaultPanel";
import { ErrorNote, FindingsList, ResultActions, ScoreMeter, summaryText, VerdictBadge } from "./components/Shared";
import {
  ArrowRightIcon, ArrowUpRightIcon, CheckIcon, ChevronDownIcon, FileSearchIcon, GlobeIcon,
  InfoIcon, KeyIcon, LinkIcon, LockIcon, LogoMark, MailIcon, MenuIcon, MessageIcon,
  MonitorIcon, MoonIcon, SearchIcon, ServerIcon, ShieldCheckIcon, SunIcon, XIcon,
  EyeOffIcon,
} from "./components/icons";

const REPO = "https://github.com/Manoj-2424150118/aegis-cyber-defense-platform";

const COVERAGE = [
  { icon: <LinkIcon size={20} />, threat: "Phishing links", defense: "Link Checker", anchor: "tool-url", blurb: "Scores any link for typosquats, IP hosts, shorteners and credential-harvest signals." },
  { icon: <KeyIcon size={20} />, threat: "Weak & breached passwords", defense: "Password Lab", anchor: "tool-password", blurb: "Strength, crack-time and breach exposure — checked with k-anonymity, never in plain text." },
  { icon: <FileSearchIcon size={20} />, threat: "Malware attachments", defense: "File Scanner", anchor: "tool-file", blurb: "Static triage of suspicious files in memory. Never executed, never stored." },
  { icon: <MailIcon size={20} />, threat: "Phishing & CEO-fraud email", defense: "Email Analyser", anchor: "tool-email", blurb: "SPF, DKIM and DMARC, spoofing and social-engineering language, signal by signal." },
  { icon: <MessageIcon size={20} />, threat: "Scam SMS & WhatsApp messages", defense: "Message Checker", anchor: "tool-message", blurb: "Digital-arrest, KYC, UPI and task-scam patterns — plus every link inside the message, scored." },
  { icon: <GlobeIcon size={20} />, threat: "Unsafe websites", defense: "Website Audit", anchor: "tool-web", blurb: "Grades HTTPS, security headers and cookie flags — and shows the owner how to fix them." },
  { icon: <ServerIcon size={20} />, threat: "Spoofable domains", defense: "Domain Checker", anchor: "tool-domain", blurb: "Can anyone send email as this domain? SPF, DMARC, CAA and DNS health, graded from live records." },
  { icon: <LockIcon size={20} />, threat: "Bad TLS certificates", defense: "TLS Inspector", anchor: "tool-tls", blurb: "Issuer, expiry runway, hostname coverage and protocol version — from a real handshake." },
  { icon: <EyeOffIcon size={20} />, threat: "Leaked secrets & keys", defense: "Secret Scanner", anchor: "tool-secret", blurb: "Finds exposed API keys, tokens and passwords in pasted configs and code — masked, never stored." },
] as const;

const TOOL_NAV = [
  { label: "Link Checker", anchor: "tool-url" },
  { label: "Password Lab", anchor: "tool-password" },
  { label: "File Scanner", anchor: "tool-file" },
  { label: "Email Analyser", anchor: "tool-email" },
  { label: "Message Checker", anchor: "tool-message" },
  { label: "Website Audit", anchor: "tool-web" },
  { label: "Domain Checker", anchor: "tool-domain" },
  { label: "TLS Inspector", anchor: "tool-tls" },
  { label: "Secret Scanner", anchor: "tool-secret" },
  { label: "Vault", anchor: "tool-vault" },
] as const;

const TRUST = ["No sign-up", "Nothing stored", "Ten tools, one place", "Every result explained"] as const;

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
    const t = setInterval(() => setTick((x) => x + 1), 60_000);
    return () => clearInterval(t);
  }, [mode]);
  const options: { value: ThemeMode; label: string; icon: React.ReactNode }[] = [
    { value: "auto", label: "Auto", icon: <MonitorIcon size={14} /> },
    { value: "light", label: "Light", icon: <SunIcon size={14} /> },
    { value: "dark", label: "Dark", icon: <MoonIcon size={14} /> },
  ];
  return (
    <div className="seg" role="group" aria-label="Theme">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={mode === o.value}
          onClick={() => setMode(o.value)}
          title={o.value === "auto" ? "Auto follows day and night (light 7am–7pm)" : `${o.label} theme`}
        >
          {o.icon}
          <span className="seg-label">{o.label}</span>
        </button>
      ))}
    </div>
  );
}

const FAQS = [
  {
    q: "Is Aegis really free?",
    a: "Yes — free and open source under the MIT licence. No account is needed for any check; an account only unlocks the encrypted vault.",
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

const PHISH_SAMPLE = "http://192.168.10.5/paypal/login/verify";
const SAFE_SAMPLE = "https://www.google.com";
const MSG_SAMPLE = "Dear customer, your bank account will be blocked today. Update your KYC immediately at http://secure-bank-verify.xyz/login to avoid closure.";

/* A real result, produced by the live Link Checker for the sample
 * phishing link — rendered with the same components as live results. */
const PANEL_FINDINGS = [
  { points: 35, code: "ip-host", message: "Host is a raw IP address — a classic phishing / malware-delivery pattern." },
  { points: 20, code: "brand-in-path", message: "Page path name-drops paypal on an unrelated domain." },
  { points: 15, code: "no-https", message: "No HTTPS — traffic (and any password typed here) is not encrypted." },
  { points: 15, code: "phish-keywords", message: "Credential / urgency keywords in the URL: login, verify." },
];

function ProductPanel() {
  return (
    <div className="hero-panel" aria-label="Sample scan result">
      <div className="panel-head">
        <span className="panel-title">Sample result · Link Checker</span>
        <VerdictBadge score={85} verdict="malicious" />
      </div>
      <p className="panel-url">{PHISH_SAMPLE}</p>
      <ScoreMeter score={15} />
      <FindingsList findings={PANEL_FINDINGS} />
      <p className="panel-note">
        <InfoIcon size={15} />
        <span>A real result for a known phishing pattern, checked by this platform. Paste your own link on the left and get the same breakdown.</span>
      </p>
    </div>
  );
}

function RankList({ items, mono = false }: { items: { name: string; count: number }[]; mono?: boolean }) {
  const max = Math.max(...items.map((i) => i.count), 1);
  return (
    <ol className="rank-list">
      {items.map((i) => (
        <li key={i.name} className="rank-row">
          <div className="rank-line">
            <span className="rank-name">{mono ? <code>{i.name}</code> : i.name}</span>
            <span className="rank-count">{i.count}</span>
          </div>
          <div className="rank-bar" aria-hidden="true">
            <div className="rank-bar-fill" style={{ width: `${Math.round((i.count / max) * 100)}%` }} />
          </div>
        </li>
      ))}
    </ol>
  );
}

function TrendingSection() {
  const [data, setData] = useState<Trending | null>(null);
  useEffect(() => {
    let live = true;
    api.getTrending().then((d) => { if (live) setData(d); }).catch(() => { /* trends are a bonus, never block the page */ });
    return () => { live = false; };
  }, []);
  if (!data) return null;
  return (
    <section id="trending" className="section">
      <p className="eyebrow">Trending threats</p>
      <h2 className="section-title">What people are checking</h2>
      <p className="section-sub">Live aggregates from this platform's own scans over the last {data.window_days} days. Only verdicts, impersonated brand names and repeat flagged domains are counted; submitted links, emails and messages are never stored or shown.</p>
      {data.total_scans === 0 ? (
        <p className="meta">No scans recorded yet in this window. Run any check above and it will be counted here — in aggregate only.</p>
      ) : (
        <>
          <div className="trend-stats">
            <div className="trend-stat"><strong>{data.total_scans.toLocaleString()}</strong><span>checks run</span></div>
            <div className="trend-stat"><strong>{data.flagged_pct}%</strong><span>flagged risky</span></div>
            <div className="trend-stat"><strong>{data.scans_last_7_days.toLocaleString()}</strong><span>checks this week</span></div>
          </div>
          <div className="trend-cols">
            {data.top_patterns.length > 0 && (
              <div className="trend-card"><h3>Most-seen scam patterns</h3>
                <RankList items={data.top_patterns.map((p) => ({ name: p.label, count: p.count }))} />
              </div>
            )}
            {data.top_impersonated_brands.length > 0 && (
              <div className="trend-card"><h3>Most-impersonated brands</h3>
                <RankList items={data.top_impersonated_brands.map((b) => ({ name: b.name, count: b.count }))} />
              </div>
            )}
            {data.top_flagged_domains.length > 0 && (
              <div className="trend-card"><h3>Repeat flagged domains</h3>
                <RankList items={data.top_flagged_domains.map((d) => ({ name: d.domain, count: d.count }))} mono />
              </div>
            )}
          </div>
        </>
      )}
    </section>
  );
}

export default function App() {
  const [heroText, setHeroText] = useState("");
  const [smart, setSmart] = useState<SmartScanResult | null>(null);
  const [smartBusy, setSmartBusy] = useState(false);
  const [smartError, setSmartError] = useState("");
  const [version, setVersion] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [navOpen, setNavOpen] = useState(false);
  const heroInputRef = useRef<HTMLTextAreaElement>(null);

  const focusHero = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
    heroInputRef.current?.focus();
  };

  const runSmartScan = async (text: string) => {
    const value = text.trim();
    if (!value || smartBusy) return;
    setSmartBusy(true);
    setSmartError("");
    setSmart(null);
    try {
      setSmart(await api.smartScan(value));
    } catch (e) {
      setSmartError(e instanceof Error ? e.message : "The check failed. Please try again.");
    } finally {
      setSmartBusy(false);
    }
  };

  // ⌘K / Ctrl-K or "/" from anywhere jumps to the scan box.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (document.activeElement?.tagName ?? "").toUpperCase();
      const inField = tag === "INPUT" || tag === "TEXTAREA";
      if (((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") || (e.key === "/" && !inField)) {
        e.preventDefault();
        focusHero();
      }
      if (e.key === "Escape") setNavOpen(false);
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
    { id: "tool-secret", name: "Secret Scanner", kw: "secret api key token leak env config credentials exposed password", node: <SecretScanner /> },
    { id: "tool-vault", name: "Encrypted Vault", kw: "vault secrets password manager encryption storage", node: <VaultPanel /> },
  ];
  const visibleTools = TOOLS.filter((t) => `${t.name} ${t.kw}`.toLowerCase().includes(filter.trim().toLowerCase()));

  // Live platform status — real data from /health, shown in nav + footer.
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

  const NAV_LINKS = [
    { label: "Tools", href: "#tools" },
    { label: "Coverage", href: "#coverage" },
    { label: "Trending", href: "#trending" },
    { label: "How it works", href: "#how" },
    { label: "Privacy", href: "#privacy" },
    { label: "FAQ", href: "#faq" },
  ];

  return (
    <div>
      <a className="skip-link" href="#tools">Skip to the tools</a>
      <nav className="nav" aria-label="Main">
        <div className="nav-inner">
          <a className="brand" href="#top" aria-label="Aegis home">
            <LogoMark size={27} className="logo-mark" />
            <span>Aegis</span>
          </a>
          <div className="nav-links">
            {NAV_LINKS.map((l) => <a key={l.href} href={l.href}>{l.label}</a>)}
          </div>
          <div className="nav-right">
            <span className="live-pill" title="Live platform status">
              <span className={version ? "live-dot" : "live-dot off"} aria-hidden="true" />
              {version ? `Live · v${version}` : "Checking status…"}
            </span>
            <ThemeToggle />
            <a className="btn ghost" href="#tool-vault" style={{ minHeight: 40, padding: "0 16px" }}>Sign in</a>
            <button type="button" className="btn primary" style={{ minHeight: 40, padding: "0 16px", border: 0 }} onClick={focusHero}>Run a free scan</button>
            <button
              type="button"
              className="icon-btn nav-toggle"
              aria-expanded={navOpen}
              aria-label={navOpen ? "Close menu" : "Open menu"}
              onClick={() => setNavOpen((o) => !o)}
            >
              {navOpen ? <XIcon size={20} /> : <MenuIcon size={20} />}
            </button>
          </div>
        </div>
        <div className={`nav-sheet${navOpen ? " open" : ""}`}>
          {NAV_LINKS.map((l) => <a key={l.href} href={l.href} onClick={() => setNavOpen(false)}>{l.label}</a>)}
          <a href="#tool-vault" onClick={() => setNavOpen(false)}>Sign in to the vault</a>
        </div>
      </nav>

      <div className="page">
        <header className="hero" id="top">
          <div>
            <p className="hero-eyebrow">Personal cyber defense, without the noise.</p>
            <h1>Check it first. <span className="quiet">Open it safely.</span></h1>
            <p className="sub">
              Ten free checks for the links, emails, messages, files, passwords and pasted configs that reach
              you every day — each one explained, signal by signal.
            </p>
            <form
              className="command-bar"
              onSubmit={(e) => { e.preventDefault(); void runSmartScan(heroText); }}
            >
              <span className="cb-icon"><SearchIcon size={19} /></span>
              <textarea
                ref={heroInputRef}
                value={heroText}
                onChange={(e) => setHeroText(e.target.value)}
                placeholder="Paste a link, email, or message…"
                aria-label="Link, email or message to check"
                rows={1}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    void runSmartScan(heroText);
                  }
                }}
              />
              <span className="kbd" aria-hidden="true">Ctrl K</span>
              <button type="submit" disabled={smartBusy}>{smartBusy ? "Checking…" : "Check"}</button>
            </form>
            <div className="hero-samples">
              <span>Try:</span>
              <button type="button" className="sample" onClick={() => { setHeroText(PHISH_SAMPLE); void runSmartScan(PHISH_SAMPLE); }}>a phishing link</button>
              <button type="button" className="sample" onClick={() => { setHeroText(SAFE_SAMPLE); void runSmartScan(SAFE_SAMPLE); }}>a safe link</button>
              <button type="button" className="sample" onClick={() => { setHeroText(MSG_SAMPLE); void runSmartScan(MSG_SAMPLE); }}>a scam message</button>
            </div>
            {smartError && <ErrorNote error={smartError} />}
            {smart && (
              <div className="result smart-result" aria-live="polite">
                <div className="result-head">
                  <span>Detected {smart.detected_label} · checked with the {smart.tool}</span>
                  <VerdictBadge score={smart.risk_score} verdict={smart.verdict} />
                </div>
                <ScoreMeter score={100 - smart.risk_score} />
                <FindingsList findings={smart.result.findings} />
                {smart.result.cleaned_url && (
                  <p className="smart-note">Tracking-free version of your link: <code>{smart.result.cleaned_url}</code></p>
                )}
                {smart.detected_type !== "url" && (smart.result.links_found?.length ?? 0) > 0 && (
                  <p className="smart-note">Links found inside: {smart.result.links_found?.join(", ")}</p>
                )}
                <ResultActions title="summary" summary={summaryText(smart.verdict, smart.risk_score, smart.result.findings)} data={smart} />
              </div>
            )}
            <div className="trust-strip" aria-label="Platform facts">
              {TRUST.map((p) => (
                <span key={p} className="trust-chip"><CheckIcon size={14} />{p}</span>
              ))}
            </div>
          </div>
          <ProductPanel />
        </header>

        <main>
          <section id="coverage" className="section reveal">
            <p className="eyebrow">Coverage</p>
            <h2 className="section-title">What it covers</h2>
            <p className="section-sub">Ten tools, one platform. Pick a threat and jump straight to its tool.</p>
            <div className="cover-grid">
              {COVERAGE.map((c) => (
                <a key={c.threat} className="cover-card" href={`#${c.anchor}`}>
                  <span className="tile">{c.icon}</span>
                  <strong>{c.threat}</strong>
                  <span className="cover-defense">{c.defense}</span>
                  <span className="cover-blurb">{c.blurb}</span>
                  <span className="cover-arrow">Open tool <ArrowRightIcon size={16} /></span>
                </a>
              ))}
            </div>
          </section>

          <section id="tools" className="section">
            <p className="eyebrow">The tools</p>
            <h2 className="section-title">Run a check</h2>
            <p className="section-sub">No account needed. Every check runs live in front of you, and every finding comes with a suggested fix.</p>
            <div className="tool-nav" aria-label="Jump to a tool">
              {TOOL_NAV.map((t) => <a key={t.anchor} href={`#${t.anchor}`}>{t.label}</a>)}
            </div>
            <div className="tool-filter">
              <div className="field">
                <span id="filter-label">Filter tools</span>
                <input
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder="Try 'password', 'dns', 'scam'…"
                  aria-labelledby="filter-label"
                />
              </div>
              {filter.trim() && <span className="filter-count">{visibleTools.length} of {TOOLS.length} tools</span>}
            </div>
            <div className="grid">
              {visibleTools.map((t) => (
                <div key={t.id} className="tool-cell">{t.node}</div>
              ))}
              {visibleTools.length === 0 && <p className="meta">No tool matches “{filter}”. Try a shorter word — or clear the filter to see all ten.</p>}
            </div>
          </section>

          <TrendingSection />

          <section id="how" className="section reveal">
            <p className="eyebrow">How it works</p>
            <h2 className="section-title">The same flow, every tool</h2>
            <p className="section-sub">No black boxes. You see each stage as it runs.</p>
            <div className="steps">
              <div className="step-card">
                <span className="step-num">One</span>
                <strong>Paste, drop or type</strong>
                <p>A link, an email, a file, a password, a website — whatever reached you and made you pause.</p>
              </div>
              <div className="step-card">
                <span className="step-num">Two</span>
                <strong>The check runs live</strong>
                <p>Each engine runs its stages in the open, streaming every signal it checks into the timeline.</p>
              </div>
              <div className="step-card">
                <span className="step-num">Three</span>
                <strong>Get a verdict and the fix</strong>
                <p>A plain-language verdict, the evidence behind it, and a suggested fix for every finding.</p>
              </div>
            </div>
          </section>

          <section id="privacy" className="section reveal">
            <p className="eyebrow">Privacy &amp; data</p>
            <h2 className="section-title">What happens to what you paste</h2>
            <p className="section-sub">A security tool should be able to answer this in plain language.</p>
            <div className="privacy-grid">
              <div className="privacy-item">
                <FileSearchIcon size={20} />
                <div>
                  <strong>Files are never stored</strong>
                  <p>Uploads are analysed in memory and discarded when the scan ends. They are never executed and never written to disk.</p>
                </div>
              </div>
              <div className="privacy-item">
                <KeyIcon size={20} />
                <div>
                  <strong>Passwords stay private</strong>
                  <p>The breach check uses k-anonymity — only 5 characters of a hash leave your browser. Vault items are AES-256-GCM ciphertext; the key never reaches the server.</p>
                </div>
              </div>
              <div className="privacy-item">
                <ServerIcon size={20} />
                <div>
                  <strong>Trends are aggregates only</strong>
                  <p>The public trends view counts verdicts, impersonated brands and repeat flagged domains. Submitted links, emails, messages and addresses are never stored or shown.</p>
                </div>
              </div>
              <div className="privacy-item">
                <ShieldCheckIcon size={20} />
                <div>
                  <strong>Open methodology</strong>
                  <p>Every engine is open source, and each finding names its signal and weight. Read the <a href={`${REPO}/blob/main/SECURITY.md`} target="_blank" rel="noopener noreferrer">security policy</a> or verify the code on <a href={REPO} target="_blank" rel="noopener noreferrer">GitHub</a>.</p>
                </div>
              </div>
            </div>
          </section>

          <section id="faq" className="section reveal">
            <p className="eyebrow">FAQ</p>
            <h2 className="section-title">Questions</h2>
            <p className="section-sub">The things people ask before they trust a security tool.</p>
            <div className="faq-list">
              {FAQS.map((f) => (
                <details key={f.q} className="faq-item">
                  <summary>{f.q}<ChevronDownIcon size={18} className="faqchev" /></summary>
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
            <a className="btn ghost" href={REPO} target="_blank" rel="noopener noreferrer">Contribute on GitHub <ArrowUpRightIcon size={16} /></a>
          </section>
        </main>

        <footer>
          <div className="footer-grid">
            <div className="footer-brand">
              <a className="brand" href="#top" aria-label="Aegis home">
                <LogoMark size={26} className="logo-mark" />
                <span>Aegis</span>
              </a>
              <p>Personal cyber defense for the links, emails, messages and files that reach you every day.</p>
            </div>
            <div className="footer-col">
              <h3>Tools</h3>
              <ul>
                {TOOL_NAV.slice(0, 5).map((t) => <li key={t.anchor}><a href={`#${t.anchor}`}>{t.label}</a></li>)}
              </ul>
            </div>
            <div className="footer-col">
              <h3>More tools</h3>
              <ul>
                {TOOL_NAV.slice(5).map((t) => <li key={t.anchor}><a href={`#${t.anchor}`}>{t.label}</a></li>)}
                <li><a href="#trending">Trending threats</a></li>
                <li><a href="#coverage">Coverage</a></li>
              </ul>
            </div>
            <div className="footer-col">
              <h3>Resources</h3>
              <ul>
                <li><a href={REPO} target="_blank" rel="noopener noreferrer">GitHub repository</a></li>
                <li><a href={`${REPO}/blob/main/SECURITY.md`} target="_blank" rel="noopener noreferrer">Security policy</a></li>
                <li><a href="/.well-known/security.txt">security.txt</a></li>
                <li><a href="#privacy">Privacy &amp; data</a></li>
                <li><a href="#faq">FAQ</a></li>
              </ul>
            </div>
          </div>
          <div className="footer-bottom">
            <span>© {new Date().getFullYear()} Aegis — built by <a href="https://manoj-2424150118.github.io" target="_blank" rel="noopener noreferrer">Manoj Kumar Sharma</a>. Heuristic checks are a first line of defence, not a guarantee.</span>
            <span className="status-line">
              <span className={version ? "live-dot" : "live-dot off"} aria-hidden="true" />
              {version ? `All systems normal · v${version}` : "Status unknown"}
            </span>
          </div>
        </footer>
      </div>
    </div>
  );
}
