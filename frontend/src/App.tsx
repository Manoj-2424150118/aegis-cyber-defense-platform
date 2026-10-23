import { EmailAnalyzer, FileScanner, PasswordLab, UrlChecker, WebAudit } from "./components/Tools";
import { VaultPanel } from "./components/VaultPanel";

const COVERAGE = [
  { icon: "🎣", threat: "Phishing links & fake login pages", defense: "URL Analyser — 14 weighted signals, typosquat & homograph detection", anchor: "tool-url" },
  { icon: "🔓", threat: "Weak, reused & breached passwords", defense: "Password Lab — entropy, crack-time, k-anonymity breach check", anchor: "tool-password" },
  { icon: "🦠", threat: "Malware & ransomware attachments", defense: "File Scanner — type-spoofing, droppers, macros, zip bombs", anchor: "tool-file" },
  { icon: "✉️", threat: "Phishing & CEO-fraud (BEC) email", defense: "Email Analyser — SPF/DKIM/DMARC, spoofing & pressure tactics", anchor: "tool-email" },
  { icon: "🕵️", threat: "Unsafe websites & man-in-the-middle", defense: "Website Audit — TLS, HSTS, CSP & cookie grading (SSRF-guarded)", anchor: "tool-web" },
  { icon: "🗄️", threat: "Theft of your stored secrets", defense: "Encrypted Vault — AES-256-GCM, Argon2id key derivation", anchor: "tool-vault" },
] as const;

const CONTROLS = [
  "Argon2id password hashing", "Account lockout + rate limiting", "SSRF protection",
  "Upload size caps (chunked)", "Strict CSP & security headers", "JWT with short expiry",
  "Timing-safe auth errors", "Request IDs & audit logging", "Bandit + CodeQL in CI",
  "Dependabot", "Non-root Docker", "Generic error responses",
] as const;

export default function App() {
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
          <a href="#security">Security</a>
          <a href="https://github.com/Manoj-2424150118/aegis-cyber-defense-platform" target="_blank" rel="noopener noreferrer">GitHub ↗</a>
          <span className="live-dot" title="Live demo">● Live</span>
        </div>
      </nav>

      <header className="hero" id="top">
        <p className="hero-badge">Production-grade · Open source · Defence-in-depth</p>
        <h1>Personal cyber defense,<br />engineered like a product.</h1>
        <p className="sub">
          Six security tools that protect an individual user from the attacks that actually
          compromise people — phishing, malicious files, breached passwords and unsafe
          websites — each verdict explained in plain language, never a black box.
        </p>
        <div className="hero-cta">
          <a className="btn primary" href="#tools">Run the tools</a>
          <a className="btn ghost" href="https://github.com/Manoj-2424150118/aegis-cyber-defense-platform" target="_blank" rel="noopener noreferrer">Review the code</a>
        </div>
        <div className="stats">
          <div><strong>6</strong><span>detection modules</span></div>
          <div><strong>50+</strong><span>automated tests</span></div>
          <div><strong>100%</strong><span>findings explained</span></div>
          <div><strong>AES-256</strong><span>vault encryption</span></div>
        </div>
      </header>

      <section id="coverage" className="section">
        <h2 className="section-title">Threat coverage</h2>
        <p className="section-sub">Mapped the way a security analyst thinks: attack first, control second.</p>
        <div className="coverage-grid">
          {COVERAGE.map((c) => (
            <a key={c.threat} className="coverage-card" href={`#${c.anchor}`}>
              <span className="coverage-icon">{c.icon}</span>
              <strong>{c.threat}</strong>
              <span>{c.defense}</span>
            </a>
          ))}
        </div>
      </section>

      <section id="tools" className="section">
        <h2 className="section-title">The tools</h2>
        <p className="section-sub">No account needed for checks. Try the built-in samples — including a live phishing example.</p>
        <div className="grid">
          <UrlChecker />
          <PasswordLab />
          <FileScanner />
          <EmailAnalyzer />
          <WebAudit />
          <div id="tool-vault"><VaultPanel /></div>
        </div>
      </section>

      <section id="security" className="section">
        <h2 className="section-title">Secured like it preaches</h2>
        <p className="section-sub">
          Aegis audits other people's security — so its own is held to the same standard,
          tested in an isolated sandbox before every deployment.
        </p>
        <div className="controls">
          {CONTROLS.map((c) => <span key={c} className="control-chip">✓ {c}</span>)}
        </div>
      </section>

      <footer>
        <p>
          Built by <a href="https://manoj-2424150118.github.io" target="_blank" rel="noopener noreferrer">Manoj Kumar Sharma</a> —
          Cybersecurity &amp; Software Professional · FastAPI · React · TypeScript · Docker
        </p>
        <p className="foot-note">
          Aegis never executes uploaded files, never stores plaintext secrets, and breach-checks passwords
          with k-anonymity. Static analysis is a first line of defence — keep your OS, browser and antivirus updated too.
        </p>
      </footer>
    </div>
  );
}
