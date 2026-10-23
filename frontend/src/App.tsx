import { EmailAnalyzer, FileScanner, PasswordLab, UrlChecker, WebAudit } from "./components/Tools";
import { VaultPanel } from "./components/VaultPanel";

const COVERAGE = [
  { icon: "🎣", threat: "Phishing links", defense: "URL Analyser", anchor: "tool-url" },
  { icon: "🔓", threat: "Weak & breached passwords", defense: "Password Lab", anchor: "tool-password" },
  { icon: "🦠", threat: "Malware attachments", defense: "File Scanner", anchor: "tool-file" },
  { icon: "✉️", threat: "Phishing & CEO-fraud email", defense: "Email Analyser", anchor: "tool-email" },
  { icon: "🕵️", threat: "Unsafe websites", defense: "Website Audit", anchor: "tool-web" },
  { icon: "🗄️", threat: "Stolen secrets", defense: "Encrypted Vault", anchor: "tool-vault" },
] as const;

const REPO = "https://github.com/Manoj-2424150118/aegis-cyber-defense-platform";

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
          <a href={REPO} target="_blank" rel="noopener noreferrer">GitHub ↗</a>
          <span className="live-dot" title="Live demo">● Live</span>
        </div>
      </nav>

      <header className="hero" id="top">
        <p className="hero-badge">Free · Open source · MIT</p>
        <h1>Check it <span className="grad">before it hurts you.</span></h1>
        <p className="sub">
          Six tools that scan links, emails, files, passwords and websites for real threats —
          and tell you exactly how to fix what they find.
        </p>
        <div className="hero-cta">
          <a className="btn primary" href="#tools">Run the tools</a>
          <a className="btn ghost" href={REPO} target="_blank" rel="noopener noreferrer">View source</a>
        </div>
      </header>

      <section id="coverage" className="section">
        <h2 className="section-title">What it covers</h2>
        <p className="section-sub">Tap a row to jump to the tool.</p>
        <div className="coverage-list">
          {COVERAGE.map((c) => (
            <a key={c.threat} className="coverage-row" href={`#${c.anchor}`}>
              <span className="coverage-icon">{c.icon}</span>
              <strong>{c.threat}</strong>
              <span>{c.defense}</span>
            </a>
          ))}
        </div>
      </section>

      <section id="tools" className="section">
        <h2 className="section-title">The tools</h2>
        <p className="section-sub">No account needed. Every check runs live in front of you, and every finding comes with a suggested fix.</p>
        <div className="grid">
          <UrlChecker />
          <PasswordLab />
          <FileScanner />
          <EmailAnalyzer />
          <WebAudit />
          <div id="tool-vault"><VaultPanel /></div>
        </div>
      </section>

      <section className="oss-band">
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
