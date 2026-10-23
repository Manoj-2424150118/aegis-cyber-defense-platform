import { EmailAnalyzer, FileScanner, PasswordLab, UrlChecker, WebAudit } from "./components/Tools";
import { VaultPanel } from "./components/VaultPanel";

const THREATS = [
  ["🎣 Phishing links", "URL Analyser"],
  ["✉️ BEC & phishing email", "Email Analyser"],
  ["🦠 Malware attachments", "File Scanner"],
  ["🔓 Weak / breached passwords", "Password Lab"],
  ["🗄️ Stolen secrets", "AES-256-GCM Vault"],
  ["🕵️ Unsafe websites & MITM", "Website Audit"],
] as const;

export default function App() {
  return (
    <main>
      <header className="hero">
        <h1>🛡️ Aegis</h1>
        <p className="tagline">Personal Cyber Defense Platform</p>
        <p className="sub">
          One place to check the link, email, file, password or website in front of you —
          before an attacker uses it against you. Built with a production-grade
          FastAPI + React stack and defence-in-depth throughout.
        </p>
        <div className="threat-grid">
          {THREATS.map(([threat, module]) => (
            <div key={threat} className="threat-chip">
              <strong>{threat}</strong>
              <span>{module}</span>
            </div>
          ))}
        </div>
      </header>
      <div className="grid">
        <UrlChecker />
        <PasswordLab />
        <FileScanner />
        <EmailAnalyzer />
        <WebAudit />
        <VaultPanel />
      </div>
      <footer>
        <p>
          Aegis never executes uploaded files, never stores plaintext secrets, and breach-checks
          passwords with k-anonymity. Static analysis is a first line of defence — keep your OS,
          browser and antivirus updated too.
        </p>
      </footer>
    </main>
  );
}
