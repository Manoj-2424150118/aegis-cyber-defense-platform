import type { Finding } from "../api";

export function verdictClass(score: number): string {
  if (score >= 70) return "bad";
  if (score >= 40) return "warn";
  if (score >= 20) return "low";
  return "good";
}

export function VerdictBadge({ score, verdict }: { score: number; verdict: string }) {
  return <span className={`badge ${verdictClass(score)}`}>{verdict} · {score}/100</span>;
}

export function ScoreMeter({ score }: { score: number }) {
  // score = safety (0-100): render as a risk meter inverted for readability
  const risk = 100 - score;
  return (
    <div className="meter" role="img" aria-label={`risk ${risk} of 100`}>
      <div className={`meter-fill ${verdictClass(risk)}`} style={{ width: `${risk}%` }} />
    </div>
  );
}

export function StrengthMeter({ score }: { score: number }) {
  const cls = score >= 70 ? "good" : score >= 40 ? "warn" : "bad";
  return (
    <div className="meter" role="img" aria-label={`strength ${score} of 100`}>
      <div className={`meter-fill ${cls}`} style={{ width: `${score}%` }} />
    </div>
  );
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  return (
    <ul className="findings">
      {findings.map((f, i) => (
        <li key={i}>
          <span className={f.points > 0 ? "finding-points hit" : "finding-points ok"}>{f.points > 0 ? `+${f.points}` : "✓"}</span>
          <span>{f.message}</span>
        </li>
      ))}
    </ul>
  );
}

export function ErrorNote({ error }: { error: string }) {
  if (!error) return null;
  return <p className="error" role="alert">{error}</p>;
}

export function Spinner() {
  return <span className="spinner" aria-hidden="true" />;
}

export async function copyText(text: string, setDone: (v: boolean) => void) {
  try {
    await navigator.clipboard.writeText(text);
    setDone(true);
    setTimeout(() => setDone(false), 1600);
  } catch {
    setDone(false);
  }
}
