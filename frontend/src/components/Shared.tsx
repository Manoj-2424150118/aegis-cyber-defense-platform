import type { Finding } from "../api";

export function verdictClass(score: number): string {
  if (score >= 70) return "bad";
  if (score >= 40) return "warn";
  if (score >= 20) return "low";
  return "good";
}

export function ScoreMeter({ score, invert = false }: { score: number; invert?: boolean }) {
  const shown = invert ? 100 - score : score;
  return (
    <div className="meter" aria-label={`score ${shown} of 100`}>
      <div className={`meter-fill ${verdictClass(invert ? score : 100 - score)}`} style={{ width: `${shown}%` }} />
    </div>
  );
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  return (
    <ul className="findings">
      {findings.map((f, i) => (
        <li key={i} className={f.points > 0 ? "finding-hit" : "finding-info"}>
          <span className="finding-points">{f.points > 0 ? `+${f.points}` : "✓"}</span>
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
