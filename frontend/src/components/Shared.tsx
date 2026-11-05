import { useEffect, useRef, useState } from "react";
import type { Finding, LiveStepEvent, StreamHandlers } from "../api";

/** The hero scan box dispatches this event; the URL checker listens
 * for it, adopts the value and runs — one search surface, like the
 * big single-purpose tool sites (paste once, land on the result). */
export const HERO_SCAN_EVENT = "aegis:hero-scan";

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
          <div className="finding-main">
            <span className={f.points > 0 ? "finding-points hit" : "finding-points ok"}>{f.points > 0 ? `+${f.points}` : "✓"}</span>
            <span>{f.message}</span>
          </div>
          {f.fix && (
            <p className="fix-line"><strong>Suggested fix — </strong>{f.fix}</p>
          )}
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

/* ---------- Live agent view ---------- */

export interface LiveScanState<T> {
  steps: LiveStepEvent[];
  total: number;
  running: boolean;
  elapsedMs: number;
  run: (starter: (handlers: StreamHandlers) => Promise<T>) => Promise<T | null>;
  reset: () => void;
}

/** Drives a streamed analysis: collects step events as the server
 * executes each stage, tracks elapsed time for the console header. */
export function useLiveScan<T>(): LiveScanState<T> {
  const [steps, setSteps] = useState<LiveStepEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [running, setRunning] = useState(false);
  const [elapsedMs, setElapsedMs] = useState(0);
  const startRef = useRef(0);

  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => setElapsedMs(Date.now() - startRef.current), 100);
    return () => clearInterval(id);
  }, [running]);

  async function run(starter: (handlers: StreamHandlers) => Promise<T>): Promise<T | null> {
    setSteps([]);
    setTotal(0);
    setElapsedMs(0);
    startRef.current = Date.now();
    setRunning(true);
    try {
      return await starter({
        onStart: (t) => setTotal(t),
        onStep: (s) => setSteps((prev) => [...prev, s]),
      });
    } finally {
      setElapsedMs(Date.now() - startRef.current);
      setRunning(false);
    }
  }

  function reset() {
    setSteps([]);
    setTotal(0);
    setElapsedMs(0);
  }

  return { steps, total, running, elapsedMs, run, reset };
}

function detailText(detail: Record<string, unknown>): string {
  return Object.entries(detail)
    .map(([k, v]) => `${k.replace(/_/g, " ")}: ${String(v)}`)
    .join(" · ");
}

interface ConsoleScanView {
  steps: LiveStepEvent[];
  total: number;
  running: boolean;
  elapsedMs: number;
}

export function LiveConsole({ scan, error }: { scan: ConsoleScanView; error?: string }) {
  const bodyRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    bodyRef.current?.scrollTo({ top: bodyRef.current.scrollHeight });
  }, [scan.steps, scan.running]);
  if (!scan.running && scan.steps.length === 0 && !error) return null;
  return (
    <div className="console" role="log" aria-live="polite" aria-label="Live analysis trace">
      <div className="console-head">
        <span className="cdot r" /><span className="cdot y" /><span className="cdot g" />
        <span className="console-title">AEGIS AGENT · LIVE ANALYSIS</span>
        <span className="console-time">{(scan.elapsedMs / 1000).toFixed(1)}s</span>
      </div>
      <div className="console-body" ref={bodyRef}>
        {scan.steps.map((s) => (
          <div className="cline" key={s.index}>
            <div className="cline-main">
              <span className="cstep">[{s.index}/{scan.total || "?"}]</span>
              <span className="cmark">✓</span>
              <span className="clabel">{s.label}</span>
              {typeof s.running_score === "number" && <span className="cscore">risk {s.running_score}</span>}
            </div>
            {s.findings.map((f) => (
              <div className="cfinding hit" key={f.code}>↳ +{f.points} — {f.message}</div>
            ))}
            {s.detail && <div className="cfinding info">↳ {detailText(s.detail)}</div>}
            {s.findings.length === 0 && !s.detail && <div className="cfinding ok">↳ clear — nothing found</div>}
          </div>
        ))}
        {scan.running && (
          <div className="cline working">
            <span className="cpulse">●</span> agent working<span className="cursor">▍</span>
          </div>
        )}
        {error && <div className="cline err">✕ {error}</div>}
      </div>
    </div>
  );
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
