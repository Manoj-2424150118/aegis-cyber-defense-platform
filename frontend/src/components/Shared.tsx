import { useEffect, useRef, useState } from "react";
import type { Finding, LiveStepEvent, StreamHandlers } from "../api";
import { AlertIcon, CheckCircleIcon, CheckIcon, CopyIcon, DownloadIcon, EyeIcon, EyeOffIcon, InfoIcon, ShareIcon } from "./icons";

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

function VerdictIcon({ cls }: { cls: string }) {
  if (cls === "good") return <CheckCircleIcon size={15} />;
  if (cls === "info") return <InfoIcon size={15} />;
  return <AlertIcon size={15} />;
}

export function VerdictBadge({ score, verdict }: { score: number; verdict: string }) {
  const cls = verdictClass(score);
  return (
    <span className={`badge ${cls}`}>
      <VerdictIcon cls={cls} />
      {verdict} · {score}/100
    </span>
  );
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
  const filled = Math.max(0, Math.min(5, Math.round(score / 20)));
  return (
    <div className="meter-segs" role="img" aria-label={`strength ${score} of 100`}>
      {Array.from({ length: 5 }, (_, i) => (
        <span key={i} className={`seg-fill${i < filled ? ` on-${cls}` : ""}`} />
      ))}
    </div>
  );
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  return (
    <ul className="findings">
      {findings.map((f, i) => (
        <li key={i}>
          <div className="finding-main">
            <span className={`sev-dot ${f.points >= 25 ? "bad" : f.points > 0 ? "hit" : "ok"}`} aria-hidden="true" />
            <span>{f.message}</span>
            <span className="finding-points">{f.points > 0 ? `+${f.points}` : "clear"}</span>
          </div>
          {f.fix && (
            <p className="fix-line"><strong>Fix — </strong>{f.fix}</p>
          )}
        </li>
      ))}
    </ul>
  );
}

export function ErrorNote({ error }: { error: string }) {
  if (!error) return null;
  return (
    <p className="error" role="alert">
      <AlertIcon size={17} />
      <span>{error}</span>
    </p>
  );
}

export function Spinner() {
  return <span className="spinner" aria-hidden="true" />;
}

/** Copy-summary / share / copy-JSON actions offered under every
 * result, with a checked-at line (client clock, set when the result
 * renders). Share uses the Web Share API where available and falls
 * back to copying the summary. */
export function ResultActions({ title, summary, data }: { title: string; summary: string; data: unknown }) {
  const [copiedSummary, setCopiedSummary] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [shared, setShared] = useState(false);
  const [checkedAt] = useState(() => new Date());
  async function share() {
    try {
      if (navigator.share) {
        await navigator.share({ title: "Aegis check result", text: summary });
        return;
      }
      throw new Error("no native share");
    } catch {
      void copyText(summary, setShared);
    }
  }
  return (
    <>
      <p className="meta result-meta">
        <span>Checked at {checkedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
        <span>Source: this device · Aegis live check</span>
      </p>
      <div className="actions-row">
        <button type="button" className="copy" onClick={() => void copyText(summary, setCopiedSummary)}>
          <CopyIcon size={14} /> {copiedSummary ? "Copied" : `Copy ${title}`}
        </button>
        <button type="button" className="copy" onClick={() => void share()}>
          <ShareIcon size={14} /> {shared ? "Copied to share" : "Share"}
        </button>
        <button type="button" className="copy" onClick={() => void copyText(JSON.stringify(data, null, 2), setCopiedJson)}>
          <DownloadIcon size={14} /> {copiedJson ? "Copied" : "Copy as JSON"}
        </button>
      </div>
    </>
  );
}

export function summaryText(verdict: string, score: number, findings: Finding[]): string {
  const lines = findings.map((f) => `${f.points > 0 ? `+${f.points}` : "clear"} — ${f.message}`);
  return `Aegis result: ${verdict} (${score}/100)\n${lines.join("\n")}`;
}

/** Password field with a show/hide toggle. */
export function PasswordInput({
  value, onChange, placeholder, ariaLabel, autoComplete = "off", required,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  ariaLabel: string;
  autoComplete?: string;
  required?: boolean;
}) {
  const [shown, setShown] = useState(false);
  return (
    <div className="pw-wrap">
      <input
        type={shown ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={ariaLabel}
        autoComplete={autoComplete}
        required={required}
      />
      <button
        type="button"
        className="pw-toggle"
        onClick={() => setShown((s) => !s)}
        aria-label={shown ? "Hide password" : "Show password"}
        aria-pressed={shown}
      >
        {shown ? <EyeOffIcon size={18} /> : <EyeIcon size={18} />}
      </button>
    </div>
  );
}

/* ---------- Live scan timeline ---------- */

export interface LiveScanState<T> {
  steps: LiveStepEvent[];
  total: number;
  running: boolean;
  elapsedMs: number;
  run: (starter: (handlers: StreamHandlers) => Promise<T>) => Promise<T | null>;
  reset: () => void;
}

/** Drives a streamed analysis: collects step events as the server
 * executes each stage, tracks elapsed time for the timeline header. */
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

interface TimelineScanView {
  steps: LiveStepEvent[];
  total: number;
  running: boolean;
  elapsedMs: number;
}

/** The scan timeline: each completed stage with its findings, then —
 * while streaming — one active step. Announced politely to screen
 * readers via aria-live; technical values stay in mono. */
export function ScanTimeline({ scan, error }: { scan: TimelineScanView; error?: string }) {
  if (!scan.running && scan.steps.length === 0 && !error) return null;
  return (
    <div className="timeline" aria-live="polite" aria-label="Live analysis progress">
      <div className="timeline-head">
        <span className="timeline-title">Analysis</span>
        <span className="timeline-time">{(scan.elapsedMs / 1000).toFixed(1)}s</span>
      </div>
      <div>
        {scan.steps.map((s) => (
          <div className="t-step" key={s.index}>
            <span className="t-marker"><CheckIcon size={14} /></span>
            <div>
              <div className="t-step-main">
                <span className="t-step-num">{s.index}/{scan.total || "?"}</span>
                <span className="t-step-label">{s.label}</span>
                {typeof s.running_score === "number" && <span className="t-score">risk {s.running_score}</span>}
              </div>
              {s.findings.map((f) => (
                <div className="t-finding hit" key={f.code}>
                  <span className={`sev-dot ${f.points >= 25 ? "bad" : "hit"}`} aria-hidden="true" />
                  <span>{f.message}</span>
                  <span className="t-points">+{f.points}</span>
                </div>
              ))}
              {s.detail && <div className="t-detail">{detailText(s.detail)}</div>}
              {s.findings.length === 0 && !s.detail && (
                <div className="t-finding">
                  <span className="sev-dot ok" aria-hidden="true" />
                  <span>Clear — nothing found</span>
                </div>
              )}
            </div>
          </div>
        ))}
        {scan.running && (
          <div className="t-step" aria-hidden="true">
            <span className="t-marker active"><span className="t-pulse" /></span>
            <div className="t-step-main">
              <span className="t-step-label working">Working…</span>
            </div>
          </div>
        )}
        {error && (
          <div className="t-error" role="alert">
            <AlertIcon size={17} />
            <span>{error}</span>
          </div>
        )}
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
