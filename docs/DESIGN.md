# Aegis design system — "Quiet Authority" (v1.9)

The interface is an editorial security journal crossed with a precision
instrument: warm neutrals, hairline structure, one jade accent, and
typography doing the heavy lifting. No neon, no glow, no glassmorphism,
no emoji icons, no gradient text.

## Tokens

All tokens live as CSS custom properties in `frontend/src/styles.css`
(`:root` = dark, `:root[data-theme="light"]` = light). Highlights:

- Surfaces: `--bg` → `--bg-elev-1/2/3` (layered, never pure black/white).
  Dark page `#0A0C0B` (warm ink); light page `#F6F4EF` (warm paper).
- One accent: jade `--accent` (`#2FB37F` dark / `#0E7A57` light), used
  for action and emphasis only. `--highlight` (parchment) is reserved
  for eyebrows and editorial numerals. Semantic colours (`--good`,
  `--warn`, `--danger`, `--info`) appear only with an icon and a word.
- Hairline borders are decorative structure (1px `--line`); form
  controls use `--line-strong`, and the focus ring (`--focus`, 2px +
  offset) carries the interactive-state contrast requirement.
- Radius scale: 6 / 10 / 16 / full. Spacing scale: 4–128px. Motion:
  `--ease-out` cubic-bezier(.16,1,.3,1) at 120/200/320ms; no loops
  except the active-step pulse and the spinner (both honour
  `prefers-reduced-motion`).

## Typography

Self-hosted WOFF2 (latin subsets, `font-display: swap`, sans 400/600
preloaded), served from `/assets/fonts/` — zero third-party requests:

- **Geist Sans** (SIL OFL) — UI and body; weights 400/500/600/700.
- **Geist Mono** (SIL OFL) — data, hashes, meta; tabular numbers with
  slashed zero.
- **Instrument Serif** (SIL OFL) — editorial accent only: the hero
  eyebrow (italic) and the "How it works" numerals.

Font files were harvested from the Fontsource npm packages at build
time; the packages are not runtime dependencies.

## Components

- `frontend/src/components/icons.tsx` — inline SVG icon set (24 grid,
  1.5 stroke, `currentColor`), including the `LogoMark` shield/A
  monogram (also `public/assets/favicon.svg`).
- Results system (`Shared.tsx`): `VerdictBadge` (dot + icon + word +
  score), `ScoreMeter`, segmented `StrengthMeter`, `FindingsList`
  (severity dot + points + inline "Fix —"), `ResultActions` (copy
  summary / copy as JSON), `PasswordInput` (show/hide toggle).
- `ScanTimeline` replaces the old terminal console: completed stages
  with check markers and per-stage findings, one active pulsing step
  while streaming, `aria-live="polite"`.
- Hero: asymmetric two-column with a command bar (Ctrl-K / "/" focuses
  it) and a **real** sample result panel rendered by the same result
  components (the known phishing-pattern sample, checked live).

## Accessibility (WCAG 2.2 AA)

- Token contrast verified programmatically: every text/background pair
  in both themes ≥ 4.5:1 (light `--text-3` and `--warn` were darkened
  from the first-pass values to pass: 5.39 and 5.28 respectively).
- Visible focus everywhere, skip link, landmarks, ordered headings,
  labelled fields (`aria-labelledby` + visible labels), 44px targets,
  status never carried by colour alone.
- `prefers-reduced-motion`, `forced-colors`, and a print stylesheet
  are covered in the CSS.

## Performance notes

- CSS 29.7 KB (6.1 KB gzip), JS 285 KB (85 KB gzip); fonts total
  216 KB across 8 subset files, loaded on demand by weight.
- No `backdrop-filter` on large surfaces (nav uses a small blur over a
  mostly-opaque tint); no animation libraries; CSS-driven motion.
- Dynamic meter/bar widths are set via React style props (CSSOM),
  which the strict `style-src 'self'` CSP permits; there is no inline
  `<script>` or `<style>` in the page, and the theme bootstrap remains
  the external `/assets/theme-init.js`.

## Decisions worth knowing

- The hero command bar keeps a `<textarea>` (single visible row) rather
  than an `<input>`: Smart Scan accepts whole emails and messages, and
  pasting multi-line text into a one-line input silently truncates it.
  Enter submits; Shift-Enter adds a line.
- The "Coverage" cards remain as a navigation layer above the tool
  grid. The tool grid itself is a uniform 1/2/3-column grid, but rows
  use `align-items: start`: when one tool's result makes its card grow,
  its neighbours keep their natural height instead of stretching into
  mostly-empty boxes — the owner's standing layout preference, confirmed
  in QA when equal-height stretching left large blank panels. Coverage
  cards (uniform content) do stretch to equal height.
- Light-theme `--line` hairlines sit below 3:1 by design (decorative
  separation, not component identification); controls and focus states
  meet the UI contrast requirements.
