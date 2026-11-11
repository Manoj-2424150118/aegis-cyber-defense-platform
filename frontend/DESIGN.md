# Aegis design system — "Quiet Authority"

Rationale, tokens and QA notes for the premium UI/UX overhaul
(branch `feat/uiux-track`, baseline v2.0.0 `48d301e`). The baseline
already carried the v1.9 Quiet Authority system; this pass audited it
against the overhaul spec gate by gate and fixed what failed.

## Art direction

Editorial security journal × precision instrument. Depth comes from
layered warm-neutral surfaces and 1px hairlines — never glow, never
glass. One jade accent for action; semantic colours for status only,
always paired with an icon and a word. Geist (sans) for UI, Instrument
Serif italic for editorial accents only, Geist Mono for data. All
fonts self-hosted WOFF2 (SIL OFL), `font-display: swap`, sans 400/600
preloaded.

## Tokens

Tokens live in the `:root` blocks of `src/styles.css` (dark default,
`[data-theme="light"]` overrides) — the spec's `:root` option.
Spacing 4–128px scale, radii 6/10/16/999, motion
`cubic-bezier(.16,1,.3,1)` at 120/200/320ms.

### Contrast (measured, WCAG ratio script over the token pairs)

Every text pair passes 4.5:1 in both themes, with two adjustments
made during this pass:

- Light `--highlight` `#8A6D2F` → `#7C6028` (was 4.43:1 on the page
  background; now 5.37:1).
- Form boundaries used `--line-strong` at 1.7:1 — below the 3:1
  non-text rule. Inputs and the command bar now use a dedicated
  `--line-input` (dark `#5F675F` = 3.18:1 on elev-1; light `#8A8674`
  = 3.66:1 on white). Decorative hairlines keep the spec values.

Spot values (dark): text 17.6:1, text-2 8.9:1, text-3 5.1:1, accent
7.4:1, button ink on accent 6.2:1. Light: text 16.9:1, text-2 7.4:1,
accent 4.9:1, white ink on accent 5.3:1. `prefers-contrast: more`
lifts tertiary text and lines further in both themes.

## Components

Shell (sticky nav + mobile sheet with focus management and scroll
lock, skip-to-main link, 4-column footer with live status), hero
command bar (Ctrl/⌘K focuses it from anywhere), real sample-result
product panel, coverage cards, uniform tool grid (no masonry),
sticky tool nav with scroll-spy, scan timeline (aria-live polite)
replacing any terminal metaphor, findings with severity dot + points
+ fix, result actions (copy summary / share / copy as JSON /
checked-at meta), segmented strength meter, dropzone, vault,
trending ranks with bars, steps, privacy band, FAQ `<details>`.

## Decisions worth knowing

- **Dynamic meter widths keep React `style` props** (score meter,
  trending bars). They are data-driven values set via CSSOM, not
  markup style attributes; every *static* inline style was removed.
- **The theme bootstrap was already external** (`/assets/theme-init.js`)
  in the baseline, satisfying CSP `script-src 'self'`. The JSON-LD
  block in `index.html` is structured data, not an executable
  bootstrap, and was left as-is.
- **Copy fix:** page metadata said "Nine free security tools"; the
  platform ships ten (Secret Scanner, v2.0). Corrected everywhere.
- **Heading order:** all ten tool cards were `<h2>`; now `<h3>` under
  the section `<h2>`.
- **Keyboard fixes:** the password visibility toggle was removed
  from the tab order (`tabIndex={-1}`) and the file input was
  `display:none` — both are reachable now, the dropzone shows a
  `:focus-within` ring.
- **Cascade bug fixed:** the ≤640px command-bar rules sat before the
  hero base rules and never applied; the mobile field clipped its
  two-line placeholder. The media block now follows the base rules.

## QA evidence (this pass, local build)

- Screenshots: `frontend/qa-screenshots/` — 320/375/768/1280/1440px,
  both themes, headless Chrome with a fresh profile per shot, served
  from the local `dist/` build. (QA copies preset the stored theme in
  `/tmp` only; shipped code untouched.)
- Lighthouse (local, sandbox VM, uncompressed `http.server`):
  Accessibility **100**, Performance 78, LCP 1.2s, CLS 0. The
  performance figure is a floor, not a production measurement — the
  sandbox serves the 288 KB bundle uncompressed on 1.5 shared CPUs;
  production serves it via Cloudflare with compression. Treat
  "Lighthouse ≥95" as unverified until run against the deployed
  build or a compressed local server.
- Keyboard walkthrough (code-verified): skip link → brand → nav →
  theme segmented control → Sign in / Run a free scan → command bar
  → samples → coverage cards → tool-nav → filter → each tool's
  labelled controls → footer. Escape closes the mobile sheet and
  focus returns to the toggle; Ctrl/⌘K or `/` jumps to the scan box.
  Not screen-reader tested in this environment — NVDA/VoiceOver pass
  still owed on a real device.
- Backend suite untouched and green: 186 passed.

## Not done / owed

- Production Lighthouse run (≥95 perf gate) after deploy.
- Screen-reader pass (NVDA/VoiceOver) on a real device.
- Code-splitting the tool bundle was considered and rejected for
  now: the tools are the page's primary content and lazy chunks
  would break first-paint anchor links to `#tool-*`.
