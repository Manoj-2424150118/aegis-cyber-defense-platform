# Contributing to Aegis

Aegis is free and open source (MIT). Anyone may use it, fork it, modify it
for their own needs, and contribute improvements back — that's the point.

## Ways to help

- **Detection rules** — new phishing/malware signals belong in
  `backend/app/modules/`. Engines are pure functions over staged contexts;
  follow the existing pattern and add your finding's **suggested fix** to
  `backend/app/modules/remediation.py` (a finding without a fix will fail
  the test suite — deliberately).
- **Tests** — every new check needs a test in `backend/tests/`.
- **UI** — React + TypeScript in `frontend/`. Keep it clean and readable;
  every finding renders its fix automatically.
- **Bug reports** — open an issue with the input that misbehaved and the
  output you expected.

## Dev setup

```bash
cd backend && python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q          # full suite must stay green
cd ../frontend && npm install && npm run build
python3 scripts/qa_battery.py http://127.0.0.1:8020   # against a local server
```

## Ground rules

- No fake detections: a check must correspond to a real attack technique.
- No telemetry, no tracking, no storing user content. Files are analysed
  in memory and never written to disk; passwords are never logged.
- Security fixes should come with a regression test.

By contributing you agree your work is licensed under the project's MIT
license.
