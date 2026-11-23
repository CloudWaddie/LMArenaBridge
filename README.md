# LMArenaBridge

An OpenAI-compatible API bridge to [LM Arena](https://arena.ai). It exposes `POST /api/v1/chat/completions` and proxies requests through LMArena's internal API, using browser automation to handle Cloudflare and reCAPTCHA challenges.

## Status — November 2026

Sorry for going quiet — the repo sat without an update for about 3 months (since late August 2026), and in that time LMArena changed enough to break the bridge: chat now requires a real logged-in `arena-auth-prod-v1` session, the request payload and headers moved, and the old reCAPTCHA header auth is rejected outright.

As of 23 November 2026 the bridge works again against the live site — both streaming and non-streaming completions return real responses. I intend to keep it maintained through at least 23 December 2026, so if LMArena breaks it again, file an issue and it should get fixed.

## What's required now

- A real arena.ai account. Drop your `arena-auth-prod-v1` cookie into `auth_tokens` in `config.json`. The bridge refreshes the ~20-minute session automatically (including the new chunked `.0`/`.1` cookie format) and persists it back to config.
- Python 3.12+, plus Playwright/Camoufox browsers for Cloudflare and reCAPTCHA handling.

## Running

```bash
python -m src.main
```

The server listens on `:8000`. Send requests with `Authorization: Bearer <api-key>` (keys are managed via `config.json` or the dashboard at `/dashboard`).

```bash
curl http://localhost:8000/api/v1/chat/completions \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"model": "<model-id>", "messages": [{"role": "user", "content": "hi"}]}'
```

See `CLAUDE.md` for the architecture overview and test commands.

## Notes

- LMArena rate-limits chat creation aggressively (real `Retry-After` of ~20 minutes when hammered) — keep request bursts small.
- Your `config.json` holds live credentials. It's gitignored — never commit it.
