# VERITY

VERITY is a privacy-first anti-abuse prototype built for a student innovation competition. It replaces repeated CAPTCHA-style friction with one-time enrollment, a pseudonymous cryptographic credential, and adaptive risk-based verification.

## Competition premise

CAPTCHA is treated as a software invention that never existed. Instead of forcing users to repeatedly prove they are human, VERITY makes abusive behavior expensive while legitimate behavior stays mostly invisible.

## Architecture

- Frontend: React + TypeScript + Vite + Tailwind
- Backend: Node.js + TypeScript + Express
- Database: PostgreSQL schema defined with Prisma
- Cryptography: browser native Web Crypto + ECDSA P-256 verification
- Demo flows: enrollment, store UI, risk dashboard, attack simulation

## How it works

1. The user completes 20 varied enrollment questions sampled from a larger question pool; question and answer order are randomized.
2. When configured, Google reCAPTCHA v2 gates enrollment and is validated by the API using Google's Siteverify endpoint.
3. The browser generates a private/public keypair locally.
4. The public key is registered with Stamp.
5. Participating websites request a silent verification challenge.
6. The browser signs the payload locally.
7. Stamp checks nonce freshness, signature validity, and abuse signals.
8. Decisions are returned as ALLOW, SILENT_MONITOR, STEP_UP, RATE_LIMIT, or BLOCK.

## Setup

```bash
npm install
cp .env.example .env
```

## Database setup

```bash
npm run db:generate
npm run db:push
```

## Running locally

```bash
npm run dev
```

The web app runs on http://localhost:5173 and the API runs on http://localhost:3001.

## Docker

```bash
docker compose up
```

## Tests

```bash
npm test
```

## Demo flow

1. Open /enroll and complete the 20-question assessment.
2. Create the credential locally.
3. Open /admin and enter the prototype password `password`.
4. Use the Admin tabs for Dashboard, Attack Simulator, and Live Verification.

The default Admin password is for local demonstration only. Change `ADMIN_PASSWORD` and `SESSION_SECRET` before exposing the API.

## Google reCAPTCHA

Local development uses Google's published reCAPTCHA v2 test keys by default, so the checkbox integration is visible immediately. Google test keys always pass and do not issue a real challenge. For actual CAPTCHA protection, register a reCAPTCHA v2 widget in the Google reCAPTCHA admin console and set `RECAPTCHA_SITE_KEY` and `RECAPTCHA_SECRET_KEY` in `.env`. Set `RECAPTCHA_HOSTNAME` to the registered hostname to enforce hostname validation. The API validates each one-use response token with Google's Siteverify endpoint before issuing an enrollment session. Production mode never falls back to test keys and requires real reCAPTCHA keys; local development can enforce keys with `RECAPTCHA_REQUIRED=true`.

## Environment variables

See .env.example for the supported values.
