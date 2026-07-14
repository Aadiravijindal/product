# Recrypt — Post-Quantum Migration Agent

Find quantum-vulnerable cryptography, generate hybrid post-quantum patches, verify them with real
equivalence tests, and hand your auditor a certificate.

Verified by 175 automated checks (135 API + 40 full-browser UI) on the production build,
including restart-persistence and API-failure fallback tests.

## Run it

```bash
npm install
export ANTHROPIC_API_KEY=sk-ant-...   # optional but recommended — see "What's real" below
npm run dev                            # http://localhost:3000
```

## Demo flow (matches the 10-minute script)

1. **Home** — pick one of the 3 sample repos (Python payments, Java auth, Node API gateway), or paste
   any code snippet. Both go through the identical pipeline.
2. **Scan results** — the CBOM-style table: file, lines, algorithm, usage type, risk, status.
3. **Finding detail** — the remediation agent: classification → side-by-side hybrid diff →
   confidence meter (85% auto-approve threshold; the Java TLS finding is deliberately below it) →
   live equivalence tests → Approve / Escalate / Reject.
4. **Dashboard** — "X of Y migrated", quantum exposure score (0–100 with letter grade), pass rate,
   migration history.
5. **Certificate** — printable one-page compliance certificate with certificate ID (Print / Save as PDF).

Product features beyond the core loop:
- **Analyze all** — run the remediation agent across every finding in a scan at once, with live per-row status.
- **Disk persistence** — scans, analyses, and review decisions survive server restarts (`.recrypt-data.json`).
- **CBOM export** — download a CycloneDX-inspired JSON of any scan for the customer's own tooling.
- **Patch artifacts** — download or copy the patched file straight from the finding view.
- **Cryptographic evidence** — every equivalence test exposes the actual key/signature/ciphertext bytes
  (hex excerpts) produced during the run, expandable in the UI.
- **Engine stats & history** — files/patterns/duration per scan; recent scans listed on the home screen.

## What's real vs. what's demo scaffolding

**Real:**
- Scanning: regex pattern engine over actual files/snippets (Python, Java, JS/TS, Go patterns).
- LLM analysis: with `ANTHROPIC_API_KEY` set, classification and patch generation are live Claude API
  calls (`claude-opus-4-8`, JSON-schema-constrained output) — this is what makes the "paste your own
  code" moment unscripted.
- Equivalence tests: executed on every analysis, on this host —
  - RSA-2048 PSS sign/verify and ECDH via `node:crypto`
  - **ML-DSA-65 (FIPS 204)** and **ML-KEM-768 (FIPS 203)** via `@noble/post-quantum` (audited, pure JS)
  - hybrid composite + tamper-rejection checks, with measured timings and real signature sizes
    (an ML-DSA-65 signature is ~3.3 KB vs 256 bytes for RSA-2048 — say this proactively in the room).

**Demo scaffolding (say so if asked):**
- No auth/SSO/multi-user; in-memory store, no database.
- Sample repos stand in for connecting a customer's live repo / CBOM feed.
- Without an API key, analysis falls back to a built-in remediation library (hand-verified hybrid
  patches for the sample repos; template guidance for arbitrary snippets) — clearly labeled in the UI.
- The certificate is not cryptographically signed (called out in its own footer).

## Layout

- `sample-repos/` — the three deliberately-vulnerable demo codebases
- `lib/scanner.ts` — detection engine; `lib/verify.ts` — real equivalence tests;
  `lib/claude.ts` — live LLM calls; `lib/remediation.ts` — offline fallback patches
- `app/api/*` — scan / analyze / action routes; `app/*` — the five screens

## Verify it works (one command)

After `npm run build`, run the built-in verification harness. It boots a
server, runs 88 automated checks across the whole product (scanning,
the assurance pipeline, real crypto proofs, migration plan, CBOM export,
error handling), prints a pass/fail summary, and shuts the server down.

```bash
npm run build     # once
npm run verify    # → "88 passed, 0 failed"
```

Other checks:

```bash
npm run smoke     # quick end-to-end check against an already-running server (localhost:3000)
npm run typecheck # strict TypeScript, zero errors
```

`npm run verify` exits 0 on success and 1 on any failure, so it also works
in CI. With `ANTHROPIC_API_KEY` set, it additionally exercises the live
Claude two-agent pipeline; without it, the built-in engine is verified.

## The Enterprise Console ("Final product")

The **Final product →** button on the home screen opens the Enterprise Console —
the org-wide platform the demo grows into: fleet dashboard (exposure score,
risk by team, 8-quarter trend), 24 repositories under continuous scan,
overnight fix-run records, the crypto policy gate with CISO exceptions, and
the audit trail. The three connected sample repos run the real pipeline from
inside the console; the wider fleet is a clearly-labeled representative
simulation.

Owner sign-in is required. Set the passcode via environment variable — never
in source:

```bash
# locally: add to .env.local
PLATFORM_PASSCODE=your-passcode
# optionally override the owner email (defaults to the repo owner's)
PLATFORM_EMAIL=you@example.com
```

On Vercel: Settings → Environment Variables → add `PLATFORM_PASSCODE` → redeploy.
Without the env var the passcode defaults to `recrypt-preview` (dev only — set
a real one before sharing the link).

## Set your API key once (no more re-typing)

Create a file called `.env.local` in the project root with your key:

```bash
echo 'ANTHROPIC_API_KEY=sk-ant-your-real-key' > .env.local
```

That's it. `npm run dev` and `npm start` read it automatically — you never
export the key again. `.env.local` is gitignored, so it can never be committed
or pushed. (Copy `.env.example` if you prefer a template.)

**Never hardcode a key into source files** — committed keys leak the moment
they hit GitHub and get drained by bots. `.env.local` avoids that entirely.
