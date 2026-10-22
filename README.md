# php2shell-safe-poc

Detection-only verification toolkit for **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619) — a reported pre-authentication memory-corruption issue in PHP's `session.upload_progress` handling, patched upstream on 2026-10-21 (PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).

## What this is

**Primary purpose: find out whether your own PHP app is vulnerable — no WAF required, no WAF assumed.** `scripts/recon.sh` + `scripts/probe_oom.sh`, run directly against the origin, are the complete answer to that question on their own. See `docs/RUNBOOK.md` Part A.

**Separate, optional purpose:** if the app *does* sit behind a WAF/CDN, `scripts/verify_waf.sh` + `scripts/lookup_cf_rule.sh` additionally check whether the WAF is blocking this specific issue — and whether it's blocking it via a rule actually documented for this CVE, not an incidental generic match. This is Part B of the runbook and is a different question from "is the app vulnerable." A WAF result by itself proves nothing about the app underneath — see "Why the split exists" in `docs/RUNBOOK.md`.

This repo intentionally does **not** include exploitation, memory-reclaim spraying, or RCE-chain code. It stops at "can we reach/trigger the reported fault condition" and (optionally) "does the WAF catch it" — it does not attempt to pop a shell.

## What this is not

- Not an exploit framework.
- Not a mass-scanning tool — it targets one host at a time, by design, and only on explicit invocation.
- Not a substitute for patching. A clean result from these scripts does not certify immunity to every reported variant of this issue — only to the specific probe tested.

## Authorization

**Use only against systems you own or are explicitly authorized to test.** The probe can cause a transient `HTTP 500` / out-of-memory condition on the PHP worker that handles it. Do not run this against production systems or anything you don't control.

## Caveat on technical claims

Public write-ups about CVE-2026-109618/109619 (including the ones this repo's probe logic was derived from) disagree with each other — at least three independent sources contradict each other's root-cause mechanism and on which mitigation covers which CVE. Treat PHP's own security advisory as ground truth; treat this repo's commentary as a verification aid, not an authoritative technical account.

**`display_errors` matters for interpreting results.** The strong OOM signature `probe_oom.sh` looks for only appears in the response body when `display_errors=On`. With it `Off` (common in production), a vulnerable host still OOMs but returns an empty `500` body — the script falls back to a weaker, baseline-compared signal and says so explicitly. A clean-looking or ambiguous result under `display_errors=Off` is **not** a pass — see `docs/RUNBOOK.md` for how to read it.

## Contents

Core (vulnerability check, no WAF involved):
- `scripts/recon.sh` — version/ini check (run locally on the host, or adapt for SSH); also reports `display_errors`, which changes how to read `probe_oom.sh`'s result
- `scripts/probe_oom.sh` — builds and sends the non-destructive OOM probe plus a harmless baseline, reports a strong / weak-ambiguous / clean verdict (see Caveat below on why there are three, not two)

Optional (only if a WAF/CDN is in front of the app):
- `scripts/verify_waf.sh` — sends the identical probe through a WAF-fronted hostname and reports block vs. pass-through, surfacing the `cf-ray` header for cross-referencing against your WAF's event log
- `scripts/lookup_cf_rule.sh` — given a `cf-ray` value, queries Cloudflare's Security Events API for the exact rule ID/description that fired, so you can confirm it matches the vendor's *documented, CVE-specific* rule rather than an incidental generic-anomaly match

- `docs/RUNBOOK.md` — full walkthrough: Part A (is my app vulnerable — no WAF needed) and Part B (optional WAF coverage check), each with its own decision table

## Quick start

**No WAF, or testing the origin directly — this is the complete vulnerability check:**

```bash
# 1. recon (run on the host itself, or over SSH)
bash scripts/recon.sh

# 2. non-destructive probe against the origin (its own IP/hostname — nothing proxying in front)
HOST=<origin-ip-or-host> PATH_=/index.php bash scripts/probe_oom.sh

# 3. confirm worker survival
curl -sk -i "https://$HOST$PATH_"
```

Read the result using `docs/RUNBOOK.md` Part A's verdict table — it covers patched-version, config-disabled, strong-signal, weak/ambiguous-signal, and clean-result cases explicitly, since a bare "no signal" is not the same as "safe" (see the `display_errors` caveat below).

**Only if the app sits behind a WAF/CDN, as an additional, separate check:**

```bash
# 4. same probe through your public, WAF-fronted hostname
HOST=<public-hostname> PATH_=/index.php bash scripts/verify_waf.sh

# 5. confirm the exact rule that fired (not just that something blocked it)
CF_API_TOKEN=<token> CF_ZONE_ID=<zone> RAY_ID=<cf-ray from step 4> bash scripts/lookup_cf_rule.sh
```

A result here tells you about the WAF, not the app — see `docs/RUNBOOK.md` Part B.

## References

- Cloudflare — PHP2Shell WAF coverage: https://blog.cloudflare.com/php-vulnerabilities-waf-protection/

## Remediation

1. Patch PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or your distro's backport). This is the only complete fix per vendor reporting.
2. Interim mitigation if you can't patch immediately: `session.upload_progress.enabled = Off`. Scope is reportedly partial — verify with `scripts/probe_oom.sh` what it actually closes on your build.
3. Keep a WAF rule covering this in place as defense-in-depth, not as a substitute for patching.

## License

MIT — see `LICENSE`.
