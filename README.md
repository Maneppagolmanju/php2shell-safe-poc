# php2shell-safe-poc

Detection-only verification toolkit for **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619) — a reported pre-authentication memory-corruption issue in PHP's `session.upload_progress` handling, patched upstream on 2026-10-21 (PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).

## What this is

A set of **non-weaponized** scripts to answer two questions about a host you own/are authorized to test:

1. Is the PHP instance reachable through the vulnerable code path (version/config check + a single non-destructive OOM probe)?
2. If a WAF sits in front of it, does the WAF actually block the probe, and which rule fires?

This repo intentionally does **not** include exploitation, memory-reclaim spraying, or RCE-chain code. It stops at "can we reach/trigger the reported fault condition" and "does the WAF catch it" — it does not attempt to pop a shell.

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

- `scripts/recon.sh` — version/ini check (run locally on the host, or adapt for SSH)
- `scripts/probe_oom.sh` — builds and sends the non-destructive ARM request, reports whether the pre-userland OOM signature appears
- `scripts/verify_waf.sh` — sends the identical probe through a WAF-fronted hostname and reports block vs. pass-through, surfacing the `cf-ray` header for cross-referencing against your WAF's event log
- `scripts/lookup_cf_rule.sh` — given a `cf-ray` value, queries Cloudflare's Security Events API for the exact rule ID/description that fired, so you can confirm it matches the vendor's *documented, CVE-specific* rule rather than an incidental generic-anomaly match
- `docs/RUNBOOK.md` — full walkthrough tying the above together into a verification procedure, including a decision table and remediation priority

## Quick start

```bash
# 1. recon (run on the host itself, or over SSH)
bash scripts/recon.sh

# 2. non-destructive probe against the origin directly (bypass any WAF/CDN)
HOST=<origin-ip-or-host> PATH_=/index.php bash scripts/probe_oom.sh

# 3. confirm worker survival
curl -sk -i "https://$HOST$PATH_"

# 4. same probe through your public, WAF-fronted hostname
HOST=<public-hostname> PATH_=/index.php bash scripts/verify_waf.sh

# 5. confirm the exact rule that fired (not just that something blocked it)
CF_API_TOKEN=<token> CF_ZONE_ID=<zone> RAY_ID=<cf-ray from step 4> bash scripts/lookup_cf_rule.sh
```

See `docs/RUNBOOK.md` for how to read the results, including why step 5 matters (a `403` alone doesn't tell you whether a CVE-specific rule fired vs. an incidental generic one).

## References

- Cloudflare — PHP2Shell WAF coverage: https://blog.cloudflare.com/php-vulnerabilities-waf-protection/

## Remediation

1. Patch PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or your distro's backport). This is the only complete fix per vendor reporting.
2. Interim mitigation if you can't patch immediately: `session.upload_progress.enabled = Off`. Scope is reportedly partial — verify with `scripts/probe_oom.sh` what it actually closes on your build.
3. Keep a WAF rule covering this in place as defense-in-depth, not as a substitute for patching.

## License

MIT — see `LICENSE`.
