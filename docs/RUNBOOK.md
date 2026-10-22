# Verification Runbook

This ties `scripts/recon.sh`, `scripts/probe_oom.sh`, and `scripts/verify_waf.sh` into one procedure.

## 1. Background

- **Name:** "PHP2Shell"
- **IDs:** CVE-2026-109618, CVE-2026-109619
- **Reported scope:** unauthenticated memory-corruption bugs in PHP's `session.upload_progress` handling
- **Patched in:** PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (released 2026-10-21)

> Secondary write-ups disagree with each other on the precise CVE-to-mechanism mapping and on which single setting mitigates which CVE — at least three independently-circulating technical accounts contradict each other on root cause. Verify the mechanism description against **PHP's own security advisory** before restating it as fact anywhere.

> **`display_errors` changes what a positive result looks like.** The `500` + `exhausted ... in Unknown on line 0` body text in step 2 only appears when `display_errors=On`. With `display_errors=Off` (the security-recommended, common production default), a vulnerable host still OOMs but returns a bare `500` with an **empty body** — indistinguishable at the body level from any unrelated server error. `probe_oom.sh` handles this by also sending a harmless baseline request and comparing status codes, reporting a status-only flip as a **weak/ambiguous** signal rather than silently calling it "unrecognized." Treat a weak signal as "not ruled out," not as a pass. This also means a full RCE chain (as opposed to the reachability probe here) has been reported elsewhere as itself being easier to achieve with `display_errors=On` and is comparatively less mature/less portable with it off — another reason a clean-looking result under `display_errors=Off` should not be read as reassuring.

## 2. Procedure

1. **Recon** (on the host or over SSH): `bash scripts/recon.sh`. Confirms SAPI type, the `memory_limit`/`post_max_size` ratio, whether `session.upload_progress` is enabled, and `display_errors` (so you know in advance which signal strength to expect from step 2).
2. **Probe the origin directly**, bypassing any WAF/CDN: `HOST=<origin> bash scripts/probe_oom.sh`. Checks for the pre-userland OOM signature (`500` + `exhausted ... in Unknown on line 0`) and falls back to a baseline-comparison weak signal if that text is absent but the status code still flipped.
3. **Confirm worker survival**: a plain follow-up `curl` to the same endpoint. Informative for SAPI classification; not alone proof of exploitability.
4. **Negative control**: set `session.upload_progress.enabled = Off`, restart, re-run step 2's identical request. A clean `200` here is your evidence that this specific mitigation closes the tested path on your build.
5. **WAF verification**: run the identical probe against the **public, WAF-fronted hostname**: `HOST=<public-host> bash scripts/verify_waf.sh`. A `403` (not a `500`) means the WAF is intercepting it before PHP ever sees it. The script prints the `cf-ray` header for the blocked request.
6. **Confirm it's the *right* rule, not just *a* rule**: a `403` alone only proves something blocked the request — it could be a documented CVE-specific rule, or an incidental generic anomaly rule (oversized field, repeated-byte heuristic, etc.) that happens to also catch this shape of traffic. Don't conflate the two.
   - Take the `cf-ray` value from step 5 and look it up in Cloudflare's Security Events log (dashboard: Security → Events, filter by Ray ID) or run `scripts/lookup_cf_rule.sh` (uses the GraphQL Security Events API) to pull the exact `ruleId`/`description` that matched.
   - Cross-reference that rule ID against the rule(s) your WAF provider has **explicitly published** for this CVE. For Cloudflare, that's the managed-ruleset entry documented for PHP2Shell (see References).
   - **Match** → confirmed, CVE-specific coverage; safe to represent as "the vendor's documented php2shell rule is active and firing."
   - **No match / generic anomaly rule instead** → the block is incidental. Don't claim CVE-specific WAF coverage on that basis alone — escalate and consider it unmitigated at the WAF layer.

## 3. Decision table

| Origin direct (step 2) | Through WAF (step 5) | Verdict |
|---|---|---|
| Vulnerable response | `403` blocked | WAF is mitigating; origin still needs patching |
| Vulnerable response | Passes through | WAF rule not covering this path — escalate |
| Patched/clean response | n/a | Origin already remediated |

## 4. Remediation priority

1. Patch PHP (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or distro backport) — the only complete fix per vendor reporting.
2. Interim: `session.upload_progress.enabled = Off` — partial scope, confirm with step 4 what it actually closes.
3. Keep the WAF rule as defense-in-depth, not a substitute for patching.

## 5. Before citing externally

Re-verify CVE IDs, fixed-version list, and root-cause description against PHP's own advisory. Don't restate any single vendor blog's internal-mechanics narrative (including ones referenced during this repo's development) as confirmed fact.

## 6. References

- Cloudflare — PHP2Shell WAF coverage: https://blog.cloudflare.com/php-vulnerabilities-waf-protection/ (confirmed by matching the rule ID observed in our own Security Events log during testing, per step 6 above — re-verify the link yourself before citing it onward, as content and rule IDs can change)
