# Verification Runbook

**Core goal: determine whether your own PHP app is vulnerable — this works standalone, with no WAF involved.** Part A below is the complete procedure for that. Part B is a separate, optional add-on only relevant if a WAF/CDN sits in front of the app and you additionally want to check whether it's actually blocking this.

Do not skip straight to Part B. A WAF result tells you nothing about the app underneath (see "Why this split exists" below).

## 0. Background

- **Name:** "PHP2Shell"
- **IDs:** CVE-2026-109618, CVE-2026-109619
- **Reported scope:** unauthenticated memory-corruption bugs in PHP's `session.upload_progress` handling
- **Patched in:** PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (released 2026-10-21)

> Secondary write-ups disagree with each other — at least three independently-circulating technical accounts contradict each other's root-cause mechanism and on which mitigation covers which CVE. Verify the mechanism description against **PHP's own security advisory** before restating it as fact anywhere.

---

## Part A — Is *my app* vulnerable? (no WAF required, no WAF assumed)

Run this against the PHP host directly — its IP or a hostname that resolves straight to it, nothing proxying in front. If you don't have a WAF at all, this is the entire procedure; stop after step A5.

### A1. Version check (authoritative, do this first)

```bash
bash scripts/recon.sh
```

- If the PHP version is **already** 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later (or your distro's backport of the fix) → **verdict: patched, not vulnerable to this disclosed issue.** You can stop here; the remaining steps are about *confirming* exposure on unpatched builds, not re-litigating a version that's already fixed.
- Otherwise, continue — the version alone doesn't tell you whether the *reachable* precondition applies to your config.

### A2. Config check (still from `recon.sh`'s output)

- `session.upload_progress.enabled` — if `Off`, the specific code path this probe targets isn't reachable via this vector at all. **Verdict: not reachable via this vector on this config** — note that the underlying code defect may still exist; patching is still the complete fix, this setting is a narrowing of the attack surface, not a guarantee the whole issue class is closed.
- `memory_limit` vs `post_max_size` — a small `memory_limit` relative to `post_max_size` is the reported trigger condition. If `memory_limit` is large relative to anything an attacker could realistically POST, the condition may not be reachable regardless of version — this is informative, not conclusive; proceed to the probe either way if you're unsure.
- `display_errors` — note whether it's On or Off now; it changes how to read A3's result (see below).

### A3. Probe

```bash
HOST=<origin-ip-or-hostname> PATH_=/index.php bash scripts/probe_oom.sh
```

Sends one oversized-filename multipart request and a harmless baseline request, then compares them. Three possible outcomes:

| Result | Meaning |
|---|---|
| **STRONG** — `500` + `exhausted ... in Unknown on line 0` in the body | The pre-userland OOM precondition is reachable on this host right now. This confirms the *reachable primitive*, not full RCE — see A5. |
| **WEAK / AMBIGUOUS** — status flipped to `500` vs. the baseline, but no OOM text in the body | Expected when `display_errors=Off`. **Do not read this as a pass.** It's consistent with the same condition occurring silently. Corroborate with host error logs if you have shell/log access, or treat as "not ruled out." |
| **Clean 200**, same as baseline | Either the config doesn't trigger the condition (see A2), or the version is patched (A1), or the specific `NAMELEN` tuning doesn't fit this build — not an unconditional "safe," just "not reproduced with these parameters." |

### A4. Worker survival (informative, not decisive)

```bash
curl -sk -i "https://<origin>/index.php"
```

A normal `200` here means the worker that just OOM'd is still alive — relevant to SAPI classification (persistent SAPIs like Apache mod_php are reported to survive this path; FPM/CGI are reported to exit on it, which would make this DoS-class on those SAPIs rather than something with further-chain potential).

### A5. Negative control (sanity-checks your own test, optional but recommended)

Set `session.upload_progress.enabled = Off`, restart, re-run A3's identical request. If the signal from A3 disappears, that confirms your probe is actually measuring the reported condition and not some unrelated 500 on this host — useful before you trust a STRONG or WEAK result enough to act on it.

### Part A verdict

| A1 version | A2 config | A3 probe | Verdict |
|---|---|---|---|
| Patched | — | — | **Not vulnerable** to this disclosed issue |
| Unpatched | `upload_progress=Off` | — | **Not reachable via this vector**; patch anyway |
| Unpatched | `upload_progress=On` | STRONG | **Confirmed: reachable primitive present.** Patch now; this is not proof of full RCE, but it is proof the precondition is live. |
| Unpatched | `upload_progress=On` | WEAK/AMBIGUOUS | **Inconclusive — treat as not ruled out.** Likely `display_errors=Off` masking a real STRONG result; don't report this as safe. |
| Unpatched | `upload_progress=On` | Clean 200 | **Not reproduced with current parameters** — not a guarantee; consider re-tuning `NAMELEN`/the memory ratio before calling it safe. |

**What this does *not* prove either way:** full exploitability to RCE. Even deep, build-specific exploit research reviewed during this repo's development didn't reach a portable, zero-app-cooperation RCE chain — a STRONG result here means "exposed to the reported precondition," which is already enough reason to patch, not "exploited."

---

## Part B — Optional: is a WAF in front of it actually blocking this?

**Only relevant if the app sits behind a WAF/CDN.** This section tests the WAF, not the app — run Part A first to know what the app itself does; Part B tells you whether something in front of it changes what an attacker sees.

### Why this split exists

If you run a probe against a WAF-fronted hostname instead of the origin, a `403` tells you *the WAF blocked this specific request* — it says nothing about whether the app underneath is vulnerable. Conflating the two means a blocked request could be mistaken for "safe" (it might not be — the WAF could be the only thing standing between an unpatched app and exploitation) or a passed-through vulnerable response could be mistaken for "the WAF test failed" when really the WAF was never in that path. Keep the two questions, and the two scripts, separate.

### B1. Run the probe through the WAF

```bash
HOST=<public-hostname-behind-waf> PATH_=/index.php bash scripts/verify_waf.sh
```

A `403` (not a `500`) means the WAF intercepted the request before PHP ever saw it. The script prints the `cf-ray` header for the blocked request.

### B2. Confirm it's the *right* rule, not just *a* rule

A `403` alone only proves *something* blocked the request — it could be a documented CVE-specific rule, or an incidental generic anomaly rule (oversized field, repeated-byte heuristic) that happens to also catch this shape of traffic.

- Take the `cf-ray` value from B1 and look it up in Cloudflare's Security Events log (dashboard: Security → Events, filter by Ray ID), or run `scripts/lookup_cf_rule.sh` (GraphQL Security Events API) to pull the exact `ruleId`/`description`.
- Cross-reference that rule ID against the rule(s) your WAF provider has **explicitly published** for this CVE (for Cloudflare, see References).
- **Match** → confirmed CVE-specific coverage.
- **No match / generic rule** → the block is incidental; don't claim CVE-specific coverage from this alone.

### Part A + Part B combined verdict

| Part A (origin) | Part B (WAF) | Verdict |
|---|---|---|
| Vulnerable (STRONG/WEAK) | `403`, rule confirmed CVE-specific (B2) | WAF is mitigating; origin still needs patching |
| Vulnerable (STRONG/WEAK) | `403`, rule is generic/unconfirmed | Incidental block only — don't rely on it; escalate |
| Vulnerable (STRONG/WEAK) | Passes through | WAF not covering this path at all — escalate |
| Not vulnerable / patched (Part A) | n/a | Origin already remediated; Part B is optional defense-in-depth confirmation only |

---

## Remediation priority

1. Patch PHP (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or distro backport) — the only complete fix per vendor reporting.
2. Interim, if you can't patch immediately: `session.upload_progress.enabled = Off` — partial scope (see A2); confirm with A5 what it actually closes on your build.
3. If you have a WAF, keep a confirmed CVE-specific rule enabled as defense-in-depth — not a substitute for patching.

## Before citing externally

Re-verify CVE IDs, fixed-version list, and root-cause description against PHP's own advisory. Don't restate any single vendor blog's internal-mechanics narrative (including ones referenced during this repo's development) as confirmed fact.

## References

- Cloudflare — PHP2Shell WAF coverage: https://blog.cloudflare.com/php-vulnerabilities-waf-protection/ (confirmed by matching the rule ID observed in our own Security Events log during testing, per Part B2 — re-verify the link yourself before citing it onward, as content and rule IDs can change)
