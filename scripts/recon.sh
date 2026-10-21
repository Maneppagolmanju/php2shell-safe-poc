#!/bin/bash
# php2shell-safe-poc: recon
# Run this on the target host itself (or over SSH) before probing it over HTTP.
# Reports the facts that determine whether CVE-2026-109618/109619 are even
# reachable: SAPI type, memory_limit/post_max_size ratio, and whether
# session.upload_progress is enabled.
set -u

echo "== PHP version =="
php -v 2>/dev/null || echo "php CLI not found on this host"

echo
echo "== Relevant php.ini settings =="
php -i 2>/dev/null | grep -E \
  'Server API|memory_limit|post_max_size|session.save_handler|session.upload_progress|session.use_strict_mode|session.use_only_cookies' \
  || echo "php -i not available; check these manually in php.ini"

echo
echo "== Interpretation =="
echo "- Persistent SAPI (Apache mod_php, 'cli-server') is required for the reported"
echo "  worker-survival step; FPM/CGI are reported to exit on this path (DoS-class only)."
echo "- session.upload_progress.enabled must be On (stock default) for the probe to reach"
echo "  the reported code path at all."
echo "- memory_limit small relative to post_max_size is the reported trigger condition."
