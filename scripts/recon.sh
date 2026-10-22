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
  'Server API|memory_limit|post_max_size|session.save_handler|session.upload_progress|session.use_strict_mode|session.use_only_cookies|^display_errors' \
  || echo "php -i not available; check these manually in php.ini"

echo
echo "== Interpretation =="
echo "- Persistent SAPI (Apache mod_php, 'cli-server') is required for the reported"
echo "  worker-survival step; FPM/CGI are reported to exit on this path (DoS-class only)."
echo "- session.upload_progress.enabled must be On (stock default) for the probe to reach"
echo "  the reported code path at all."
echo "- memory_limit small relative to post_max_size is the reported trigger condition."
echo "- display_errors: if On, scripts/probe_oom.sh can give a STRONG signal (OOM text in the"
echo "  response body). If Off (common in production), expect only a WEAK/ambiguous signal —"
echo "  see docs/RUNBOOK.md. Do not read a clean result as reassuring when display_errors=Off."
