#!/usr/bin/env bash
# Smoke test of a built oaax-manager. Usage: tools/smoke.sh <command that runs oaax-manager>
# e.g. tools/smoke.sh uvx --isolated --from dist/oaax_manager-0.1.0-py3-none-any.whl oaax-manager
# Asserts on what the tool really prints and on its exact exit code: a broken import or a missing
# index.json must fail here, and a traceback (exit 1) must not pass for a clean error.
set -uo pipefail
fail() { echo "SMOKE TEST FAILED: $*" >&2; exit 1; }

list=$("$@" list 2>&1) || fail "'list' exited non-zero: $list"
printf '%s\n' "$list" | grep -Eq '^runtime +cpu ' || fail "'list' shows no cpu runtime: $list"
printf '%s\n' "$list" | grep -Eq '^toolchain ' || fail "'list' shows no toolchain: $list"
printf '%s\n' "$list" | head -3

err=$("$@" fetch runtime nosuch 2>&1 >/dev/null)
rc=$?
[ "$rc" -eq 1 ] || fail "'fetch runtime nosuch' should exit 1, got $rc: $err"
printf '%s' "$err" | grep -q "no runtime for vendor 'nosuch'" || fail "unexpected error text: $err"
printf '%s' "$err" | grep -q Traceback && fail "a traceback is not a clean error: $err"
echo "smoke test OK"
