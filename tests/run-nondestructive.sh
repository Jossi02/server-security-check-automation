#!/bin/bash
set -eu
export PATH="/usr/bin:/bin:$PATH"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

PASSWD_FILE="$ROOT/tests/fixtures/passwd-clean" bash "$ROOT/linux/U-52.sh" >/dev/null
grep -q '"status": "PASS"' "$ROOT/linux/KISA_RESULT/U-52.json"

PASSWD_FILE="$ROOT/tests/fixtures/passwd-duplicate" bash "$ROOT/linux/U-52.sh" >/dev/null
grep -q '"status": "FAIL"' "$ROOT/linux/KISA_RESULT/U-52.json"
grep -q '"status": "MANUAL_REQUIRED"' "$ROOT/linux/KISA_RESULT/U-52.json"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
mkdir "$tmpdir/good" "$tmpdir/bad"
chmod 755 "$tmpdir/good"
chmod 757 "$tmpdir/bad"
printf 'clean:x:1000:1000::/path/that/does/not/exist:/bin/sh\n' > "$tmpdir/passwd-clean"
printf 'bad:x:1000:1000::%s/bad:/bin/sh\n' "$tmpdir" > "$tmpdir/passwd-bad"

PASSWD_FILE="$tmpdir/passwd-clean" bash "$ROOT/linux/U-57.sh" >/dev/null
grep -q '"status": "PASS"' "$ROOT/linux/KISA_RESULT/U-57.json"

PASSWD_FILE="$tmpdir/passwd-bad" bash "$ROOT/linux/U-57.sh" >/dev/null
grep -q '"status": "FAIL"' "$ROOT/linux/KISA_RESULT/U-57.json"
grep -q '"fixed": false' "$ROOT/linux/KISA_RESULT/U-57.json"

echo 'Bash fixture tests passed.'
