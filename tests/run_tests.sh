#!/usr/bin/env bash
# Hermetic test suite for ssrf_oob.sh.
# Stubs out interactsh-client and curl (see tests/stubs/) so no network
# access or real OOB server is needed. The curl stub appends interaction
# JSON lines to the run's interactsh.log for requests that match a hit
# rule, which lets us verify the correlation pipeline end to end.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/ssrf_oob.sh"
STUBS="$ROOT/tests/stubs"

TMP="$(mktemp -d /tmp/ssrf_oob_tests_XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

export PATH="$STUBS:$PATH"
# keep the interactsh config bootstrap hermetic in tests
export ITCH_CONFIG="$TMP/itch-config.yaml"
# stub session domain does not resolve -- skip the DNS wait in tests
export SSRF_OOB_SKIP_DNS_CHECK=1
SMALL_PARAMS="$TMP/params_small.txt"
cat > "$SMALL_PARAMS" <<'EOF'
url
callback
dest
webhook
src
EOF

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
assert_eq() { # desc expected actual
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
assert_contains() { # desc file needle
    if grep -qF -- "$3" "$2" 2>/dev/null; then ok "$1"; else bad "$1 (missing '$3' in $2)"; fi
}
assert_not_contains() {
    if grep -qF -- "$3" "$2" 2>/dev/null; then bad "$1 (unexpected '$3' in $2)"; else ok "$1"; fi
}

# run_case <name> <hit_on> <extra env...> -- <script args...>
# Always uses -w 1 --poll-interval 1 for speed and an explicit -o outdir.
run_case() {
    local name="$1" hit_on="$2"; shift 2
    local out="$TMP/$name"
    mkdir -p "$out"
    export SSRF_TEST_OUTDIR="$out"
    export SSRF_TEST_CURL_LOG="$out/curl.log"
    export SSRF_TEST_HIT_ON="$hit_on"
    : > "$SSRF_TEST_CURL_LOG"
    bash "$SCRIPT" -o "$out" -w 1 --poll-interval 1 "$@" > "$out/stdout.txt" 2>&1
    echo $?
}

echo "== ssrf_oob.sh test suite (tmp: $TMP) =="

# ---- 1. single URL with FUZZ, both schemes, hit on the url= param ----
rc=$(run_case t1 "url=" -u "http://target.local/fetch?url=FUZZ")
assert_eq "t1: exit code 0" 0 "$rc"
assert_eq "t1: 2 confirmed (http+bare)" 2 "$(jq length "$TMP/t1/confirmed.json")"
assert_contains "t1: report shows CONFIRMED" "$TMP/t1/report.txt" "[CONFIRMED]"
assert_eq "t1: summary confirmed count" 2 "$(jq -r .confirmed_hits "$TMP/t1/summary.json")"
assert_eq "t1: all sent" 2 "$(grep -c '^SENT' "$TMP/t1/send.log")"

# ---- 2. no FUZZ -> auto-param expansion, nothing skipped ----
rc=$(run_case t2 "callback=" --params "$SMALL_PARAMS" -u "http://target.local/endpoint")
assert_eq "t2: exit code 0" 0 "$rc"
assert_eq "t2: total = params x 2 schemes" 10 "$(jq -r .total_test_cases "$TMP/t2/summary.json")"
assert_eq "t2: 2 confirmed (callback param, both schemes)" 2 "$(jq length "$TMP/t2/confirmed.json")"
assert_contains "t2: injection tagged auto-param:callback" "$TMP/t2/confirmed.json" "auto-param:callback"
assert_eq "t2: every candidate appears in report" 10 "$(grep -c 'no interaction\|CONFIRMED' "$TMP/t2/report.txt")"

# ---- 3. noise is separated, never counted ----
export SSRF_TEST_NOISE=1
rc=$(run_case t3 "url=" -u "http://target.local/fetch?url=FUZZ")
unset SSRF_TEST_NOISE
assert_eq "t3: 2 confirmed" 2 "$(jq length "$TMP/t3/confirmed.json")"
assert_eq "t3: 1 noise interaction" 1 "$(jq length "$TMP/t3/noise.json")"
assert_eq "t3: noise not counted in summary" 2 "$(jq -r .confirmed_hits "$TMP/t3/summary.json")"

# ---- 4. header injection on FUZZ-less line ----
rc=$(run_case t4 "X-Forwarded-Host:" --params "$SMALL_PARAMS" \
    -u "http://target.local/endpoint" -H "X-Forwarded-Host: FUZZ")
assert_eq "t4: exit code 0" 0 "$rc"
# every auto-param job also carries the FUZZ header (5 params x 2 schemes)
# plus the 2 dedicated header-injection jobs -> 12 confirmed
assert_eq "t4: 12 header-carrying hits confirmed" 12 "$(jq length "$TMP/t4/confirmed.json")"
assert_contains "t4: injection tagged header:" "$TMP/t4/confirmed.json" "header:X-Forwarded-Host:"

# ---- 5. plain -H header (no FUZZ) is actually sent (regression) ----
rc=$(run_case t5 "url=" -u "http://target.local/fetch?url=FUZZ" -H "X-Test: yes")
assert_eq "t5: exit code 0" 0 "$rc"
assert_contains "t5: custom header present in request log" "$TMP/t5/curl.log" "X-Test: yes"

# ---- 6. -d implies POST when -X not given (regression) + body FUZZ ----
rc=$(run_case t6 '"cb":' -u "http://target.local/fetch?url=FUZZ" -d '{"cb":"FUZZ"}')
assert_eq "t6: exit code 0" 0 "$rc"
assert_eq "t6: request used POST" "POST" "$(head -1 "$TMP/t6/curl.log" | cut -f1)"
assert_contains "t6: body carried the callback label" "$TMP/t6/curl.log" '"cb":"http://'
assert_eq "t6: 2 confirmed via body" 2 "$(jq length "$TMP/t6/confirmed.json")"

# ---- 7. explicit -X overrides -d POST default ----
rc=$(run_case t7 '"cb":' -u "http://target.local/fetch?url=FUZZ" -d '{"cb":"FUZZ"}' -X PUT)
assert_eq "t7: request used PUT" "PUT" "$(head -1 "$TMP/t7/curl.log" | cut -f1)"

# ---- 8. scheme modes ----
rc=$(run_case t8a "url=" -u "http://target.local/fetch?url=FUZZ" --scheme bare)
assert_eq "t8a: bare only -> 1 test case" 1 "$(jq -r .total_test_cases "$TMP/t8a/summary.json")"
rc=$(run_case t8b "url=" -u "http://target.local/fetch?url=FUZZ" --scheme all)
assert_eq "t8b: all -> 3 test cases" 3 "$(jq -r .total_test_cases "$TMP/t8b/summary.json")"

# ---- 9. --encode URL-encodes the payload ----
rc=$(run_case t9 "url=" -u "http://target.local/fetch?url=FUZZ" --encode)
assert_eq "t9: exit code 0" 0 "$rc"
assert_contains "t9: payload is URL-encoded" "$TMP/t9/curl.log" "http%3A%2F%2F"

# ---- 10. transport failures are UNSENT, not hidden ----
export SSRF_TEST_FAIL_LABELS=1
rc=$(run_case t10 "nothing-matches" -u "http://failme.local/?x=FUZZ" --retries 2)
unset SSRF_TEST_FAIL_LABELS
assert_eq "t10: exit code 0" 0 "$rc"
assert_contains "t10: FAILED recorded in send.log" "$TMP/t10/send.log" "FAILED label="
assert_contains "t10: retried 3 attempts" "$TMP/t10/send.log" "after 3 attempt"
assert_contains "t10: report marks UNSENT" "$TMP/t10/report.txt" "[UNSENT]"
assert_eq "t10: 0 confirmed" 0 "$(jq length "$TMP/t10/confirmed.json")"
assert_eq "t10: summary unsent = 2" 2 "$(jq -r .unsent "$TMP/t10/summary.json")"

# ---- 11. -u and -l together -> error ----
out="$TMP/t11"; mkdir -p "$out"
bash "$SCRIPT" -o "$out" -u "http://a.local/" -l "$SMALL_PARAMS" >/dev/null 2>&1
assert_eq "t11: -u + -l rejected" 1 "$?"

# ---- 12. bad --scheme and non-numeric -w rejected ----
out="$TMP/t12"; mkdir -p "$out"
bash "$SCRIPT" -o "$out" -u "http://a.local/" --scheme bogus >/dev/null 2>&1
assert_eq "t12a: bogus --scheme rejected" 1 "$?"
bash "$SCRIPT" -o "$out" -u "http://a.local/" -w abc >/dev/null 2>&1
assert_eq "t12b: non-numeric -w rejected" 1 "$?"

# ---- 13. --version / --list-params ----
v=$(bash "$SCRIPT" --version)
assert_eq "t13a: --version prints version" "ssrf_oob.sh v4.0" "$v"
n=$(bash "$SCRIPT" --list-params | wc -l)
if [ "$n" -gt 100 ]; then ok "t13b: bundled wordlist has >100 params ($n)"; else bad "t13b: wordlist too small ($n)"; fi

# ---- 14. --git-repo integration copies + commits findings ----
gitrepo="$TMP/findings_repo"; mkdir -p "$gitrepo"
git -C "$gitrepo" init -q
git -C "$gitrepo" remote add origin https://github.com/example/findings.git
rc=$(run_case t14 "url=" --params "$SMALL_PARAMS" -u "http://target.local/fetch?url=FUZZ" \
    --git-repo "$gitrepo" --id testrun)
assert_eq "t14: exit code 0" 0 "$rc"
found_dir=$(find "$gitrepo/findings/ssrf" -mindepth 1 -maxdepth 1 -type d | head -1)
if [ -n "$found_dir" ] && [ -f "$found_dir/summary.json" ] && [ -f "$found_dir/SUMMARY.txt" ]; then
    ok "t14: findings copied into findings/ssrf/<id>/"
else
    bad "t14: findings dir/files missing"
fi
commit_count=$(git -C "$gitrepo" rev-list --count HEAD 2>/dev/null || echo 0)
assert_eq "t14: commit landed in findings repo" 1 "$commit_count"
if [ "$commit_count" != "1" ]; then
    echo "  --- git-debug.log from run ---"
    cat "$TMP/t14/git-debug.log" 2>/dev/null
fi
assert_contains "t14: commit message mentions run id" <(git -C "$gitrepo" log --format=%s -1 2>/dev/null) "ssrf-oob: testrun"

echo ""
echo "=================================="
echo " Results: $PASS passed, $FAIL failed"
echo "=================================="
[ "$FAIL" -eq 0 ]
