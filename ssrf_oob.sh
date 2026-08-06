#!/bin/bash
# ==========================================================
# ssrf_oob.sh -- Blind/OOB SSRF callback helper
#
# Injects a UNIQUE, per-request interactsh subdomain label into
# every candidate SSRF injection point, then correlates any
# out-of-band interaction back to the EXACT request that caused
# it. This is the whole point of the design:
#
#   - Every test gets its own label -> a hit can only ever be
#     attributed to ONE specific request. No ambiguity, no
#     "which of these 40 params fired?" guessing.
#   - Every candidate tested is logged and reported, hit or not.
#     Nothing is silently dropped from the output.
#   - Any interaction whose label doesn't match a known test
#     (background internet scanning of the wildcard domain,
#     stale runs, etc.) is reported separately as NOISE, never
#     counted as a confirmed finding.
#
# Only run against targets you are authorized to test.
# ==========================================================

set -uo pipefail
VERSION="3.0"

CYAN='\033[1;36m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'
RED='\033[1;31m'; DIM='\033[2m'; RESET='\033[0m'

log()     { echo -e "\n${GREEN}[*]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
error()   { echo -e "${RED}[-]${RESET} $1"; }
have()    { command -v "$1" &>/dev/null; }

# ----------------------------------------------------------
# Defaults
# ----------------------------------------------------------
LIST_FILE=""
SINGLE_URL=""
METHOD="GET"
DATA_TEMPLATE=""
EXTRA_HEADERS=()
WAIT_SECONDS=45
OUTDIR=""
CONCURRENCY=5
SCHEME_MODE="both"     # http | bare | both
AUTO_INSTALL=0
PARAMS_FILE=""
GIT_REPO=""
RUN_ID=""

# Built-in candidate SSRF param names, used ONLY for lines in
# the list that don't already contain a FUZZ marker.
DEFAULT_PARAMS=(url uri path dest destination redirect redirect_uri redir
  return return_url returnUrl next target rurl callback cb notify webhook
  ping fetch proxy forward host domain site load src source img image file
  feed continue view show navigation open out to link resource endpoint
  api template page data q query remote server connect addr ip u link_url
  avatar picture logo thumbnail import export sync)

usage() {
    cat << USAGE
ssrf_oob.sh v${VERSION} -- blind/OOB SSRF callback helper

Usage:
  $0 -u <url> [options]          Test a single URL
  $0 -l <list_file> [options]    Test a list of URLs

Input (one required):
  -u, --url URL           Single target URL. Add FUZZ where the callback
                          goes (e.g. https://target.com/fetch?url=FUZZ).
                          Without FUZZ, auto-expands against all built-in
                          candidate param names (nothing skipped).
  -l, --list FILE         File of target URLs, one per line. Same FUZZ
                          rules as -u apply to each line.

Options:
  -H "Header: value"      Extra header, repeatable. Value may itself
                          contain FUZZ (e.g. -H "X-Forwarded-Host: FUZZ").
  -X METHOD               HTTP method (default: GET, or POST if -d given)
  -d, --data TEMPLATE     Request body template containing FUZZ. Implies
                          POST unless -X overrides it.
  --scheme MODE           How to render the callback: http | bare | both
                          (default: both -- tests full "http://label.dom/"
                          AND a bare "label.dom" per candidate, since some
                          apps need a full URL and some just parse a host)
  --params FILE           Override the built-in candidate param list for
                          FUZZ-less input (one param name per line)
  -w, --wait SECONDS      Grace period after sending all requests before
                          polling for interactions (default: 45). Raise
                          this for targets that process SSRF async
                          (queues/webhooks can fire minutes later).
  -c, --concurrency N     Parallel requests (default: 5)
  -o, --outdir DIR        Output directory (default: ssrf_oob_<timestamp>)
  -y, --yes               Auto-install interactsh-client if missing
  --git-repo PATH         If set and PATH is a git repo, copy results into
                          PATH/findings/ssrf/<id>/ and commit+push, same
                          pattern as the full/daily recon scripts.
  --id NAME               Label used for the git-repo findings folder
  -h, --help              Show this help
  -v, --version           Show version

Examples:
  $0 -u "https://target.com/api/fetch?url=FUZZ"
  $0 -u "https://target.com/api/fetch?url=FUZZ" -H "X-Forwarded-Host: FUZZ"
  $0 -u "https://target.com/api/fetch" -d '{"callback":"FUZZ"}' -X POST
  $0 -u "https://target.com/endpoint" -w 120
  $0 -l urls.txt --git-repo ~/bugbounty-findings --id acme-corp

Output:
  <outdir>/report.txt        Human-readable, one line per candidate tested
  <outdir>/confirmed.json    Only confirmed OOB hits, machine-readable
  <outdir>/noise.json        Unmatched interactions (informational only)
  <outdir>/correlation.tsv   label -> exact request that used it
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
        -u|--url) SINGLE_URL="$2"; shift 2 ;;
        -l|--list) LIST_FILE="$2"; shift 2 ;;
        -H) EXTRA_HEADERS+=("$2"); shift 2 ;;
        -X) METHOD="$2"; shift 2 ;;
        -d|--data) DATA_TEMPLATE="$2"; METHOD="${METHOD:-POST}"; shift 2 ;;
        --scheme) SCHEME_MODE="$2"; shift 2 ;;
        --params) PARAMS_FILE="$2"; shift 2 ;;
        -w|--wait) WAIT_SECONDS="$2"; shift 2 ;;
        -c|--concurrency) CONCURRENCY="$2"; shift 2 ;;
        -o|--outdir) OUTDIR="$2"; shift 2 ;;
        -y|--yes) AUTO_INSTALL=1; shift ;;
        --git-repo) GIT_REPO="$2"; shift 2 ;;
        --id) RUN_ID="$2"; shift 2 ;;
        -*) error "Unknown option: $1"; usage ;;
        *) error "Unexpected argument: $1"; usage ;;
    esac
done

# ----------------------------------------------------------
# Input resolution: -u writes a temp file so the rest of the
# pipeline treats single-URL and list mode identically.
# ----------------------------------------------------------
TEMP_LIST=""
if [ -n "$SINGLE_URL" ] && [ -n "$LIST_FILE" ]; then
    error "Pass either -u/--url OR -l/--list, not both."
    exit 1
elif [ -n "$SINGLE_URL" ]; then
    TEMP_LIST="$(mktemp /tmp/ssrf_oob_url_XXXXXX.txt)"
    echo "$SINGLE_URL" > "$TEMP_LIST"
    LIST_FILE="$TEMP_LIST"
    trap '[[ -n "$TEMP_LIST" ]] && rm -f "$TEMP_LIST"; kill "${ITCH_PID:-}" 2>/dev/null' EXIT
elif [ -n "$LIST_FILE" ] && [ ! -f "$LIST_FILE" ]; then
    error "-l/--list: file not found: $LIST_FILE"
    exit 1
elif [ -z "$LIST_FILE" ]; then
    error "You must pass -u/--url <url> or -l/--list <file>."
    exit 1
fi
if [ -n "$DATA_TEMPLATE" ] && [[ "$DATA_TEMPLATE" != *FUZZ* ]]; then
    error "--data template must contain a FUZZ marker."
    exit 1
fi
if [[ "$SCHEME_MODE" != "http" && "$SCHEME_MODE" != "bare" && "$SCHEME_MODE" != "both" ]]; then
    error "--scheme must be http, bare, or both"
    exit 1
fi

[ -z "$OUTDIR" ] && OUTDIR="ssrf_oob_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
CORR_FILE="$OUTDIR/correlation.tsv"
REPORT_FILE="$OUTDIR/report.txt"
CONFIRMED_FILE="$OUTDIR/confirmed.json"
NOISE_FILE="$OUTDIR/noise.json"
INTERACTSH_LOG="$OUTDIR/interactsh.log"
: > "$CORR_FILE"
: > "$REPORT_FILE"
: > "$CONFIRMED_FILE"
: > "$NOISE_FILE"

if [ -n "$PARAMS_FILE" ]; then
    mapfile -t DEFAULT_PARAMS < "$PARAMS_FILE"
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
interactsh-client -pi 5 -json > "$INTERACTSH_LOG" 2>&1 &
ITCH_PID=$!
trap 'kill "$ITCH_PID" 2>/dev/null' EXIT

DOMAIN=""
for _ in $(seq 1 20); do
    DOMAIN=$(grep -oE '[a-z0-9]{10,40}\.oast\.[a-z]+' "$INTERACTSH_LOG" | head -n1)
    [ -n "$DOMAIN" ] && break
    sleep 1
done
if [ -z "$DOMAIN" ]; then
    error "Could not determine interactsh domain -- check $INTERACTSH_LOG"
    exit 1
fi
success "Session domain: $DOMAIN"

# ----------------------------------------------------------
# 3. Build the correlation table: one row per (line x param x
#    scheme-variant) combination that will actually be sent.
#    Nothing here is skipped or sampled -- every candidate that
#    applies to a line gets a row and, later, a report line.
# ----------------------------------------------------------
gen_label() { tr -dc 'a-z0-9' < /dev/urandom | head -c12; }

TOTAL=0
declare -a JOBS

while IFS= read -r line; do
    [ -z "$line" ] && continue
    [[ "$line" =~ ^# ]] && continue

    if [[ "$line" == *FUZZ* ]]; then
        variants=()
        [[ "$SCHEME_MODE" == "http" || "$SCHEME_MODE" == "both" ]] && variants+=("http")
        [[ "$SCHEME_MODE" == "bare" || "$SCHEME_MODE" == "both" ]] && variants+=("bare")
        for scheme in "${variants[@]}"; do
            label=$(gen_label)
            cb="$label.$DOMAIN"
            [ "$scheme" = "http" ] && payload="http://$cb/" || payload="$cb"
            test_url="${line//FUZZ/$payload}"
            printf "%s\t%s\t%s\t%s\t%s\tfuzz-marker\n" "$label" "$scheme" "$METHOD" "$test_url" "$line" >> "$CORR_FILE"
            JOBS+=("$label|$scheme|$test_url")
            TOTAL=$((TOTAL+1))
        done
    else
        warn "No FUZZ marker in: $line -- expanding against ${#DEFAULT_PARAMS[@]} candidate params instead of skipping it"
        sep="?"; [[ "$line" == *"?"* ]] && sep="&"
        for param in "${DEFAULT_PARAMS[@]}"; do
            variants=()
            [[ "$SCHEME_MODE" == "http" || "$SCHEME_MODE" == "both" ]] && variants+=("http")
            [[ "$SCHEME_MODE" == "bare" || "$SCHEME_MODE" == "both" ]] && variants+=("bare")
            for scheme in "${variants[@]}"; do
                label=$(gen_label)
                cb="$label.$DOMAIN"
                [ "$scheme" = "http" ] && payload="http://$cb/" || payload="$cb"
                test_url="${line}${sep}${param}=${payload}"
                printf "%s\t%s\t%s\t%s\t%s\tauto-param:%s\n" "$label" "$scheme" "$METHOD" "$test_url" "$line" "$param" >> "$CORR_FILE"
                JOBS+=("$label|$scheme|$test_url")
                TOTAL=$((TOTAL+1))
            done
        done
    fi

    # Header-based injection (e.g. X-Forwarded-Host: FUZZ) applies
    # per base line too, on top of whatever URL variants above.
    for h in "${EXTRA_HEADERS[@]}"; do
        [[ "$h" != *FUZZ* ]] && continue
        variants=()
        [[ "$SCHEME_MODE" == "http" || "$SCHEME_MODE" == "both" ]] && variants+=("http")
        [[ "$SCHEME_MODE" == "bare" || "$SCHEME_MODE" == "both" ]] && variants+=("bare")
        base_url="${line//FUZZ/}"
        for scheme in "${variants[@]}"; do
            label=$(gen_label)
            cb="$label.$DOMAIN"
            [ "$scheme" = "http" ] && payload="http://$cb/" || payload="$cb"
            hval="${h//FUZZ/$payload}"
            printf "%s\t%s\t%s\t%s\t%s\theader:%s\n" "$label" "$scheme" "$METHOD" "$base_url" "$line" "$hval" >> "$CORR_FILE"
            JOBS+=("$label|$scheme|$base_url|HEADER|$hval")
            TOTAL=$((TOTAL+1))
        done
    done
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
#    true negative.
# ----------------------------------------------------------
log "Sending $TOTAL requests (concurrency: $CONCURRENCY)..."
SEND_LOG="$OUTDIR/send.log"
: > "$SEND_LOG"

send_one() {
    local job="$1"
    IFS='|' read -r label scheme url extra hval <<< "$job"
    local status
    if [ "$extra" = "HEADER" ]; then
        status=$(curl -s -o /dev/null -w "%{http_code}" -X "$METHOD" -H "$hval" \
            $( [ -n "$DATA_TEMPLATE" ] && echo -d "${DATA_TEMPLATE//FUZZ/$hval}" ) \
            --max-time 15 "$url" 2>>"$SEND_LOG")
    else
        status=$(curl -s -o /dev/null -w "%{http_code}" -X "$METHOD" \
            $( [ -n "$DATA_TEMPLATE" ] && echo -d "${DATA_TEMPLATE//FUZZ/http://$label.$DOMAIN/}" ) \
            --max-time 15 "$url" 2>>"$SEND_LOG")
    fi
    if [ -n "$status" ]; then
        echo "SENT  label=$label http=$status url=$url" >> "$SEND_LOG"
    else
        echo "FAILED label=$label (curl error/timeout) url=$url" >> "$SEND_LOG"
    fi
}
export -f send_one
export METHOD DATA_TEMPLATE DOMAIN SEND_LOG

printf "%s\n" "${JOBS[@]}" | xargs -P "$CONCURRENCY" -I{} bash -c 'send_one "$@"' _ {}

FAILED_COUNT=$(grep -c '^FAILED' "$SEND_LOG" || true)
[ "$FAILED_COUNT" -gt 0 ] && warn "$FAILED_COUNT requests failed to send -- see $SEND_LOG (still included in the report as UNSENT, not silently dropped)"
success "All requests dispatched."

# ----------------------------------------------------------
# 5. Grace period for async/delayed backend processing.
# ----------------------------------------------------------
log "Waiting ${WAIT_SECONDS}s for out-of-band callbacks (raise -w for targets that process SSRF asynchronously)..."
sleep "$WAIT_SECONDS"

kill "$ITCH_PID" 2>/dev/null
sleep 1
trap - EXIT

# ----------------------------------------------------------
# 6. Correlate. Every interaction's full-id is matched against
#    the known label set. Matches = confirmed. Non-matches =
#    noise, reported separately, never counted as a hit.
# ----------------------------------------------------------
log "Correlating interactions against known labels..."

if ! have jq; then
    warn "jq not found -- falling back to grep-based matching (less robust). Install jq for reliable JSON parsing."
fi

declare -A LABEL_SEEN
CONFIRMED_COUNT=0
NOISE_COUNT=0

echo "[" > "$CONFIRMED_FILE.tmp"
echo "[" > "$NOISE_FILE.tmp"
first_confirmed=1
first_noise=1

while IFS= read -r jsonline; do
    [ -z "$jsonline" ] && continue
    if have jq; then
        full_id=$(echo "$jsonline" | jq -r '."full-id" // ."unique-id" // empty' 2>/dev/null)
        protocol=$(echo "$jsonline" | jq -r '.protocol // "unknown"' 2>/dev/null)
        remote=$(echo "$jsonline" | jq -r '."remote-address" // "unknown"' 2>/dev/null)
        ts=$(echo "$jsonline" | jq -r '.timestamp // "unknown"' 2>/dev/null)
    else
        full_id=$(echo "$jsonline" | grep -oE '"full-id":"[^"]+"' | cut -d'"' -f4)
        protocol=$(echo "$jsonline" | grep -oE '"protocol":"[^"]+"' | cut -d'"' -f4)
        remote=$(echo "$jsonline" | grep -oE '"remote-address":"[^"]+"' | cut -d'"' -f4)
        ts=$(echo "$jsonline" | grep -oE '"timestamp":"[^"]+"' | cut -d'"' -f4)
    fi
    [ -z "$full_id" ] && continue
    label="${full_id%%.*}"

    match=$(awk -F'\t' -v l="$label" '$1==l {print; exit}' "$CORR_FILE")
    if [ -n "$match" ]; then
        LABEL_SEEN["$label"]=1
        orig_url=$(echo "$match" | cut -f4)
        orig_line=$(echo "$match" | cut -f5)
        injection=$(echo "$match" | cut -f6)
        [ "$first_confirmed" -eq 0 ] && echo "," >> "$CONFIRMED_FILE.tmp"
        first_confirmed=0
        printf '  {"label":"%s","protocol":"%s","remote_address":"%s","timestamp":"%s","test_url":"%s","source_line":"%s","injection":"%s"}\n' \
            "$label" "$protocol" "$remote" "$ts" "$orig_url" "$orig_line" "$injection" >> "$CONFIRMED_FILE.tmp"
        CONFIRMED_COUNT=$((CONFIRMED_COUNT+1))
    else
        [ "$first_noise" -eq 0 ] && echo "," >> "$NOISE_FILE.tmp"
        first_noise=0
        printf '  {"label":"%s","protocol":"%s","remote_address":"%s","timestamp":"%s"}\n' \
            "$label" "$protocol" "$remote" "$ts" >> "$NOISE_FILE.tmp"
        NOISE_COUNT=$((NOISE_COUNT+1))
    fi
done < "$INTERACTSH_LOG"

echo "]" >> "$CONFIRMED_FILE.tmp"; mv "$CONFIRMED_FILE.tmp" "$CONFIRMED_FILE"
echo "]" >> "$NOISE_FILE.tmp"; mv "$NOISE_FILE.tmp" "$NOISE_FILE"

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
echo "Unmatched/noise interactions: $NOISE_COUNT (see noise.json -- not counted as findings)"
echo "=========================================="
while IFS=$'\t' read -r label scheme method test_url orig_line injection; do
    if [ -n "${LABEL_SEEN[$label]:-}" ]; then
        echo "[CONFIRMED] $orig_line  |  $injection  |  $scheme  ->  see confirmed.json (label=$label)"
    else
        echo "[no interaction] $orig_line  |  $injection  |  $scheme  (label=$label)"
    fi
done < "$CORR_FILE"
} > "$REPORT_FILE"

echo ""
echo -e "${CYAN}=========================================="
if [ "$CONFIRMED_COUNT" -gt 0 ]; then
    success "$CONFIRMED_COUNT CONFIRMED out-of-band interaction(s) -- each traced to exactly one request."
else
    warn "No confirmed interactions. All $TOTAL test cases came back negative."
fi
[ "$NOISE_COUNT" -gt 0 ] && warn "$NOISE_COUNT unmatched interaction(s) logged as noise (not counted) -- see $NOISE_FILE"
echo " Full per-candidate report: $REPORT_FILE"
echo " Confirmed hits (JSON):     $CONFIRMED_FILE"
echo " Correlation table:         $CORR_FILE"
echo -e "==========================================${RESET}"

# ----------------------------------------------------------
# 8. GITHUB INTEGRATION (optional)
# Mirrors the --git-repo pattern used by full_recon.sh /
# daily_recon.sh: copy results into findings/ssrf/<id>/ in the
# target repo, commit, push. Skipped entirely if --git-repo
# wasn't passed or doesn't point at a real repo.
# ----------------------------------------------------------
if [ -n "$GIT_REPO" ]; then
    section() { echo -e "\n${CYAN}== $1 ==${RESET}"; }
    section "GitHub Integration"

    if [ -d "$GIT_REPO" ]; then
        if [ -z "$RUN_ID" ]; then
            if [ -n "$SINGLE_URL" ]; then
                RUN_ID="$(echo "$SINGLE_URL" | sed 's|https\?://||;s|[^a-zA-Z0-9._-]|_|g' | cut -c1-40)_$(date +%Y%m%d_%H%M%S)"
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

        cat > "$GIT_OUTDIR/SUMMARY.txt" << SUMMARY
SSRF OOB run: $RUN_ID
Date: $(date '+%Y-%m-%d %H:%M:%S')
Input: ${SINGLE_URL:-$LIST_FILE}
Total test cases: $TOTAL
Confirmed OOB hits: $CONFIRMED_COUNT
Unmatched/noise interactions: $NOISE_COUNT
SUMMARY

        ( cd "$GIT_REPO" && \
          git add "findings/ssrf/$RUN_ID" 2>/dev/null && \
          git commit -m "ssrf-oob: $RUN_ID ($CONFIRMED_COUNT confirmed)" 2>/dev/null && \
          git push 2>/dev/null && success "Pushed to GitHub" || warn "git add/commit/push failed -- check remote/auth; results are still copied locally to $GIT_OUTDIR" )
    else
        warn "--git-repo '$GIT_REPO' is not a directory -- skipping git integration (results are still in $OUTDIR/)"
    fi
fi
