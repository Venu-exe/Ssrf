# ssrf-oob-helper

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/Venu-exe/Ssrf/actions/workflows/ci.yml/badge.svg)](https://github.com/Venu-exe/Ssrf/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Venu-exe/Ssrf)](https://github.com/Venu-exe/Ssrf/releases)

A blind / out-of-band **SSRF callback helper** for bug bounty hunting and authorized
pentests. Pure bash + [`interactsh-client`](https://github.com/projectdiscovery/interactsh).

> ⚠️ **Only run this against targets you are authorized to test.** See [SECURITY.md](SECURITY.md).

## The problem with most "SSRF callback" scripts

Most quick-and-dirty SSRF fuzzers point every payload at the *same*
Burp Collaborator / interactsh domain. That works until you get a hit —
and then you have no idea which of the 40 parameters you fuzzed actually
caused it, or whether it was even your traffic at all (wildcard OOB
domains pick up background internet scanning noise constantly).

This tool exists to close that gap:

- **Every single test gets its own randomly-generated subdomain label.**
  A hit can be traced back to exactly one request — one URL, one param,
  one scheme variant. No guessing.
- **Nothing is silently skipped.** A line without an obvious injection
  point isn't dropped — it's expanded against the candidate param
  wordlist (`wordlists/params.txt`, 250+ names) and tested that way.
  The final report lists every candidate tested, hit or not.
- **Noise is reported separately, never counted as a finding.** Any
  interaction that doesn't match a known label (background scanning of
  the wildcard `*.oast.*` domain, stale runs, etc.) goes to
  `noise.json`, clearly separated from `confirmed.json`.
- **Failures are never hidden.** Requests that fail at the transport
  level are reported as `UNSENT` in the report — they can't masquerade
  as true negatives.
- **Async-friendly.** A configurable grace period (`-w`) plus live
  polling (`--poll-interval`) accounts for targets that process SSRF
  payloads out-of-band (job queues, webhook dispatchers) rather than
  synchronously in the request.

## Install

### Requirements

- `bash`, `curl`
- [`interactsh-client`](https://github.com/projectdiscovery/interactsh) — the OOB engine.
  Use a **recent release** (v1.4.x): older clients can't decode the current
  interaction format from the public servers.
  ```bash
  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
  ```
  (or pass `-y` once and the script installs it for you, if Go is present)
- `jq` — optional but recommended (falls back to grep-based parsing without it)

### Options

```bash
# 1) Run straight from a clone
chmod +x ssrf_oob.sh
./ssrf_oob.sh --help

# 2) Install into ~/.local/bin
./install.sh

# 3) Docker
docker build -t ssrf-oob .
docker run --rm -v "$PWD:/out" ssrf-oob -u "https://target.com/fetch?url=FUZZ" -o /out
```

## Quick start

```bash
# Single URL with an explicit injection point
./ssrf_oob.sh -u "https://target.com/api/fetch?url=FUZZ"

# List of URLs (see examples/urls.txt)
./ssrf_oob.sh -l urls.txt

# POST body + header injection
./ssrf_oob.sh -u "https://target.com/api/fetch" \
  -d '{"callback_url":"FUZZ"}' -H "X-Forwarded-Host: FUZZ"

# Everything: all scheme variants, URL-encoded payloads, slow async target
./ssrf_oob.sh -u "https://target.com/endpoint" --scheme all --encode -w 120
```

### Injection points

Mark where the callback should go with `FUZZ`:

```
https://target.com/api/fetch?url=FUZZ
https://target.com/proxy?dest=FUZZ&other=1
```

No `FUZZ` marker? No problem — the line is automatically expanded against
every candidate param in the wordlist (`url`, `dest`, `redirect_uri`,
`callback`, `webhook`, `src`, …) instead of being skipped.

Header-based injection (repeatable):

```bash
./ssrf_oob.sh -u "https://target.com/api/fetch" -H "X-Forwarded-Host: FUZZ"
```

Body-based injection (implies `POST` unless `-X` is given):

```bash
./ssrf_oob.sh -u "https://target.com/api/fetch" -d '{"callback_url":"FUZZ"}' -X POST
```

## Full options

```
Usage:
  ./ssrf_oob.sh -u <url> [options]         Test a single URL
  ./ssrf_oob.sh -l <list_file> [options]   Test a list of URLs

Input (one required):
  -u, --url URL           Single target URL (FUZZ marker optional)
  -l, --list FILE         File of target URLs (FUZZ marker optional per line)

Injection:
  -H "Header: value"      Extra header, repeatable, FUZZ-aware
  -X METHOD               HTTP method (default: GET, or POST if -d given)
  -d, --data TEMPLATE     Request body template, FUZZ-aware

Payload / request shaping:
  --scheme MODE           http | https | bare | both | all (default: both)
  --encode                URL-encode the callback payload before injection
  --params FILE           Override the candidate param wordlist
  --list-params           Print the candidate param wordlist and exit
  -t, --timeout SECONDS   Per-request timeout (default: 15)
  --retries N             Retry transport-level failures (default: 0)
  --rate SECONDS          Min delay between requests (forces concurrency 1)
  -A, --user-agent UA     Custom User-Agent
  -x, --proxy URL         Route requests via a proxy
  -b, --cookie STR        Cookie header value
  -k, --insecure          Skip TLS verification

OOB engine:
  --server URL            Custom interactsh server
  --itch-config FILE      interactsh-client config (auto-created if missing/empty)
  --poll-interval SECONDS Live hit polling interval (default: 5)

Run control:
  -w, --wait SECONDS      Grace period before final correlation (default: 45)
  -c, --concurrency N     Parallel requests (default: 5)
  -o, --outdir DIR        Output directory
  -q, --quiet             Less chatter
  -y, --yes               Auto-install interactsh-client if missing

Results / GitHub integration:
  --git-repo PATH         Push results into PATH/findings/ssrf/<id>/
  --id NAME               Label for the git-repo findings folder
  --gh-issue              Also open/comment a GitHub issue in that repo (gh CLI)
  -h, --help              Help
  -v, --version           Version
```

## Output

```
<outdir>/report.txt        One line per candidate tested — [CONFIRMED] / [UNSENT] / [no interaction]
<outdir>/confirmed.json    Only confirmed OOB hits, with source request + remote address
<outdir>/noise.json        Unmatched interactions (informational, not counted)
<outdir>/correlation.tsv   label -> exact request that used it
<outdir>/send.log          Per-request SENT/FAILED status with HTTP code
<outdir>/summary.json      Machine-readable run summary
<outdir>/interactsh.log    Raw interactsh-client JSON stream
```

Example `confirmed.json` — each hit is traced to the exact request:

```json
[
  {
    "label": "0gyw3n95rqnl",
    "protocol": "http",
    "protocols_seen": "http",
    "remote_address": "203.0.113.7",
    "timestamp": "2026-11-12T07:15:00Z",
    "test_url": "https://target.com/api/fetch?url=http://0gyw3n95rqnl.abcd1234abcd.oast.pro/",
    "source_line": "https://target.com/api/fetch?url=FUZZ",
    "injection": "fuzz-marker"
  }
]
```

Example `summary.json` (handy for piping into other tooling):

```json
{
  "version": "4.0",
  "domain": "abcd1234abcd.oast.pro",
  "input": "https://target.com/api/fetch?url=FUZZ",
  "total_test_cases": 2,
  "sent": 2,
  "send_failures": 0,
  "unsent": 0,
  "confirmed_hits": 2,
  "noise_interactions": 0
}
```

## Sample run

```console
$ ./ssrf_oob.sh -u "https://target.com/api/fetch?url=FUZZ"
==========================================
 SSRF OOB Callback Helper v4.0
 URL:    https://target.com/api/fetch?url=FUZZ
 Output: ssrf_oob_20261112_071500/
==========================================

[*] Starting interactsh-client session...
[+] Session domain: abcd1234abcd.oast.pro
[+] Generated 2 correlated test cases (full list in ssrf_oob_20261112_071500/correlation.tsv)

[*] Sending 2 requests (concurrency: 5, timeout: 15s, retries: 0)...
[+] All requests dispatched (2 sent, 0 failed).

[*] Waiting 45s for out-of-band callbacks (raise -w for targets that process SSRF asynchronously)...
[+] LIVE OOB HIT: 0gyw3n95rqnl.abcd1234abcd.oast.pro (label=0gyw3n95rqnl) -- correlating to the exact request...
[+] LIVE OOB HIT: njvrucdr92nr.abcd1234abcd.oast.pro (label=njvrucdr92nr) -- correlating to the exact request...

[*] Correlating interactions against known labels...

==========================================
[+] 2 CONFIRMED out-of-band interaction(s) -- each traced to exactly one request.
 Full per-candidate report: ssrf_oob_20261112_071500/report.txt
 Confirmed hits (JSON):     ssrf_oob_20261112_071500/confirmed.json
 Run summary (JSON):        ssrf_oob_20261112_071500/summary.json
 Correlation table:         ssrf_oob_20261112_071500/correlation.tsv
==========================================
```

And the matching `report.txt`:

```
SSRF OOB Callback Report
Domain: abcd1234abcd.oast.pro
Total test cases: 2
Confirmed OOB hits: 2
==========================================
[CONFIRMED] https://target.com/api/fetch?url=FUZZ  |  fuzz-marker  |  http  ->  see confirmed.json (label=0gyw3n95rqnl)
[CONFIRMED] https://target.com/api/fetch?url=FUZZ  |  fuzz-marker  |  bare  ->  see confirmed.json (label=njvrucdr92nr)
```

## Pushing results to a findings repo (with `gh`)

```bash
./ssrf_oob.sh -l urls.txt --git-repo ~/bugbounty-findings --id acme-corp --gh-issue
```

Copies `report.txt`, `confirmed.json`, `noise.json`, `correlation.tsv`,
`send.log`, and `summary.json` into `<repo>/findings/ssrf/<id>/`, then
commits and pushes. With `--gh-issue`, it additionally opens a GitHub
issue in that repo (or comments on the existing one for the same run)
using the [`gh`](https://cli.github.com/) CLI — handy for triaging
confirmed SSRFs. If the push fails (no remote/auth), the commit still
lands locally and the script tells you so instead of failing silently.

## Live-tested

Verified end-to-end against a running vulnerable app (local `fetch?url=` /
POST `callback` endpoints) with a real public interactsh server:

- `FUZZ` in the URL → confirmed DNS interaction, traced to the exact request
- POST body `FUZZ` → confirmed on every candidate (the body rides along)
- auto-param expansion → exactly the one vulnerable param (`url=`) confirmed,
  all other candidates reported as `[no interaction]`
- background scanning noise → separated into `noise.json`, never counted

## How correlation works

1. A single `interactsh-client` session is started; its assigned wildcard
   domain (e.g. `abcxyz....oast.pro`) is captured.
2. For each test case, a random 12-character label is generated and used
   as the subdomain: `<label>.<session-domain>`.
3. Every interaction reported by `interactsh-client` includes a `full-id`
   field — the exact subdomain that was hit. That's matched byte-for-byte
   against the correlation table.
4. A match → confirmed, with the exact source request attached.
   No match → noise, reported but not counted.

## Repository structure

```
Ssrf/
├── ssrf_oob.sh                    # the tool itself (bash + curl + interactsh-client)
├── wordlists/
│   └── params.txt                 # 409 candidate SSRF param names for auto-expansion
├── tests/
│   ├── run_tests.sh               # hermetic test suite (42 tests, no network needed)
│   └── stubs/                     # stub interactsh-client + curl used by the tests
│       ├── interactsh-client
│       └── curl
├── examples/
│   └── urls.txt                   # sample target list
├── .github/
│   ├── workflows/
│   │   └── ci.yml                 # CI: shellcheck + test suite + bash -n
│   ├── ISSUE_TEMPLATE/            # bug report & feature request forms
│   │   ├── bug_report.yml
│   │   └── feature_request.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── install.sh                     # installs script + wordlist into ~/.local/bin
├── Dockerfile                     # ready-to-run image with interactsh preinstalled
├── README.md                      # this file
├── CHANGELOG.md                   # version history
├── SECURITY.md                    # authorized-use policy + how to report tool bugs
├── CONTRIBUTING.md                # how to contribute
└── LICENSE                        # MIT
```

## Development

```bash
bash tests/run_tests.sh     # hermetic suite: stubbed interactsh-client + curl, no network
shellcheck -x ssrf_oob.sh   # lint
```

CI runs both on every push/PR (`.github/workflows/ci.yml`).
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
