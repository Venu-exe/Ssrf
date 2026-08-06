# ssrf-oob-helper

A blind/out-of-band SSRF callback helper for bug bounty hunting. Bash + `interactsh-client`.

Only run this against targets you are authorized to test.

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
  point isn't dropped — it's expanded against ~45 built-in candidate
  SSRF param names and tested that way. The final report lists every
  candidate tested, hit or not.
- **Noise is reported separately, never counted as a finding.** Any
  interaction that doesn't match a known label (background scanning of
  the wildcard `*.oast.fun` domain, stale runs, etc.) goes to
  `noise.json`, clearly separated from `confirmed.json`.
- **Async-friendly.** A configurable grace period (`-w`) accounts for
  targets that process SSRF payloads out-of-band (job queues, webhook
  dispatchers) rather than synchronously in the request.

## Requirements

- `bash`, `curl`
- [`interactsh-client`](https://github.com/projectdiscovery/interactsh) — the OOB interaction engine
  ```bash
  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
  ```
  or pass `-y` to have the script attempt this for you (requires Go).
- `jq` (optional but recommended — falls back to grep-based JSON parsing without it)

## Usage

```bash
chmod +x ssrf_oob.sh

# Single URL (new in v3.0)
./ssrf_oob.sh -u "https://target.com/api/fetch?url=FUZZ"

# List of URLs
./ssrf_oob.sh -l urls.txt
```

### Injection points

Mark where the callback should go with `FUZZ`:

```
https://target.com/api/fetch?url=FUZZ
https://target.com/proxy?dest=FUZZ&other=1
```

No `FUZZ` marker? No problem — the script automatically expands against
every built-in candidate param name (`url`, `dest`, `redirect_uri`,
`callback`, `webhook`, `src`, ...) instead of skipping.

Header-based injection:
```bash
./ssrf_oob.sh -u "https://target.com/api/fetch" -H "X-Forwarded-Host: FUZZ"
```

Body-based injection (POST):
```bash
./ssrf_oob.sh -u "https://target.com/api/fetch" \
  -d '{"callback_url":"FUZZ"}' -X POST
```

### Full options

```
Usage:
  ./ssrf_oob.sh -u <url> [options]         Test a single URL
  ./ssrf_oob.sh -l <list_file> [options]   Test a list of URLs

Input (one required):
  -u, --url URL           Single target URL (FUZZ marker optional)
  -l, --list FILE         File of target URLs (FUZZ marker optional per line)

Options:
  -H "Header: value"      Extra header, repeatable, FUZZ-aware
  -X METHOD               HTTP method (default: GET, or POST if -d given)
  -d, --data TEMPLATE     Request body template, FUZZ-aware
  --scheme MODE           http | bare | both (default: both)
  --params FILE           Override built-in candidate param list
  -w, --wait SECONDS      Grace period before polling for hits (default: 45)
  -c, --concurrency N     Parallel requests (default: 5)
  -o, --outdir DIR        Output directory
  -y, --yes               Auto-install interactsh-client if missing
  --git-repo PATH         Push results into PATH/findings/ssrf/<id>/
  --id NAME               Label for the git-repo findings folder
  -h, --help
  -v, --version
```

### Pushing results to a findings repo

```bash
./ssrf_oob.sh -l urls.txt --git-repo ~/bugbounty-findings --id acme-corp
```

Copies `report.txt`, `confirmed.json`, `noise.json`, `correlation.tsv`,
and `send.log` into `<repo>/findings/ssrf/<id>/`, then commits and
pushes. If push fails (no remote/auth), the commit still lands locally
and the script tells you so instead of failing silently.

## Output

```
<outdir>/report.txt        One line per candidate tested — [CONFIRMED] or [no interaction]
<outdir>/confirmed.json     Only confirmed OOB hits, with source request + remote address
<outdir>/noise.json         Unmatched interactions (informational, not counted)
<outdir>/correlation.tsv    label -> exact request that used it
<outdir>/send.log           Per-request SENT/FAILED status with HTTP code
<outdir>/interactsh.log     Raw interactsh-client JSON stream
```

## How correlation works

1. A single `interactsh-client` session is started; its assigned wildcard
   domain (e.g. `abcxyz....oast.fun`) is captured.
2. For each test case, a random 12-character label is generated and used
   as the subdomain: `<label>.<session-domain>`.
3. Every interaction reported by `interactsh-client` includes a `full-id`
   field — the exact subdomain that was hit. That's matched byte-for-byte
   against the correlation table.
4. A match → confirmed, with the exact source request attached.
   No match → noise, reported but not counted.

## License

MIT — see [LICENSE](LICENSE).
