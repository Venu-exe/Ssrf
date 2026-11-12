# Changelog

## [4.0] - 2026-11-12

### Fixed
- `-d/--data` now actually implies `POST` when `-X` was not passed
  (previously the default `GET` silently won, so body payloads were
  sent as GET).
- Request arguments are built in an array — JSON bodies containing
  spaces are no longer broken by word-splitting.
- Plain `-H` headers (without `FUZZ`) are now actually sent on every
  request (previously ignored).
- The body `FUZZ` marker now respects `--scheme` and `--encode`
  (previously always injected a full `http://` URL).
- The EXIT trap is no longer overwritten, so temp files are always
  cleaned up.
- Transport-failed requests are now marked `[UNSENT]` in `report.txt`
  (previously only visible in `send.log`, indistinguishable from a
  true negative in the report).
- Duplicate interactions for the same `full-id` are deduplicated.
- `confirmed.json` / `noise.json` are built with `jq` when available,
  so URLs containing quotes/backslashes can't corrupt the JSON.

### Added
- `--scheme https` and `--scheme all` (http + https + bare).
- `--encode` — URL-encode the callback payload before injection.
- `-t/--timeout`, `--retries N`, `--rate SECONDS` (rate forces
  concurrency 1 so the limit is honored).
- `-A/--user-agent`, `-x/--proxy`, `-b/--cookie`, `-k/--insecure`.
- `--server` for a custom interactsh server; broader oast-domain regex.
- Live hit polling during the grace period (`--poll-interval`):
  confirmed interactions are printed as they arrive.
- `<outdir>/summary.json` — machine-readable run summary.
- `--gh-issue` — with `--git-repo`, open or comment on a GitHub issue
  in the findings repo via the `gh` CLI.
- `-q/--quiet`, `NO_COLOR` / non-TTY color suppression, input validation
  for all numeric options and `-H` format.
- External default wordlist `wordlists/params.txt` (250+ candidate
  params) with `--list-params`; built-in array kept as fallback.
- `install.sh`, `Dockerfile`, `examples/urls.txt`.
- Hermetic test suite (`tests/run_tests.sh`) with stubbed
  `interactsh-client` and `curl` — no network needed.
- GitHub Actions CI (shellcheck + tests + syntax), issue/PR templates,
  `SECURITY.md`, `CONTRIBUTING.md`.

## [1.0] - 2026-08-04

- Initial release.
- Unique per-request interactsh label -> exact-request correlation
  (no shared-domain ambiguity).
- Auto-expansion against ~45 built-in SSRF param candidates for lines
  with no explicit FUZZ marker (nothing silently skipped).
- Header and POST-body FUZZ injection support.
- `http` / `bare` / `both` callback scheme testing.
- Noise (unmatched interactions) reported separately from confirmed hits.
- `--git-repo` / `--id` integration for pushing findings to a repo,
  matching the pattern used by the full/daily recon scripts.

## [3.0] - 2026-08-06

### Added
- `-u / --url` flag: test a single URL directly without needing a list file.
  The URL can contain a FUZZ marker or be auto-expanded against candidate
  param names, exactly like list-mode lines. Internally writes to a temp
  file so the full correlation pipeline is unchanged.
- Mutual-exclusion guard: passing both `-u` and `-l` together now exits
  with a clear error.

### Changed
- Usage line and banner updated to reflect both modes.
- Git integration RUN_ID now derived from the URL string when in single-URL
  mode (temp file path no longer leaks into commit messages).
