# Changelog

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
