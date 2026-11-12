# Contributing

Thanks for helping improve ssrf_oob.sh!

## Ground rules

- Only test against targets you are **authorized** to test.
- Never commit real target data, tokens, cookies, or OOB session details.
- Keep the script dependency-light: bash + curl required; interactsh-client
  required at runtime; jq optional.

## How to contribute

1. Fork the repo and create a branch: `git checkout -b feature/my-thing`
2. Make your changes.
3. Run the checks locally:
   ```bash
   shellcheck -x ssrf_oob.sh install.sh tests/run_tests.sh
   bash tests/run_tests.sh          # hermetic, no network needed
   bash ssrf_oob.sh --help
   ```
4. Update `README.md` (usage/options) and `CHANGELOG.md`.
5. Open a PR using the pull request template.

## Good first issues

- Add more entries to `wordlists/params.txt`
- Improve error messages / usage text
- Add test cases to `tests/run_tests.sh`
- Docs: more examples in `examples/`
