# Security Policy

## Authorized use only

`ssrf_oob.sh` is an offensive security tool. **Only run it against systems
you own or have explicit written authorization to test** (bug bounty scope,
penetration test engagement, lab environments). Unauthorized use may be illegal.

## Reporting vulnerabilities in this tool

If you find a security issue *in this script itself* (e.g., a way it could
exfiltrate data, execute unintended commands, or be abused):

- Open a **private** report via GitHub: Security tab → "Report a vulnerability",
  or email the maintainer.
- Do **not** open a public issue for exploitable bugs in the tool.

## Scope notes

- Findings produced by this tool against third-party targets must follow the
  target's disclosure policy.
- The script never sends data anywhere except: the target you point it at
  (that's the point), and the interactsh OOB server (payload labels only).
