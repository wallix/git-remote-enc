# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting: <https://github.com/wallix/git-remote-enc/security/advisories/new>.
Do not open a public issue, pull request or discussion for a vulnerability.

Include the affected version (`git-remote-enc --version`), the platform, and
the steps or input that reproduce the problem. Never include real private keys,
pack keys (`git-remote-enc manifest --show-keys` output) or repository
contents; a throwaway key and remote reproduce anything the format allows.

## What to expect

- Acknowledgement within 5 working days.
- An assessment (accepted, needs information, or declined with the reason)
  within 15 working days.
- Coordinated disclosure: the fix is released, then the advisory is published
  on GitHub with a CVE when one applies. The default embargo is 90 days from
  the report, shorter if a fix ships earlier or the issue is exploited in the
  wild. Reporters are credited unless they ask not to be.

## Supported versions

Only the latest release receives security fixes. The on-remote format may
change between 0.x releases; `CHANGELOG.md` says when it does.

## Scope

In scope: the `git-remote-enc` binary and `enccore` library, the on-remote
format and trust model described in [`DESIGN.md`](DESIGN.md), and the release
artifacts and their build pipeline.

The threat model, including what the host is expected to learn, is in
[`DESIGN.md` §6](DESIGN.md#6-trust-model). Behaviour listed there as a
non-goal or accepted residual risk (traffic analysis, the backend branch name,
revocation of past history) is not a vulnerability by itself, but a way to
make it worse than documented is.
