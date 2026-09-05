# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use [GitHub's private vulnerability reporting](https://github.com/Ali0600/preflight/security/advisories/new),
or email **a.hassan0600@gmail.com** with "SECURITY" in the subject.

Please include what you can: what the issue is, how to reproduce it, and what an
attacker could do with it. I will acknowledge within a few days and tell you what
I plan to do about it.

This is a personal project, not a funded product — there is no bounty, and I fix
things as fast as one person reasonably can.

## Supported versions

Only the current `main` branch is supported. This is a published npm package and GitHub Action; fixes land on
`main` and ship from there.

## What this project already does

- Every third-party GitHub Action is pinned to a commit SHA, and workflow tokens
  are least-privilege.
- Dependencies are checked before they merge, and known advisories are tracked in
  the repository's Security tab.
