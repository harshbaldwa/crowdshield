# Security policy

## Supported code

Crowdshield is pre-1.0. Security fixes are applied to the current default branch; there is not yet a maintained release branch or published container registry artifact. Operators should build only reviewed commits and retain the matching SBOM, scan results, configuration, image digest, and data backup.

## Reporting a vulnerability

Use a private GitHub security advisory draft:

https://github.com/harshbaldwa/crowdshield/security/advisories/new

Include affected revision/version, impact, prerequisites, a minimal synthetic reproducer, and suggested mitigation when available. Do not include real CrowdSec machine credentials, notification tokens, private feed data, production logs, database copies, or host/network identifiers.

If private advisories are unavailable, contact the repository owner through a private channel before opening a public issue. Public issues should contain only non-sensitive coordination details until a fix is available.

## High-priority reports

Examples include:

- mutation or deletion of foreign CrowdSec alerts/decisions;
- bypass of allowlists, feed safety limits, ownership checks, or dry-run no-write guarantees;
- credential, token, response-body, or feed-content disclosure;
- acceptance of unsafe credential files, URLs, redirects, TLS behavior, or healthcheck targets;
- container escape, unexpected root/capability use, writable-path expansion, or secret inclusion in an image/artifact;
- unauthenticated exposure beyond the documented health/metrics network boundary;
- dependency/build/CI compromise or mutable-pin substitution;
- SQLite corruption or unsafe rollback behavior.

## Operator response

For suspected credential compromise, create and activate a new uniquely named CrowdSec machine account, verify the replacement, then delete the old account. Follow [docs/credentials.md](docs/credentials.md); do not delete the working account before cutover.

For suspected image/build compromise, stop synchronization, preserve logs and image/SBOM digests, rebuild from a reviewed commit with pinned inputs, restore a known-good data backup if required, and inspect CrowdSec ownership state before live reconciliation.

Security controls and residual assumptions are documented in [docs/container-security.md](docs/container-security.md) and [docs/threat-model.md](docs/threat-model.md).
