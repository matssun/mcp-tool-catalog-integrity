<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security Policy

MTCI is a security-sensitive project. Please report suspected vulnerabilities
responsibly.

## Supported status

MTCI is currently an experimental/incubating third-party MCP integrity-profile
proposal.

Do not assume that MTCI provides anything outside its declared boundary
(see [`docs/security-boundary.md`](docs/security-boundary.md)). In particular,
MTCI does **not** provide:

- MCP message signing or transport security (that is MCP-S Core's concern);
- authorization, delegation, or replay protection;
- tool safety classification or invocation/execution policy;
- host UX guarantees;
- official MCP extension status.

## Reporting a vulnerability

Please report security issues privately to:

```text
<security-contact@example.com>
```

Replace this placeholder before public release.

Please include:

- affected component;
- version/commit;
- reproduction steps;
- expected versus actual behavior;
- impact assessment;
- whether the issue allows a catalog descriptor to be mutated, added, or removed
  without the verifier reporting drift.

## Examples of high-severity issues

- a mutated tool descriptor accepted as unchanged against a pinned baseline;
- two distinct descriptors producing the same descriptor hash (collision);
- canonicalization differences causing a real change to hash identically to the
  pinned value;
- the verifier reporting "no drift" when a descriptor was added or removed;
- the pin store accepting an unapproved re-pin silently.

## Security boundary

The authoritative boundary is described in
[`docs/security-boundary.md`](docs/security-boundary.md). Capabilities outside
that boundary are non-claims, not vulnerabilities, unless the documentation later
changes.
