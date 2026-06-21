<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MTCI-001: Scope and Boundary — Tool Catalog Integrity, Separate from MCP-S Core

## Status

Accepted

## Context

The Model Context Protocol lets a server advertise a catalog of tools (the tool
descriptors a client discovers via `tools/list`). A host that trusts those
descriptors today has no protocol-level way to detect that the catalog has
changed since it last looked — a descriptor's schema, name, or annotations can be
silently mutated, and tools can be added or removed, without any signal the host
can verify.

A separate project, **MCP-S Core**, provides a Zero Trust security profile for
MCP: object-level message signing, freshness/replay protection, delegated
authorization, transport hardening, and verified-context propagation. It is
tempting to fold catalog-integrity concerns into MCP-S, or to brand this work as
an "MCP-S extension."

This decision settles what this project is, and — equally important — what it is
not.

## Decision

MTCI defines an **optional, standalone Tool Catalog Integrity Profile**. Its
entire concern is the integrity of MCP tool **catalog descriptors**: detecting
unauthorized addition, removal, or mutation of tool descriptors against a host's
pinned baseline. It is **separate from MCP-S Core**, depends on no MCP-S crate,
and is not branded as an MCP-S extension.

MTCI **composes with** MCP-S where both are deployed, but neither requires the
other.

## Rationale

Keeping the boundary clean keeps the project politically and technically
publishable on its own terms. A catalog-integrity profile that smuggled in
message signing or authorization would force reviewers to evaluate two unrelated
trust mechanisms at once, and would entangle MTCI's adoption with MCP-S's. A
narrow, single-purpose profile is easier to review, easier to compose, and easier
to propose upstream independently.

## Boundary

MTCI does **not** define, and must not grow to define:

- MCP message signing or transport security;
- authorization, delegation, or replay protection;
- host UX;
- tool **safety** classification (judging whether a tool is dangerous);
- tool **invocation** / execution policy.

The canonical statement is:

> This project defines an optional MCP Tool Catalog Integrity Profile. It is
> separate from MCP-S Core. It protects the integrity of MCP tool catalog
> descriptors and can compose with MCP-S, but it does not define MCP message
> signing, authorization, replay protection, host UX, tool safety classification,
> or tool invocation policy.

## Alternatives Considered

- **Build it as an MCP-S extension / sub-crate.** Rejected — couples MTCI's
  identity, review, and adoption to MCP-S and blurs the boundary this ADR exists
  to keep clean.
- **Fold catalog integrity into MCP-S Core's signing scope.** Rejected — catalog
  integrity is a discovery-time, host-side trust-on-first-use concern, not a
  per-message wire concern; conflating them over-broadens MCP-S Core.

## Consequences

### Positive

- MTCI is publishable and reviewable on its own.
- Clean composition surface with MCP-S and with hosts.

### Negative

- A host that wants both message security and catalog integrity must adopt two
  profiles. Accepted: they are genuinely separate concerns.

### Neutral

- The boundary must be actively defended in review (see `CONTRIBUTING.md`).

## Related

- [`docs/security-boundary.md`](../security-boundary.md)
- [`docs/spec/tool-catalog-integrity-profile.md`](../spec/tool-catalog-integrity-profile.md)
