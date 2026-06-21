<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tool Catalog Integrity Profile

**Status: Draft v0.1**

This document specifies the MCP Tool Catalog Integrity (MTCI) Profile. It is an
optional, third-party profile and is not part of the official MCP specification.
For scope and non-goals, see
[ADR-MTCI-001](../adr/adr-mtci-001-scope-and-boundary.md) and
[`../security-boundary.md`](../security-boundary.md).

## 1. Terminology

- **Tool descriptor** — the object an MCP server advertises for a single tool
  (as returned in a `tools/list` result entry): its `name`, `description`,
  `inputSchema`, and any annotations.
- **Tool catalog** — the complete set of tool descriptors a server advertises at
  a point in time.
- **Descriptor hash** — a hash identifier over the canonical form of one tool
  descriptor.
- **Catalog hash** — a hash identifier over the ordered set of descriptor hashes.
- **Pin** — a descriptor or catalog hash a host has observed and accepted.
- **Pin store** — the host-side record of current pins.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in
RFC 2119.

## 2. Canonicalization

Before hashing, a tool descriptor MUST be reduced to a canonical byte string:

1. The descriptor is parsed as a JSON value.
2. It is serialized using a deterministic canonical scheme (RFC 8785 JSON
   Canonicalization Scheme, JCS): object members sorted by key, no insignificant
   whitespace, canonical number and string forms.

Numbers are handled per RFC 8785 as IEEE-754 doubles, serialized via the
ECMAScript `Number::toString` algorithm; finite floats common in JSON Schema
(e.g. `minimum`, `multipleOf`) are therefore accepted, while non-finite (NaN,
±Infinity) and out-of-double-domain (overflow/underflow) values fail closed, and
values requiring exact high precision MUST be encoded as strings (I-JSON).

Canonicalization MUST be **fail-closed**: any value outside the JCS domain
(e.g. non-finite numbers) MUST cause a canonicalization error, never a
best-effort serialization.

## 3. Descriptor hash

The descriptor hash is:

```text
descriptor_hash = "sha256:" || base64url_nopad( SHA-256( canonical_descriptor_bytes ) )
```

Two descriptors produce the same descriptor hash if and only if their canonical
forms are byte-identical.

## 4. Catalog hash

The catalog hash is computed over the descriptor hashes of all tools in the
catalog, sorted ascending as byte strings, joined deterministically, then hashed:

```text
catalog_hash = "sha256:" || base64url_nopad( SHA-256( join( sorted(descriptor_hashes) ) ) )
```

The sort makes the catalog hash independent of the server's `tools/list`
ordering.

## 5. Pinning and verification

A host maintains a pin store mapping each tool's identity (its `name`) to the
descriptor hash it last accepted, plus the last accepted catalog hash.

On each observation of a catalog, the verifier MUST report, relative to the pin
store:

- **Added** — a tool present in the observation but not pinned.
- **Removed** — a tool pinned but absent from the observation.
- **Mutated** — a tool present in both whose descriptor hash differs from its pin.
- **Unchanged** — a tool present in both with a matching descriptor hash.

The verifier MUST fail closed: any Added / Removed / Mutated result is **drift**
that the host has not approved, and MUST be surfaced rather than silently
accepted. A host MAY then **re-pin** explicitly, which updates the pin store to
the observed hashes.

## 6. Trust-on-first-use

On first observation of a tool (no existing pin), the host establishes the pin
from the observation. MTCI does not authenticate that first observation; see the
TOFU caveat in [`../security-boundary.md`](../security-boundary.md).

## 7. Composition with MCP-S

MTCI is independent of MCP-S. Where MCP-S authenticates the message origin and
transport, a host MAY treat a first observation arriving over a verified MCP-S
channel as more trustworthy than a bare TOFU pin, but MTCI itself defines no such
dependency.

## 8. Conformance

A conforming implementation MUST:

- produce descriptor and catalog hashes per Sections 2–4;
- classify every tool as Added / Removed / Mutated / Unchanged per Section 5;
- fail closed on canonicalization errors and on unapproved drift.
