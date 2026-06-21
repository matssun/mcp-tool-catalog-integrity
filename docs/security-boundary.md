<!-- SPDX-License-Identifier: Apache-2.0 -->

# MTCI Security Boundary

**Status: DRAFT — pending owner sign-off (Mats Sundvall). Release of any
production-claim artifact is blocked until this document is signed off.**

This document is the project's **honesty gate**. It states exactly what MTCI
protects and — equally important — what it does **not** protect, so that a
security reviewer cannot over-trust the system.

The authority for the scope is
[ADR-MTCI-001](adr/adr-mtci-001-scope-and-boundary.md). Where this document and
any planning note disagree, this document and that ADR win.

---

## 1. What MTCI protects

MTCI protects the **integrity of an MCP server's tool catalog** as observed by a
host:

- It detects **mutation** of a previously pinned tool descriptor (any change to
  the descriptor's canonical content — name, description, input schema,
  annotations, etc.).
- It detects **addition** of a tool descriptor not in the pinned baseline.
- It detects **removal** of a tool descriptor present in the pinned baseline.

The mechanism is:

1. A **canonical descriptor hash** over each tool descriptor, and a catalog hash
   over the set, stable across insignificant JSON serialization differences.
2. A **pin store** recording the hashes a host has accepted (trust-on-first-use,
   with explicit, host-approved re-pin on change).
3. A **verifier** that compares an observed catalog against the pinned baseline
   and **fails closed** on any drift the host has not approved.

## 2. What MTCI does NOT protect (non-claims)

The following are **out of scope by design**. They are not vulnerabilities in
MTCI unless this document later changes:

- **MCP message signing / transport security.** MTCI does not sign or verify
  individual MCP messages and does not secure the transport. Use MCP-S Core for
  that; MTCI composes with it but does not provide it.
- **Authorization / delegation / replay protection.** MTCI makes no
  authorization decision and provides no freshness or replay guarantee.
- **Tool safety classification.** MTCI does not judge whether a tool is dangerous
  or trustworthy — only whether its descriptor matches what the host pinned.
- **Tool invocation / execution policy.** MTCI does not gate, sandbox, or police
  tool calls.
- **Host UX.** How a host surfaces drift to a user is the host's concern.

## 3. Trust-on-first-use caveat

MTCI's baseline is established on first observation (TOFU). MTCI does **not**
establish that the *first* catalog a host saw was itself authentic — only that
subsequent catalogs match it, or that changes are explicitly re-pinned by the
host. Authenticating the first observation requires an out-of-band trust anchor
(e.g. a signed catalog under MCP-S), which is out of MTCI's scope.

## 4. Composition with MCP-S

When deployed alongside MCP-S, the signed-message path can authenticate the
transport and origin while MTCI tracks descriptor-level catalog drift. The two
are orthogonal and neither depends on the other.

## 5. Sign-off

This boundary requires the human owner's explicit approval before any
production-claim artifact is released. The author does not self-approve it.

- Owner: Mats Sundvall
- Status: **pending**
- Date: _unsigned_
