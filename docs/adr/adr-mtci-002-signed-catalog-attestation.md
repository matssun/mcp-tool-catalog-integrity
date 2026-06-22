<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MTCI-002: Signed Catalog Attestation — an Optional Tier Above TOFU

## Status

Proposed (deferred — design recorded; **not implemented in v0.1**). MTCI v0.1
ships the trust-on-first-use (TOFU) drift profile of ADR-MTCI-001 only. This ADR
records the design of an optional, stronger tier so the intent is preserved and
reviewable when it is implemented.

> **Provenance.** This design originated as **ADR-MCPS-029** in the `mcps`
> (MCP-S) repository, drafted while the signed-tool-manifest subsystem still lived
> there. During the MCP-S purification (mcps ADR-MCPS-030), tool catalog integrity
> was established as a separate concern from MCP-S message security and relocated
> to this project. Catalog attestation is a tool-catalog-integrity concern, so its
> design belongs here, not in MCP-S Core. It has been adapted from the MCP-S proxy
> (a byte-stream interposing process) to the MTCI **in-process interposer**, where
> it fits more naturally because the interposer already observes the complete
> catalog. ADR-MCPS-029 has been removed from `mcps`.

## Context

ADR-MTCI-001 makes MTCI a **TOFU** profile: a host pins the descriptor hashes it
first observed and the verifier reports drift (added / removed / mutated /
unchanged) on every later observation. That is valuable, but it has a deliberate
limit: **TOFU establishes no provenance.** It cannot answer "*who* published this
catalog?" or "did an *operator approve* this tool set?" — only "did it change
since I first saw it?". A first observation is trusted implicitly (see the TOFU
caveat in `security-boundary.md`), and a host with no prior pin has nothing to
compare against.

A **signed catalog attestation** closes that gap. An operator (or publisher)
signs, out of band, the `(name, version, descriptor_hash)` set a given server is
permitted to advertise. The interposer then verifies that signature and asserts
the **observed** catalog matches the **attested** set — turning "unverified first
sighting" into "cryptographically attested baseline," and turning a rug pull into
a verifiable rejection rather than a mere drift report the host must adjudicate.

The MTCI core already has the pieces this tier builds on: the RFC 8785
canonicalizer, `descriptor_hash` / `catalog_hash`, the `PinStore` trait, the
`InMemoryPinStore` reference, the durable `FilePinStore` (interposer crate,
`file_pin_store` feature), and the `Interposer` / `CatalogAccumulator` that
already observe the complete (possibly paginated) catalog. This tier adds a
**signed manifest model**, a **manifest verifier**, a **distinct signer trust
anchor**, **manifest revocation**, and a **fail-closed** manifest-mismatch
response — composed at the interposer's existing observation point.

## Definitions

- **`signed catalog manifest`** — an operator-supplied, Ed25519-signed artifact
  attesting the `(name, version, descriptor_hash)` set a server is permitted to
  advertise. The manifest is itself canonicalized (RFC 8785, this crate's
  `canonical`) for a byte-stable signing preimage and parsed through a
  duplicate-key-rejecting wire-entry seam.
- **`descriptor_hash`** — `sha256:`-prefixed hash over a tool descriptor's
  canonical form (existing `descriptor_hash`), the value the manifest attests and
  the verifier recomputes from the live descriptor.
- **`rug pull`** — a server that, after a first trusted/attested sighting, serves
  a *changed* descriptor under an *unchanged* `name`. Detected only if the
  baseline survives process restarts — hence the durable pin store.
- **`catalog attestation`** — the act of verifying the operator's signed manifest
  and asserting the observed catalog's `(name, version, descriptor_hash)` set
  matches the attested set, fail-closed.

## Decision

Add an **optional signed-attestation tier** to the interposer: an
operator-supplied signed manifest, verified against the observed catalog, backed
by a durable pin store, with a **fail-closed** response to any verification
failure / rug pull / revoked manifest. The tier is **opt-in**; a host that does
not configure a manifest gets exactly today's TOFU behavior.

### 1. Integration point — the interposer's existing observation

The interposer already receives the complete catalog (`observe` / `observe_bytes`
for a single response; `CatalogAccumulator` for paginated `tools/list`). Signed
attestation is an **additional check at that same point**, gated on a configured
manifest:

- When a manifest is configured, after the catalog is assembled and the
  descriptor hashes are computed (the work `verify` already does), the interposer
  loads the operator's signed manifest, verifies it, and asserts the observed
  `(name, version, descriptor_hash)` set **equals** the attested set (no missing,
  no extra, no descriptor-diverged tool) before returning a clean `Observation`.
- This keeps MTCI a **pure in-process interposer** (ADR-MTCI-001): it owns no
  transport and parses no JSON-RPC routing. The host hands it the catalog, exactly
  as today; attestation is computed over that catalog.
- The manifest signer is a **distinct trust anchor** from anything the host's
  transport authenticates (e.g. an MCP-S message signer): manifest-signing
  identity (who *attests* the tool set — an operator / publisher role) is not the
  same as request-signing identity (who *calls* the server). Conflating them would
  over-grant.

### 2. Failure response — **fail-closed** (the load-bearing decision)

On ANY manifest verification failure (bad signature / unresolved signer / revoked
manifest / expired validity window / size-bound breach) **or** an observed-set
mismatch against the verified manifest, the interposer returns a **hard error**
(a fail-closed `Observation` outcome), never a "clean" verdict:

- **Decided: fail-closed.** Consistent with `DriftPolicy::FailClosed` and with
  MTCI's whole premise — a host's catalog-integrity guarantee must not depend on
  what a hostile server advertises. A manifest failure is evidence of a
  compromised/hostile server or a misconfiguration, not benign drift.
- **Rejected: drop-the-tool.** Silently stripping the offending tool yields a
  *partial* catalog the host cannot distinguish from a legitimate one and hides a
  live attack. A rug pull on one tool is reason to distrust the whole catalog.
- **Rejected: report-only.** Reporting-without-failing leaves the rug-pull /
  forged-manifest path reachable in an "attestation on" posture — exactly the
  false assurance this tier exists to prevent. (Note this differs from
  `DriftPolicy::Report`, which is a legitimate host choice for *unattested* TOFU
  drift; an *attested* manifest mismatch is a verification failure, not drift.)

### 3. Trust anchor and revocation

- **Manifest signer trust:** a separate, host-supplied trust anchor set over the
  manifest-signer keys (a resolver from signer identity to verifying key) — kept
  distinct from any caller/transport identity.
- **Manifest revocation:** a separate, host-supplied deny-list keyed on manifest
  id (and/or signer key id), so revoking a manifest is independent of any other
  revocation domain the host runs.

### 4. Durable pin store (already available)

Attestation composes with a durable `PinStore`. MTCI already ships
`FilePinStore` (interposer crate, `file_pin_store` feature): atomic
temp + `sync_all` + rename persistence, fail-closed on a corrupt file at `open`,
and pins that survive restart. The attested baseline is recorded there, so a
post-restart rug pull is rejected rather than re-trusted as a fresh first
sighting. `InMemoryPinStore` remains **test/ephemeral** and cannot provide
restart-surviving rug-pull protection. No new durability machinery is required by
this tier — only the host's choice of a durable store.

### 5. Host configuration surface

The tier is configured by the host (MTCI is a library, not a CLI) by supplying,
to the interposer:

| Input | Meaning |
|---|---|
| signed manifest bytes | the operator-supplied signed manifest to attest against |
| manifest-signer trust anchors | verifying keys for manifest **signers** (distinct from any caller identity) |
| manifest revocation deny-list | revoked manifest ids / signer key ids |
| a durable `PinStore` (e.g. `FilePinStore`) | restart-surviving attested baseline |

A host enabling attestation without a manifest, or against a non-durable store
under a "production" posture, is a configuration error the constructor should
reject (fail-closed), mirroring how MTCI already treats `InMemoryPinStore` as
ephemeral.

### 6. Conformance vectors (added with the implementing change)

A conformance suite driving the interposer that asserts:

1. **clean accept** — a signed manifest whose `(name, version, descriptor_hash)`
   set matches the observed catalog is accepted;
2. **forged-signature / bad-signer reject** — a manifest with an invalid signature
   or a signer absent from the trust anchors is rejected (hard error, no clean
   verdict);
3. **rug-pull-across-restart reject** — same `name`, descriptor changed after a
   first attested sighting, asserted **across a pin-store reopen** to prove
   durability — rejected;
4. **manifest-revoked reject** — a manifest whose id is on the revocation
   deny-list is rejected;
5. **observed-set mismatch reject** — a tool present in the observation but not
   attested (or attested but absent / descriptor-diverged) is rejected;
6. **corrupt manifest bytes reject** — a duplicate-key or non-canonical manifest
   is rejected at the wire-entry seam.

## Threat Model

- **Trust boundary:** the server is **not** trusted to be honest about the tool
  set it advertises (it may be compromised or hostile). The manifest signer is a
  distinct, operator-controlled attesting identity.
- **Primary threat:** a compromised/hostile server performs a **rug pull**
  (changed descriptor under an unchanged `name`) or presents an **unsigned /
  forged manifest**, to get the host/model to use a tool with attacker-altered
  semantics. Defeated by descriptor-hash binding + manifest signature verification
  + attested-set equality + fail-closed rejection.
- **Restart-amnesia threat:** an attacker who can force/await a restart hopes the
  pins reset so a rug-pulled descriptor is re-trusted as a fresh first sighting.
  Defeated by the durable, fsync-persisted, reopen-on-start pin store
  (`FilePinStore`).
- **Manifest-revocation evasion:** a manifest whose signer key/id is compromised
  is denied via the revocation deny-list, on a source independent of any other
  revocation domain.
- **DoS at the trust boundary:** a hostile-but-resolvable manifest with an absurd
  tool count or enormous descriptor blobs must be bounded by breadth/size limits
  in the verifier before per-tool work.
- **Residual — external pin-store rollback:** restoring the pin-store file from a
  stale snapshot re-opens a TOFU window for the rolled-back interval; there is no
  monotonic anchor to detect it (the same caveat `FilePinStore` carries). Mitigate
  by not restoring the pin file from stale snapshots. Recorded, not solved, here.
- **Boundary preserved:** this tier does **not** make MTCI define MCP message
  signing, transport security, authorization, replay protection, host UX, tool
  safety classification, or tool invocation policy (ADR-MTCI-001). It adds catalog
  *provenance*; it composes with — and does not replace — MCP-S where both are
  deployed.

## Rationale

TOFU is a real, shippable first tier, but its lack of provenance is a known
limitation, not a hidden one. A signed attestation is the natural strengthening:
it reuses MTCI's existing canonicalization, descriptor hashing, pin store, and
interposer observation point, and adds only the manifest model, verifier, signer
anchor, and a fail-closed response. Fail-closed is the only response consistent
with MTCI's premise that a host's catalog guarantee must not depend on a hostile
server. The interposer — which already holds the complete catalog — is a cleaner
integration point than the MCP-S proxy this design first targeted, because MTCI
never has to parse a transport or a routing header to obtain the catalog.

## Alternatives Considered

- **Stay TOFU-only forever.** Rejected as the long-term posture: TOFU cannot
  attest provenance, so it cannot protect a host that has no prior pin or that
  wants operator approval of the catalog. TOFU remains the **default**; this is an
  optional tier above it.
- **Report-only / drop-the-tool on manifest failure.** Rejected: both leave the
  rug-pull / forged-manifest path reachable in an "attestation on" posture and
  hand the host a catalog it cannot trust; see §2.
- **Reuse a caller/transport identity anchor for manifests.** Rejected: manifest
  signer identity is distinct from caller identity; conflating them over-grants.
- **In-memory pin store under attestation.** Rejected: defeats rug-pull protection
  across restarts; the durable store is the production tier.
- **Fold attestation into MCP-S.** Rejected and already settled: catalog integrity
  is separate from MCP-S message security (ADR-MTCI-001, mcps ADR-MCPS-030).

## Consequences

### Positive
- Catalog **provenance** and operator approval become expressible; rug-pull and
  forged-catalog protection become cryptographic rather than first-sighting-only.
- Reuses MTCI's existing canonicalizer, descriptor hashing, durable pin store, and
  interposer observation point.

### Negative
- A signed-manifest model, verifier, and trust/revocation inputs to build,
  document, and test — a meaningful increment over TOFU.
- One more durable artifact (the attested pin store) with the same
  external-rollback caveat as any TOFU store.

### Neutral
- Opt-in: hosts that configure no manifest get today's TOFU behavior unchanged.

## Open Questions for Review

- **Observed-set strictness.** Must the observed catalog **equal** the attested
  set exactly (recommended), or may the manifest be a permitted **superset** (the
  server may advertise fewer tools than attested)? Exact-match is the conservative
  default.
- **Manifest distribution.** Is an operator-supplied manifest (bytes handed to the
  interposer) sufficient, or is a defined out-of-band fetch mechanism needed? This
  ADR decides the supplied-bytes source.
- **Online manifest revocation.** A networked revocation source (vs. the offline
  deny-list) is a possible later increment; MTCI's dependency-light, sync posture
  would constrain how it is added.
- **Versioning.** Whether `version` is part of the attested identity tuple or
  advisory — descriptor-hash already binds the schema, so `version` may be
  redundant for drift but useful for operator intent.

## Related

- [ADR-MTCI-001](adr-mtci-001-scope-and-boundary.md) — Scope and boundary; TOFU is
  the base profile this tier sits above.
- [`docs/spec/tool-catalog-integrity-profile.md`](../spec/tool-catalog-integrity-profile.md)
  — the TOFU profile spec; a signed-attestation profile section lands with the
  implementing change.
- [`docs/security-boundary.md`](../security-boundary.md) — the TOFU caveat this
  tier addresses.
- Origin: `mcps` ADR-MCPS-029 (removed from `mcps`; relocated here) and the MCP-S
  purification decision mcps ADR-MCPS-030.
