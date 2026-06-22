<!-- SPDX-License-Identifier: Apache-2.0 -->

# MTCI Architecture Decision Records

This directory holds the Architecture Decision Records that govern MCP Tool
Catalog Integrity (MTCI).

Each ADR records the context, decision, rationale, alternatives, and
consequences of one architectural choice. They are intentionally short so they
remain maintainable as the project evolves.

## Index

| ID | Title |
|---|---|
| [ADR-MTCI-001](adr-mtci-001-scope-and-boundary.md) | Scope and Boundary — Tool Catalog Integrity, Separate from MCP-S Core |
| [ADR-MTCI-002](adr-mtci-002-signed-catalog-attestation.md) | Signed Catalog Attestation — an Optional Tier Above TOFU (proposed; relocated from mcps ADR-MCPS-029) |

## Conventions

- Each ADR is one markdown file named `adr-mtci-NNN-<slug>.md` where `NNN` is the
  zero-padded three-digit ADR number.
- Status values: **Proposed**, **Accepted**, **Implemented**, **Superseded by
  ADR-MTCI-NNN**, **Deprecated**, **Withdrawn**.
- New ADRs are appended with the next sequential number. A decision that changes
  an earlier decision supersedes that ADR with an explicit note in both
  directions.
