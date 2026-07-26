# Architecture decision records

These records capture durable decisions whose rationale should remain visible
after the implementation changes.

| ADR | Status | Decision |
|---|---|---|
| [001](001-native-agec-backend.md) | Accepted | Use one vendored native agec backend |
| [002](002-public-api-shape.md) | Accepted | Use explicit, type-stable, age-oriented R APIs |

## Format

New ADRs should contain:

1. title and sequential number;
2. status (`Proposed`, `Accepted`, `Superseded`, or `Rejected`);
3. context and constraints;
4. the decision;
5. consequences and rejected alternatives;
6. links to ADRs they supersede or extend.

Accepted ADRs are historical records. If a decision changes, add a new ADR and
mark the old one superseded instead of rewriting its conclusion.
