# ADR-001: Monotonic Diminishing-Gain Risk Calculation Model

## Status
Accepted

## Context
Traditional vulnerability management tools often calculate repository risk as the simple arithmetic average of finding severities. This creates a critical mathematical flaw: adding 50 Low severity findings to a repository with 1 Critical vulnerability can dilute and lower the calculated risk score, misleading engineering teams and bypassing security gates.

## Decision
We adopted a strictly monotonic, diminishing-gain risk scoring model:
$$\text{Risk}(S \cup \{f\}) \ge \text{Risk}(S)$$

1. **Base Anchoring:** The single most severe finding anchors the initial score (e.g., Critical = 10.0, High = 7.0, Medium = 4.0, Low = 1.0).
2. **Diminishing Accumulation:** Subsequent findings contribute diminishing logarithmic increments capped asymptotically at 10.0.
3. **Exploitability & Reachability:** Findings verified along an active taint flow or listed in CISA KEV / EPSS > 0.5 carry an exploitability weight multiplier.
4. **Asset Criticality:** The final composite score scales with asset business criticality.

## Consequences
- Guaranteed safety against score dilution.
- Mathematical consistency in CI/CD quality gate enforcement.
