---
title: occtl interface statistics requirements
generator: requirements-from-implementation
process: n/a
id-prefix: REQ-OCCTL
sources:
  - src/occtl/nl.c
  - doc/occtl.8.md
---

# occtl interface statistics requirements

## STAT — Interface statistics resources

### REQ-OCCTL-STAT-001 — Release acquired interface statistics references

**Requirement:** On Linux with libnl enabled, occtl MUST release each
interface reference acquired for statistics exactly once after reading it.
Empty interface names and failed lookups MUST NOT release an unacquired
reference. Text and JSON statistics output MUST remain unchanged.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** `src/occtl/nl.c` (`print_iface_stats()`);
[libnl direct link lookup](https://github.com/thom311/libnl/blob/main/doc/route.txt)
**Acceptance:** positive and negative, unit — the public statistics entry
point releases one native link object for each successful text/JSON query;
NULL/empty names and failed lookups acquire and release none. The same
regression fails before the source correction. Run with unsuppressed leak
detection as well as the normal profile.
**Links:** REQ-GEN-TECH-001, REQ-GEN-TEST-001
