---
title: occtl output requirements
generator: requirements-from-implementation
process: n/a
id-prefix: REQ-OCCTL
sources:
  - src/occtl/json.c
  - src/occtl/json.h
  - src/occtl/print.c
  - doc/occtl.8.md
---

# occtl output requirements

These requirements cover output from the occtl control tool, independently
of the daemon's authentication and session-management decisions.

## CFG — CLI-selected output format

### REQ-OCCTL-CFG-001 — JSON string escaping preserves UTF-8 values

**Requirement:** occtl MUST escape string values in JSON output per RFC 8259
§7 (quote, backslash, control characters) and pass all other bytes through
unchanged, regardless of the platform's `char` signedness, so that valid UTF-8
values decode to the original string.
**Strength:** MUST
**Status:** DERIVED
**Source:** `src/occtl/json.c` (`json_escape_val()`);
`src/occtl/print.c` (`print_single_value()`, `print_single_value_ex()`,
`print_pair_value()`); `doc/occtl.8.md` (`--json`);
[RFC 8259 sections 7 and 8.1](https://www.rfc-editor.org/rfc/rfc8259.html)
**Acceptance:** unit, local — `tests/json-escape.c` verifies unchanged
ASCII escaping, two-, three- and four-byte UTF-8 characters, mixed UTF-8
and escaped characters, and the existing fallback for a small positive
output capacity without modifying guard bytes. Run the same cases with
signed and unsigned plain `char`; both produce identical expected values.
**Links:** REQ-GEN-TEST-001, REQ-GEN-COMPAT-001
