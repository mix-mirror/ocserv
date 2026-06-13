<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) PromptKit Contributors -->

---
name: exhaustive-path-tracing
type: reasoning
description: >
  Systematic per-file reasoning protocol for deep code review. Requires
  full-file reading, local structure mapping, high-risk function identification,
  and exhaustive path tracing with coverage ledger documentation.
applicable_to:
  - review-code
  - investigate-bug
  - investigate-security
  - exhaustive-bug-hunt
---

# Protocol: Exhaustive Path Tracing

Apply this protocol when performing deep code review where completeness
matters more than speed. This protocol is language-agnostic — adapt the
specific constructs (goto, exceptions, early returns) to the target language.

## Phase 1: Full-File Structural Map

For each file under review:

1. **Read the entire file**, not just search hits or snippets.
2. Build a **local map** documenting:
   - **Entry points**: exported functions, public methods, callbacks, ISRs
   - **Major helpers**: internal functions called by entry points
   - **Lock acquisition and release sites**: every lock/unlock, acquire/release
   - **Reference count acquire/release pairs**: AddRef/Release, ObRef/ObDeref,
     retain/release, or equivalent
   - **Key flags and state variables**: mode flags, status fields, state
     machine variables
   - **Cleanup blocks**: goto labels, finally blocks, defer statements,
     destructors, shared cleanup routines
   - **Error propagation**: return codes, exceptions, error callbacks

## Phase 2: High-Risk Function Identification

Identify functions that warrant deep path tracing based on these risk signals:

- Complex **goto structure** or deeply nested error handling
- **Many unlock or release points** (risk of missing one on a path)
- **Mixed success/error mutation** — function modifies state on the
  success path and must undo it on failure
- **User/kernel boundary handling** — functions that accept user-mode
  inputs, probe buffers, or transition privilege levels
- **Interlocked or lock-free state transitions** — CAS loops, atomic
  flag updates, speculative reads
- **Size, count, or offset arithmetic** — page counts, byte counts,
  allocation sizes, array indices derived from external input
- **Resource acquisition chains** — functions that acquire multiple
  resources that must be released in reverse order

Prioritize review effort on high-risk functions. Low-risk functions
(simple getters, pure computations, thin wrappers) receive lighter review.

## Phase 3: Per-Function Path Tracing

For each high-risk function, systematically trace:

### 3a. Success Path
- Walk the happy path from entry to return.
- Record every resource acquired, lock taken, state modified, and flag set.
- Verify all resources are released and state is consistent at return.

### 3b. Early-Return Paths
- Identify every `return`, `break`, `continue`, or exception throw that
  exits the function before the normal return point.
- For each early return, verify:
  - All locks acquired before this point are released.
  - All reference counts incremented before this point are decremented.
  - All state mutations before this point are rolled back or are
    consistent with the early-return semantics.

### 3c. Goto / Cleanup Targets
- For each goto target (or equivalent cleanup block):
  - Identify which entry points jump to it and what state they hold.
  - Verify the cleanup block handles the **union** of all possible
    acquired resources — not just the resources from one path.
  - Check for cleanup ordering (resources released in reverse
    acquisition order).

### 3d. Cleanup Symmetry Verification
- For every resource acquired (lock, refcount, allocation, handle):
  - Enumerate **all** code paths from acquisition to function exit.
  - Verify the resource is released on **every** path.
  - If release is delegated to a helper, read the helper to confirm.

### 3e. State Rollback on Partial Failure
- If the function performs a **sequence of mutations** (e.g., insert into
  list A, then update table B, then modify object C):
  - Verify that failure at step N rolls back steps 1..N-1.
  - Check for partial-mutation corruption: state left inconsistent if
    an intermediate step fails.

## Phase 4: Per-Finding Documentation

For each candidate bug that survives falsification:

1. **Cite exact line numbers** or ranges.
2. **Show the path to trigger it** — step-by-step control flow from
   entry point through the failing path.
3. **Name the object, lock, refcount, or state variable** involved.
4. **Explain why existing cleanup or retry logic does NOT make it safe.**
5. **State the concrete consequence** — crash, corruption, leak, escalation.
6. **Assign confidence**: Confirmed, High-confidence, or Needs-domain-check.

## Phase 5: Coverage Ledger

Before concluding review of a file, produce a coverage ledger:

```
Coverage ledger:
  Full file read: yes/no
  High-risk functions reviewed: <list>
  Lock/refcount/goto cleanup traced: yes/no
  Arithmetic sites reviewed: yes/no
  User/kernel boundary paths reviewed: yes/no (or N/A)
  Interlocked/concurrency paths reviewed: yes/no (or N/A)
```

If any item is "no", explain why and document it as a limitation.
Do not claim "no bugs found" without a completed coverage ledger.

<!-- END PromptKit base -->

---

<!-- BEGIN ocserv extensions -->

## ocserv-Specific Extensions

### Phase 1 — ocserv local map equivalents

When building the local map, translate the generic categories as follows:

- **"Lock acquisition and release sites"** → talloc allocation/free pairs
  (`talloc_zero`, `talloc_strdup`, `talloc_free`) and `goto cleanup` labels.
- **"Reference count acquire/release pairs"** → talloc parent/child
  relationships (a child freed implicitly when its parent is freed via
  `talloc_steal`/`talloc_free`) and PCL coroutine lifecycle
  (`co_create`/`co_delete` in `src/pcl/`).
- **"User/kernel boundary handling"** → the worker/main and worker/sec-mod
  IPC boundary: any function that unpacks a protobuf message
  (`*_unpack()` from `src/*.pb-c.c`) populated by a worker process, which
  must be treated as attacker-controlled.
- **"Interlocked or lock-free state transitions"** → libev callback state
  in main/sec-mod (`src/main-*.c`, `src/sec-mod-*.c`) — a callback may run
  between two halves of what looks like a single logical operation.

### Phase 2 — ocserv high-risk function signals

In addition to the generic risk signals, prioritize:

- Any function that calls a protobuf-c `*_unpack()` on data received from
  a worker socket (`src/sec-mod.c`, `src/main.c`) — these are the parser/
  decoder functions for this codebase's untrusted-input boundary.
- `auth_mod_st` vtable implementations (`auth_init`, `auth_pass`, `auth_msg`,
  `auth_group`) in `src/auth/*.c` — these process client-supplied credentials
  before any cookie/SID is issued.
- Config parsers in `src/config.c` and `src/subconfig.c` that compute buffer
  sizes or array indices from `inih`-parsed values.
- Functions that cross a PCL coroutine switch while holding a pointer into
  a stack buffer from the calling coroutine's frame.

### Phase 5 — additional ledger line for ocserv

Add this line to the coverage ledger for any file containing IPC unpack code
or auth vtable implementations:

```
  IPC unpack / auth vtable validation traced: yes/no (or N/A)
```

<!-- END ocserv extensions -->
