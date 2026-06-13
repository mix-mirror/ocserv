<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) PromptKit Contributors -->

---
name: stack-lifetime-hazards
type: taxonomy
description: >
  Classification scheme for stack lifetime and memory escape hazards
  at system boundaries (e.g., driver ↔ framework, kernel ↔ userspace).
  Use when investigating stack corruption, use-after-return, or
  pointer lifetime violations across API boundaries.
domain: memory-safety
applicable_to:
  - investigate-bug
  - investigate-security
  - review-code
---

# Taxonomy: Stack Lifetime Hazards

Use these labels to classify findings when analyzing code for stack
lifetime violations at API or component boundaries. Every finding
MUST use exactly one label from this taxonomy.

## Labels

### H1_STACK_ADDRESS_ESCAPE

Evidence that the address of a local variable (or a pointer into a
local stack buffer) is passed across the boundary.

**Pattern**: `&local_var` or pointer arithmetic on a stack array is
passed as an argument to a cross-boundary function call.

**Risk**: If the callee stores the pointer or uses it after the caller
returns, the pointer is dangling.

### H2_STACK_BACKED_FIELD_IN_ESCAPING_STRUCT

A struct passed across the boundary contains a field whose value was
assigned from stack storage (directly or indirectly).

**Pattern**: A struct is populated on the stack, one of its fields
points to another stack variable or stack buffer, and the struct is
passed to a cross-boundary call.

**Risk**: Even if the struct itself has appropriate lifetime, individual
fields may point to dead stack frames.

### H3_ASYNC_PEND_COMPLETE_USES_CALLER_OWNED_POINTER

Evidence that a pointer (or struct containing pointers) can survive
beyond the current stack frame due to async pend→complete, queuing,
or callback completion.

**Pattern**: A pointer from the caller's frame is stored in a context
object, global, list, work item, or completion record. The callee may
return STATUS_PENDING and complete the operation asynchronously, at
which point the original stack frame is gone.

**Risk**: The completion path dereferences a pointer to a stack frame
that no longer exists.

### H4_WRITABLE_VIEW_OF_LOGICALLY_READONLY_INPUT

The call site passes a writable pointer to data that is logically
input-only, and later code assumes the data has not been modified.

**Pattern**: A `const`-qualified or logically-read-only buffer is
passed via a non-const pointer to a cross-boundary function. The caller
continues using the data after the call, assuming it is unchanged.

**Risk**: A buggy callee (e.g., third-party driver) may write through
the pointer, corrupting data the caller relies on.

**Note**: Only flag when the code implies an assumption of immutability.
Do NOT assume callees are well-behaved.

### H5_UNCLEAR_LIFETIME_NEEDS_HUMAN

Pointers cross the boundary but lifetime and ownership cannot be
proven safe from the locally visible code.

**Pattern**: The analysis cannot determine whether the memory is stack,
heap, pool, or statically allocated — or the ownership transfer
semantics are ambiguous.

**Action**: Provide the evidence, state what is unclear, and list
the specific additional code/files that a human must inspect to
resolve the ambiguity.

## Ranking Criteria

Order findings by likelihood of stack corruption impact:

1. **Highest risk**: H1 and H3 with clear evidence and minimal ambiguity.
2. **High risk**: H2 with clear field assignment from stack.
3. **Medium risk**: H4 when assumptions about immutability are implied.
4. **Lowest risk**: H5 (unclear lifetime — needs human follow-up).

## Usage

In findings, reference labels as:

```
[HAZARD: H1_STACK_ADDRESS_ESCAPE]
Location: <file>:<line>
Evidence: <code excerpt showing the stack variable and boundary call>
Reasoning: <why this is a lifetime escape risk>
```

<!-- END PromptKit base -->

---

<!-- BEGIN ocserv extensions -->

## ocserv-Specific Extensions

ocserv has no shared-memory threading, so the classic "thread A's stack
freed while thread B still holds a pointer to it" scenario does not occur
directly. The boundaries where these hazards apply instead are: PCL
coroutine switches within a worker, libev callback registration in
main/sec-mod, and serialization at the IPC boundary.

### H1_STACK_ADDRESS_ESCAPE — ocserv boundaries

- A pointer to a stack buffer passed as the `void *data` argument to
  `ev_io`/`ev_timer`/etc. callback registration (`src/main.c`,
  `src/sec-mod.c`) escapes if the registering function returns before the
  event fires — the callback then dereferences a dead stack frame.
- A pointer to a stack buffer passed into `co_call()`/`co_resume()` (PCL,
  `src/pcl/`) escapes if the target coroutine retains the pointer past the
  point where the originating coroutine's frame is reused.

### H2_STACK_BACKED_FIELD_IN_ESCAPING_STRUCT — ocserv boundaries

- A protobuf-c message struct (`*ProtobufCMessage`, from `src/ipc.proto` /
  `src/ctl.proto`) with a `char *`/`bytes` field pointed at a stack buffer,
  passed to `*_pack()`/`*_pack_to_buffer()`. Packing is synchronous in
  ocserv, so this is usually safe — but flag as H2 if the pack call is
  deferred (e.g., queued for a later libev iteration) rather than immediate.
- A `worker_st`/`main_server_st`/`proc_st` substructure (see `vpn.h`,
  `main.h`) populated with a pointer to a stack-allocated buffer and then
  stored via `talloc_steal` into a longer-lived talloc context — the
  stack buffer's lifetime does not match its new talloc parent's.

### H3_ASYNC_PEND_COMPLETE_USES_CALLER_OWNED_POINTER — ocserv boundaries

- libev is ocserv's async completion mechanism in main/sec-mod. Any
  `ev_*_start()` call whose callback closure captures a pointer into the
  registering function's stack frame is H3 if the function can return
  (and its frame be reused) before the watcher fires.
- PCL coroutines that are suspended (`co_resume` returns control to the
  scheduler) while holding a pointer to the suspending coroutine's stack
  are H3 if another coroutine can run and reuse that memory before resumption
  — verify against PCL's actual stack allocation model in `src/pcl/` before
  concluding this is exploitable; PCL stacks are typically heap-allocated
  per coroutine, which would make this `H5` instead (verify, do not assume).

### H4_WRITABLE_VIEW_OF_LOGICALLY_READONLY_INPUT — ocserv boundaries

- Config option strings parsed by `inih` (`src/inih/`) and stored in
  `cfg_st`/`perm_cfg_st` (`common-config.h`) are logically read-only for the
  lifetime of the config. Flag any code path that takes a non-`const char *`
  to one of these fields and passes it to a function known (or suspected)
  to modify its argument in place (e.g., `strtok`, in-place URL-decoding).

### H5_UNCLEAR_LIFETIME_NEEDS_HUMAN — ocserv guidance

- talloc ownership is the primary lifetime mechanism in this codebase. When
  a pointer's talloc parent cannot be determined from the visible code (e.g.,
  it was allocated with a NULL context, or `talloc_steal` is called
  conditionally), classify as H5 and state which `talloc_parent()` call or
  allocation site a human needs to inspect.
- For PCL coroutine stack allocation specifics, classify as H5 unless
  `src/pcl/` has been read to confirm the allocation strategy — do not assume
  PCL stacks behave like OS thread stacks.

<!-- END ocserv extensions -->
