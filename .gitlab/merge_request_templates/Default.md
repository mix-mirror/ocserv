## Intent
<!-- 2–3 sentences: the problem (link the issue) and the approach.
     Please keep it to one paragraph. Details, test notes and open
     questions fit better in a comment, where they can be discussed. -->

Relates/Resolves: #

## Scope
<!-- How this MR fits the issue and the discussion in it. If it covers
     only part of the problem, or changes something beyond it, say so
     here so everyone sees it up front. -->

- **Leaves open:** none   <!-- parts of the issue this MR does not address, e.g. for a follow-up -->
- **Also changes:** none   <!-- anything beyond the issue: new dependency, option, rejected configuration, behavior change -->

## Checklist
<!-- Tick what applies. If an item is unclear or doesn't fit, ask in a comment. -->
 * [ ] Intent and Scope filled in; anything left open or also changed is listed under **Scope**
 * [ ] CI passes (review starts once it is green)
 * [ ] Every commit has `Signed-off-by: Name <email>`
 * [ ] `ninja -C build` succeeds after each commit, not just at the final one
 * [ ] `Resolves: #NNN` on a commit that fully fixes an issue; `Relates: #NNN` for partial fixes, tests or docs
 * [ ] `clang-format --dry-run -Werror` passes on all modified files under `src/` and `tests/`
 * [ ] Both a positive test (correct behavior) and a negative test (bad input rejected)
 * [ ] Tests are self-diagnosing: a CI failure is explainable from the log output alone
 * [ ] New tests registered in `tests/meson.build`
 * [ ] No new Linux-specific syscalls without `#ifdef __linux__` guard
 * [ ] Documentation updated / NEWS entry present (for non-trivial changes)

## Reviewer's checklist
 * [ ] CI is green
 * [ ] Scope: the MR matches the issue and the direction in its discussion, or each difference is listed under **Scope** and agreed; settle scope before reviewing the code
 * [ ] Description is short and the scope is clear; if not, ask the author to trim it
 * [ ] All commits carry `Signed-off-by:`
 * [ ] `Resolves:`/`Relates:` matches what the MR covers (partial scope uses `Relates:`)
 * [ ] Every changed line relates to the stated change; unrelated cleanups can go in their own MR
 * [ ] Both a positive and a negative test exist and are registered in `tests/meson.build`
 * [ ] Memory: `talloc` used throughout; every allocation return checked; error paths use `goto cleanup`
 * [ ] Any change to a cross-process privilege boundary is called out for discussion
 * [ ] New worker code: no new syscalls without a corresponding seccomp filter update
 * [ ] Config/doc/test triangle consistent: new options present in `sample.config`, man page, and a test
 * [ ] Comments explain *why*, not *what*; new headers have correct guards (`#ifndef PATH_H`)
 * [ ] Documentation updated and NEWS entry present for non-trivial changes
