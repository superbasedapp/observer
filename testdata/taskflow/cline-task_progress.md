# cline `task_progress` — reference shape (NOT decoded)

Cline's Focus Chain (shipped v3.25, removed in Cline 4.x) is a
`task_progress` **parameter** riding on every tool call, not a
standalone (tool, raw_tool_name)-keyed call — a third capture shape
class internal/taskflow's decoder table cannot represent (see
docs/task-tracking.md "Deferred: cline's task_progress parameter").
This fixture exists only so the shape is documented somewhere in
`testdata/`; no decoder table entry references it, and
`internal/taskflow.Decode` never sees it.

Reconstructed from the vendor system prompt (github.com/cline/cline,
`src/core/prompts/system.ts` @ v3.25.0) and the on-disk
`focus_chain_taskid_<id>.md` format — no live populated instance was
found on the grounding operator's box (60 occurrences of the string,
all the injected system reminder, 0 populated).

The value is a raw Markdown checklist string with exactly two line
prefixes — there is no in-progress marker:

```
# Focus Chain List for Task 17
- [x] Reproduce the crash locally
- [x] Add a regression test
- [ ] Fix the null check in the parser
- [ ] Open a PR
```
