# Design notes for in-flight features

These documents capture the **rationale** for in-flight or
explicitly-deferred work — motivation, design alternatives
considered, security implications, open questions. They are
intended to be useful to anyone landing on the project who wants
to understand *why* something is the way it is, including parts
that haven't been built yet.

What lives here:

- Design proposals for proposed features (`group-sharing`,
  `keyspaces-and-grants`).
- The `next-steps-backlog`, which records explicitly-deferred work
  with enough context to pick it up later.
- Design references for completed work whose rationale is still
  load-bearing (e.g. `bao-streaming-and-storage-simplification`,
  marked ✅).

What does **not** live here:

- **Step-by-step execution plans** ("Group A → Group B → run this
  command"). Active execution is tracked in GitHub issues; ad-hoc
  agent-driven execution state lives outside the repo.
- **Completed-phase plans.** Those move to [`archive/`](archive/).

If the document you're writing reads as a checklist, it should be
a GitHub issue, not a file here.
