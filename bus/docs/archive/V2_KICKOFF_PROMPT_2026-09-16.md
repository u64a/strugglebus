# StruggleBus v2: fresh-session kickoff

**Prepared:** 2026-09-16 (UTC+10)  
**Purpose:** Start the first baseline mini-sprint in a fresh CLI session when
the owner gives the kickoff prompt below. Preparing or reading this document
does not itself authorize execution.

## Saved handoff state

The owner explicitly paused before starting M0 and requested this handoff.
V2 work so far is documentation and design consultation only. **M0 and P0 have
not started.** No v2 metric baseline has been measured, no metric dependencies
or CI gates have been installed, and no v2 application features have been built.

At preparation, the checkout was on `main` at
`d8c51f6769aef5e609fa1512797593f7e98267dd`. Documentation is saved on disk but
uncommitted:

- Modified: `README.md` and `docs\DESIGN.md`.
- New: `docs\V2_REVIEW_2026-09-15.md`,
  `docs\V2_DESIGN_MAP_2026-09-16.md` and this kickoff document.

Use the same working checkout in the new session. Inspect its actual state;
do not reset, overwrite existing changes, or assume these files exist in a
different worktree or a fresh clone.

The [design map](V2_DESIGN_MAP_2026-09-16.md) is the agreed v2 product scope and
delivery-policy record. It supersedes speculative options in the earlier
[comparative review](V2_REVIEW_2026-09-15.md). The coordinator consultation is
complete: reply 2386 to question 2367 is summarized in the map. Do not repeat
that consultation or wait for another reply to start M0.

Some deployed-version statements in the existing README/DESIGN are dated.
They are not live inventory or a reason to inspect production during M0.
The repository's [safety rules](../../AGENTS.md) remain binding.

## Kickoff prompt

The owner can paste this into the fresh session, or explicitly request execution
of this section. It authorizes M0 only, not the full v2 roadmap.

```text
Start StruggleBus v2 mini-sprint M0 only: establish a trustworthy,
reproducible baseline of the existing system and its change risk.

First read:
1. AGENTS.md.
2. docs\V2_DESIGN_MAP_2026-09-16.md, especially the scope, progressive
   design responsibilities, mini-sprint/release model and section 7 policy.
3. The saved handoff state in docs\V2_KICKOFF_PROMPT_2026-09-16.md.
Then inspect the current Git state, pyproject.toml, uv.lock and the
relevant existing test/build configuration. Read relevant v1 design
sections when needed, rather than reconstructing old session history.

Preserve the existing uncommitted documentation. The earlier comparative
review is background, not permission to add deferred features.

Working principles:
- Deep, cohesive modules with simple public contracts; no framework
  project, speculative abstraction or meaningless helper extraction.
- Keep transport adapters thin and business/authority rules shared.
- Explicit states, safe retries, observable failures and testable
  side-effect boundaries.
- One demonstrable outcome per scope-based mini-sprint. Design only the
  relevant slice deeply enough; do not complete every D1-D9 design first.
- Keep the bus separate from coordinator workflow/execution authority.

M0 objective and authorized local work:
- Confirm the current test/build behavior and record the actual source,
  working-tree state, Python version and platform used.
- Choose the smallest maintainable, repeatable way to measure function
  complexity, automated coverage and CRAP. Reuse existing tooling where
  suitable; do not build a metrics platform.
- Local development-tooling, configuration, reporting tests and directly
  related documentation changes are authorized where needed. If adding
  development dependencies, keep pyproject.toml and uv.lock synchronized
  and avoid unrelated dependency upgrades.
- Establish the baseline before judging legacy hotspots. Do not turn
  pre-existing failures or high scores into an unrelated cleanup sprint.
- Use the repository's required sync/test/build commands, including
  uv sync --locked --all-extras, uv run pytest and uv build, after any
  necessary lock update. Report failures, skipped platform coverage and
  unavailable measurements plainly; do not claim unexecuted Python/Linux
  matrix results or access remote systems just to fill the matrix.

Approved quality policy for subsequent new/materially changed code:
- Cyclomatic complexity target: at most 10 per function; higher requires
  review and a recorded justification or meaningful simplification.
- CRAP target: at most 15 per function. Above 15 and below 30 requires
  explicit review. At or above 30 blocks merging without an approved,
  justified exception.
- Branch coverage target: at least 90% for new/materially changed
  production logic, with explicit exceptions below it. Relevant
  authorization, freeze and recovery failure-path tests remain mandatory.
- API simplicity is reviewed separately; good function scores do not
  excuse complex caller protocols, weak assertions or lost atomicity.
- Baseline legacy code; do not silently grandfather new debt or require
  a wholesale legacy rewrite.

Measurement requirements for this sprint:
- Document the actual coverage basis and function mapping. The original
  CRAP formula uses basis-path coverage; label any tooling adaptation
  rather than implying identical measurements.
- Use CRAP = C^2 * (1 - T)^3 + C, with coverage T as a fraction for the
  function, not a repository-wide coverage percentage.
- Define branchless-function treatment, changed-code denominator and
  scope exclusions. Missing data must not look like a passed gate.
- If implementing reporting glue, verify calculations and function
  mapping with small known cases. C=10 gives CRAP 110 at zero coverage
  and 10 at full coverage.
- Report individual hotspots and useful distributions, not just an
  average. Keep raw generated reports ignored or in session artifacts;
  save a concise, reproducible baseline summary and artifact locations.

Boundaries:
- Do not start P0, M1 or any application feature implementation.
- No CI workflow changes or blocking CI enforcement in M0.
- No schema/production configuration changes, live-bus access, credential
  discovery, production investigation, deployment, release or tagging.
- No commits, pushes, factory runs or cross-repository implementation.
- Preserve LAN-only service, credential handling, freeze/local recovery,
  existing ordering and client behavior. Do not weaken a guard for a score.
- Do not install dependencies speculatively: change the relevant manifest
  for the selected tooling, or establish a missing-tool/dependency failure
  first, consistent with repository instructions.

Done means:
1. Another session can reproduce the baseline with documented commands.
2. The report identifies the exact measured environment, coverage basis,
   current test/build results, function-level risk hotspots and limitations.
3. Reporting/calculation changes, if any, have appropriate focused evidence.
4. Only the minimum local tooling/configuration/docs changes were made;
   the application behavior and production environment remain untouched.

Stop after M0 and present the baseline, changed files and remaining risks.
Do not automatically continue into feature work or the separate early
GHCP capability probe. Existing legacy debt does not by itself make M0
incomplete; an unreliable or unreproducible report does.
```
