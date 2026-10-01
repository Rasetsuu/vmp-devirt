# Roadmap: trace-assisted VM reconstruction → verified re-execution

Status: VMP 3.9 core proven (see `docs/coverage.md` for numbers).
Each item lists dependencies and done-criteria. Order is by leverage:
proof first, generalization second.

## Done (evidence in `docs/coverage.md`)

- Fetch discovery (executed-watch beats static on SMC targets).
- Per-site cryptor mining (v5 identity-filtered) + VTIL-rule
  canonical simplifier cross-check (`devirt synth`).
- Dispatch tables + handler extents (cross-validated both directions).
- Branch conditions 5/5 (`branch_solve.py` post-state ZF rule).
- Forcing sweeps + coverage promotion (forced-only addrs banked).
- Remill lift → `opt -O3` → `llc` (7012/7012) + lockstep replay
  fidelity (regs + memory identical modulo wall-clock bytes).
- Saturn-subset brightening (const-pool + stack slots; pool does not
  fire on 3.9 — documented negative result).
- Diversity: fresh same-source rebuilds survive the static pipeline
  unchanged (`scripts/diversity/` recipe, no new rules).

## Active

### Runnable rebuilt binary [proven modulo wall-clock]
- Depends: lifted objects, branch conditions, dispatch tables (done).
- Work: ABI stitching — entry driver initializing Remill State from a
  recorded entry snapshot, dispatch loop over lifted blocks, import
  stubs for the binary's IAT, exit with guest return value compared
  against ground truth from the unprotected build.
- Done when: rebuilt binary runs headless with no Unicorn in the loop.

### Second protector family (Tigress) [next]
- Why: same analysis loop against a different machine tests whether
  the methodology is protector-independent (VMP-only results cannot).
- Tigress is the cheap second family: academic/free, Linux-native,
  scriptable, seeded diversity, source-level ground truth for
  precision/recall scoring of handler recovery.
- Carry-over as-is: Remill lift, replay + lockstep diff, dispatch
  learning, forcing, synth. New per-protector frontend required
  (fetch shapes, environment models); backend stays shared.
- Order inside: literature (VPC identification, MBA simplification)
  → factory mirror of the VMP corpus → survival scoring, same table
  as the VMP diversity ledger.
- Done when: a Tigress frontend reports fetch sites, mined chains,
  and replay equivalence on at least two dispatch modes.

## Parked (labeled, not dropped)

- **Key-schedule taint.** Visit-order schedules falsified (key regs
  aperiodic across visits — clobbered between handlers). Correct
  frame is taint from pool/stack load chains through handler blocks.
  Real research item; queued behind protector-2 work.
- **Older/newer VMP versions.** Static pipeline is version-shaped;
  foreign samples die in loader/import emulation before VM code.
  Needs loader-emulation (import binding/decryption flow) as a
  per-target RE project. Revisit with snapshot-from-live-process
  ingestion (`harness::capture` design) rather than file loading.
- **Commercial protectors with loaders/anti-debug.** Same ingestion
  wall, harder. After two families work and the IR boundary is
  honest — otherwise special cases pile up disguised as abstractions.

## Vision (not scheduled)

Canonical recovered-machine IR (`VM_LOAD/STORE/PUSH/POP/ADD/...`)
with per-protector frontends feeding one backend. Premature before
two families exist; the IR vocabulary must emerge from evidence.

## Showcase corpus (planned: after Tigress family lands, before push)

Public end-to-end proof on targets we own outright: a benign demo
(small game or DLL exercising arithmetic + branches + loops + calls
+ memory — the factory suite's five shapes) protected with every
available VMP version × mode (Mutation/Ultra/Virtualization) ×
options (packing, anti-debug) plus Tigress (≥2 dispatch modes),
each fully devirtualized with this pipeline to replay equivalence.
One matrix: rows = protections, columns = pipeline stages, cells =
measured numbers. That table — not claims — is the release proof.
`docs/coverage.md` pushes with it (held local until then).

## Non-goals (standing)

Cheat creation/porting/operation, private servers, running bots,
universal push-button claims. Analysis-only, factory-first evidence.
