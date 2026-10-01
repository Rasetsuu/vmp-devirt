# Roadmap: trace-assisted VMP devirt → verified re-execution

Status: research platform ~75%. Each phase lists dependencies,
done-criteria, and current position. Order is by leverage:
proof first, automation second, research arcs last.

## Phase 1 — Proof closure (active)

### 1.1 Runnable rebuilt binary [PROVEN modulo wall-clock]
- Depends: lifted objects (done, 7012/7012), branch conditions (done),
  dispatch tables (done).
- Work: ABI stitching — entry driver initializing Remill State from a
  recorded entry snapshot, dispatch loop over lifted blocks, import
  stubs for the binary's IAT (port tracer's stub table), exit with
  guest RAX compared against ground truth (`solo_add(40,2)` => 42).
- Done when: rebuilt binary runs headless and returns 42 with no
  Unicorn in the loop.
- Note: replay proves the lifted code correct; this proves it
  stands alone.

### 1.2 Sweep completion [IN PROGRESS: 1650/2095 forged, 16056 addrs banked]
- Depends: force_edge + guard + promotion (all built).
- Work: forge remaining ~1945 single-path jcc sites (batches in
  background), promote new fetch sites, re-mine.
- Done when: candidate list exhausted or marginal yield < 1% for
  two consecutive batches of 100.

### 1.3 Miner v3 [DONE static; live shapes open]
- Depends: live-capture promotion (built).
- Work: `and`-key-mix shapes (`and r8b,r9b` observed live, unmined),
  16-bit dst edge cases in the Rust miner, call-depth-2 follow.
- Done when: static 40-site samples mine >= 35/40 on all four modes.

## Phase 2 — Automation (queued)

### 2.1 Handler-body synth v1 [CORE BUILT, oracle hook queued]
- Depends: handler extents + I/O pairs (have both: dispatch tables,
  hits regs, memlog).
- Work: `backend/synth.rs` — enumerative search over the 8-op chain
  alphabet, z3/concrete equivalence against observed pairs.
- Gate zero: re-derive `Neg->Not->Neg->Ror1` at `0x140eb8c73` from
  I/O pairs alone. Then aim at unmined call-hidden bodies.
- Done when: synth solves >= miner on the 40-site samples with zero
  hand rules for shapes.

### 2.2 Coverage loop closure [WRAPPER + PERTURBATION DONE]
- Have: learn (flip-regions) -> force (+guard) -> mine -> merge,
  each proven separately; 8377 forced addrs banked, 28/48 promo mine.
- Missing: automatic promotion audits (fetch re-mining inside new
  code runs by hand today), derailment-guard tuning per target.
- Done when: one command runs learn->force->mine->merge and reports
  net-new handlers without manual steps.

### 2.3 Publish [READY, needs owner]
- Repo audited (no binaries/targets, no hardcoded user paths — all env-driven, MIT + dependency notes, CI).
- One command: `gh repo create vmp-devirt --public --source=. --push`.
- Blocked on: owner account action only.

## Phase 3 — Research arcs (unstarted)

### 3.1 Key-schedule recovery (idea 1, master key) [v1 FALSIFIED, reframed]
- v1 (visit-order sequences) dead: key reg takes 90 distinct values
  over 2357 visits, aperiodic — clobbered by other handlers between
  visits, so no per-site visit-index schedule exists.
- Correct frame is taint: key bytes derive from pool/stack slots via
  load chains (miner captures the loads); track sources + update
  functions with Triton taint through handler blocks. Queued behind
  synth oracle work (same I/O pairs).

### 3.2 v1/v2 frontend depth (parked by owner)
- Thin scanners exist; needs the trace treatment 3.x got.
- Blocked on samples (no protectors for 1.x/2.x automation).

### 3.3 Second target family [STARTED, blocked; DIVERSITY PLAN ADDED]
- Diversity experiment (priority when unblocked): a SECOND 3.9.x build
  of the same source with different mutation/virtualization settings,
  then ask how much of the pipeline survives unchanged (no new rules).
  Then 3.10.x the same way. One different sample teaches more than
  ten synthetic same-build binaries.
- 3.8.1 research binary fetched (VEXA tests dir) to data/vmp381.
  `scan` detects vmp3-fdj; trace died at an RVA jump to `0xd536`.
  ALIAS_RVA lands (+2 uniq) but target is unbound import RVA:
  entry thunk `jmp [rip+0x57e2]` reads slot value `0xd536` (never
  relocated — VMP's loader didn't run under emulation). TEB/PEB +
  IAT fallback + SPARSE_HI all in place and change nothing. Needs
  loader emulation (import binding/decryption flow), a per-target
  RE project. Parked. Themida: zero work.

## Phase 4 — Vision (not scheduled)

Canonical recovered-machine IR (`VM_LOAD/STORE/PUSH/POP/ADD/...`) with
per-protector frontends (VMP, Themida, Tigress) feeding one backend.
Recorded from external review; premature before Phase 1-2 solidify.

## Non-goals (standing)
Cheat creation/porting/operation, private servers, running bots,
universal push-button claims. Analysis-only, factory-first evidence.
