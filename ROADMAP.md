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

### 1.2 Sweep completion [OPEN, compute only]
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

### 2.1 Handler-body synth v1 [UNBUILT]
- Depends: handler extents + I/O pairs (have both: dispatch tables,
  hits regs, memlog).
- Work: `backend/synth.rs` — enumerative search over the 8-op chain
  alphabet, z3/concrete equivalence against observed pairs.
- Gate zero: re-derive `Neg->Not->Neg->Ror1` at `0x140eb8c73` from
  I/O pairs alone. Then aim at unmined call-hidden bodies.
- Done when: synth solves >= miner on the 40-site samples with zero
  hand rules for shapes.

### 2.2 Coverage loop closure [PARTIAL]
- Have: learn (flip-regions) -> force (+guard) -> mine -> merge,
  each proven separately; 2293 forced addrs banked.
- Missing: automatic promotion audits (fetch re-mining inside new
  code runs by hand today), derailment-guard tuning per target.
- Done when: one command runs learn->force->mine->merge and reports
  net-new handlers without manual steps.

### 2.3 Publish [READY, needs owner]
- Repo audited (no binaries/targets, MIT + dependency notes, CI).
- One command: `gh repo create vmp-devirt --public --source=. --push`.
- Blocked on: owner account action only.

## Phase 3 — Research arcs (unstarted)

### 3.1 Key-schedule recovery (idea 1, master key)
- Goal: reverse the rolling-key schedule so unexecuted bytecode
  decrypts statically — converts the coverage wall into a static
  problem. Highest leverage, hardest. Needs cryptor corpus (have).

### 3.2 v1/v2 frontend depth (parked by owner)
- Thin scanners exist; needs the trace treatment 3.x got.
- Blocked on samples (no protectors for 1.x/2.x automation).

### 3.3 Second target family
- 3.8.1 research binary available (VEXA tests dir); Themida: zero
  work, no claims. Proves version-generality of the loop.

## Non-goals (standing)
Cheat creation/porting/operation, private servers, running bots,
universal push-button claims. Analysis-only, factory-first evidence.
