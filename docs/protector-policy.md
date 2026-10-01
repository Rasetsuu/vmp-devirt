# Protector policy: no regressions, both directions

This repo grows one protector at a time. Two guarantees, enforced by
`tests/golden.json` + `scripts/check_golden.py` (run before every push;
CI cannot run them — they need licensed/local samples):

## 1. New protectors never regress old ones

- Shared code (`backend/`, `pe_loader`, tracer core, CLI) changes must
  keep every golden number in `tests/golden.json`.
- Protector-specific behavior lives in frontends (`src/frontend/*`)
  or behind format/env gates (`fmt == Pe`, `FRAME_INIT`, `PLT_STUBS`).
  No `if tigress` / `if vmp` inside backend algorithms: generalize
  the algorithm (e.g. "any multi-successor site is a dispatcher")
  or put the special case in the frontend.
- Default runs without new flags must follow the old code path
  bit-for-bit (verify: re-run the affected golden before pushing).

## 2. Improvements propagate sideways

- A win found on protector B that applies to A gets ported, not
  forked: land it in the backend with per-frontend opt-in, extend
  the golden table with the improved number, note direction.
- Transfer log (both directions so far):

  | From → to | What | Status |
  |---|---|---|
  | VMP → Tigress | `dispatch_tables()` core, hit regs/traces/memlog shapes, branch learning (queued), replay (queued) | transferred, measured |
  | VMP → Tigress | tracer engine (snapshot/hooks/sparse) | transferred, 4 ingestion walls |
  | Tigress → VMP | PLT semantic stubs → generalize to IAT/GOT stub policy | queued |
  | Tigress → VMP | static bytecode regions → const-pool finally has targets | queued |
  | VTIL → all | `simplify_chain` linear rule subset | landed, wins on 4 VMP builds |
  | Pushan → all | post-state ZF (hit regs are post-writer) | landed, 5/5 branches |
  | Saturn → all | const-pool + stack slots (`brighten`) | landed, idiom found |

## 3. Tiers (what runs where)

- Tier 1 (CI, always): `cargo test` — unit tests over synthetic
  fixtures only. No samples, no network.
- Tier 2 (local, pre-push): `scripts/check_golden.py` — fast static
  checks (scan/mine/synth/dispatch) against `tests/golden.json`.
  Missing sample paths skip with warning, never fail.
- Tier 3 (local, on demand): full traces + replay. Too slow/costly
  for pre-push; numbers recorded in `docs/coverage.md` by hand.

## 4. Adding a protector (checklist)

1. New `src/frontend/<name>.rs` implementing `VmFrontend`; zero
   edits to existing frontends except trait changes.
2. Factory mirror (same logic, ≥2 modes) under local data dirs —
   never committed (binaries stay out).
3. Golden entries appended (measured, not hoped).
4. `check_golden.py` extended; full Tier 2 green before push.
