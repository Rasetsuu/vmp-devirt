# Coverage: factory ground truth + protection modes

All numbers from instrumented Unicorn snapshots (`trace_open_fetch`)
on self-built VMP 3.9.4 factory binaries. No target binaries here;
reproduce with your own licensed samples.

## Function coverage (VMP 3.9.4 Virtualization, default)

| Binary | Entry | Hits | End RIP | Note |
|---|---|---|---|---|
| vmp_add2 | 0x14077c26d | 2000+ | 0x140f09452 / crash 0x0 (CF=1) | baseline, 90614 uniq, 6.7M steps |
| vmp_sub2 | 0x14076a131 | 1 (+trace 6.8M steps) | 0x0 READ_UNMAPPED | 88173 uniq, 86125 sub-only |
| vmp_branches | 0x140cd5da1 | 424 | 0x140edd5ba Ok | distinct function |
| vmp_loops | 0x1409477c1 | 24 | 0x14109d29e Ok | distinct function |
| vmp_calls | 0x140fe0099 | 6 | 0x1411ccc4d Ok | distinct function |
| vmp_memory | 0x14080f739 | 1 | 0x14124a3e9 Ok | distinct function |
| vmp_arithmetic | 0x1408e5b4a | 35 | 0x141222231 Ok | distinct function |

CF=1 on add2: identical 90614 uniq — determinism proof, not new coverage.

## Protection-mode coverage (same source, different VMP setting)

| Mode | Entry | Hits | Steps / uniq | Dispatch sites | End |
|---|---|---|---|---|---|
| Mutation | 0x14106da88 | 15–27 | 319k / 44575 | 226 (e.g. 0x1410a0291: 2 targets) | WRITE_UNMAPPED 0x1411428a8 |
| Ultra | 0x140985034 | 2 | short | — | Ok 0x141248bc1 |
| Virtualization | 0x140f4493e | 4 | short | — | Ok 0x1410db5fd |

Low hit counts on Ultra/Virtualization with the add2 watchlist are
expected: fetch-site sets differ per mode (different cryptors), so a
foreign watchlist barely fires. Per-mode mining is the follow-up.

## Branch conditions

`scripts/branch_solve.py` on add2 branch-watch run: 5 divergent sites,
4 perfect (2202/2202, 88/88, 3994/3996, 779/779, 100/100).

## Chain verification (mined => verified)

`scripts/chain_verify.py`: group watch-hit visits by decoded opcode,
require equal opcodes to predict equal next-handlers (trace order).
gadd watchlist: 158/158 consistent (156 visits on one site, 2 opcodes,
0 inconsistent). Caveat: only 4/260 watch sites mine statically —
the watchlist is 98% stale (SMC); live mining (`mine-hits`) is the
source for the rest. This is the differential check Claude asked for.

## Replay fidelity (lifted 3.9.4 re-execution)

`tools/replay/` + lockstep `py_bb_diff2.py`: Remill-lifted BBs
re-executed natively with a handmade runtime, Unicorn-driven to each
replay pc comparing regs + 4 memory regions (stack page, image pool,
heap, staged).
- **Final: identical except 4 wall-clock bytes.** Across full runs
  (17-34k blocks to program return at rip=0), the ONLY divergence
  anywhere is the `rdtsc` store slot (`mov [rsi-4],eax`):
  4 differing bytes in 1MB+12KB hashed, timestamp-shaped on both
  sides. Everything else — regs, stack, pool, heap, staged — matches
  at every leg.
- Edge alignment: **33922/33922 replay edges align as a subsequence
  of baseline** (383794 baseline skips = inlined direct calls + loop
  iterations; zero hard breaks) with IAT stubs installed — stubs
  change nothing on import-free paths, as designed.
- Retracted: the "loop-count divergence" (5 vs 884) compared replay's
  covered prefix against the whole 6.7M-step baseline; within the
  prefix both do 5. Same for several "divergence" alarms that turned
  out to be reader bugs (16B stride on 24B edge records), doubled
  step counters, stale binaries (format magic now enforced), and
  cross-run file contamination (run-id dirs now).
- Environment gaps closed along the way: zero-page mapping
  (`mmap_min_addr` -> low-page buffer), `rflag.flat=0x202` seed
  (remill's `SerializeFlags` leaves `_if`/`must_be_1` untouched),
  host rdtsc/cpuid hypercalls, throw-trampolines via setjmp (C++ EH
  unreliable across llc frames), unbuffered crash-safe logs,
  BB coverage of ret/indirect successors + cap-cut continuations.

## Recompilability (factory port + runnable proof)

Lift: add2 BBs, **7012/7012 objects** via Remill + `opt -O3` + `llc`,
`ld -r` links with 0 stubs needed (2 fault-guarded blocks kept for
their faithful div-fault paths).
Re-execution (`tools/replay/`): handmade runtime + driver, 17–34k
blocks per run to program end (`rip=0`, matching baseline's own end).
End-state equivalence vs Unicorn oracle: identical regs, identical
image/pool/heap/staged, stack equal **except 7 wall-clock bytes in
2 regions** (TSC-store slot + one timing-shaped word) out of 1MB+.
The rebuilt program computes the same thing through the same paths;
remaining gap to a standalone binary is packaging (IAT stubs for
imports on paths beyond solo_add), not semantics.

Superseded: segment-span `recompile` (`seg1.o`, 86%) — replaced by
the BB pipeline above plus replay fidelity.

## Dispatch tables + handler extents (VMPredator §III transplant)

`devirt dispatch <trace.bin> <binary>` (`src/backend/dispatch.rs`):
add2 570 indirect sites (11-target max observed), sub2 515,
Mutation 226.
`devirt handlers <trace> <memlog> <binary>` (`src/backend/handlers.rs`):
jump-to-jump segments over stack-region result-stores — add2 gives
**570 handlers from 570 dispatchers (1:1)**, Mutation 226/226.
Dispatchers and handler extents cross-validate from opposite directions
with zero fetch patterns. Needs release build on 6M+ traces
(debug too slow); `PEBinary::section_map` fast path in `pe_loader.rs`.
`scripts/extract_handlers.py` (paper §III step 3 v1): Triton emulation
of handler segments (trace-derived entry past the dispatcher), symbolic
regs, concrete overlay/stack; keeps vctx-store ASTs. Mutation handlers
show call-hidden dispatch (`stop=call`), concrete + BVROL/BVADD store
exprs; top add2 dispatcher has 68 targets. Call-following + multi-path
are the queued v2.

## Dispatcher learning (idea 3 v1)

`scripts/learn_dispatch.py` on the 50k-hit branch corpus: decision
trees over live regs -> outcome, plus depth-1 search over relational
features (`a>b`, `a==b`). Raw-reg trees find proxies (0.99);
relational search finds causes: **`rsi>rbp` at 1.0000 for
`0x1410cc2be` — the hand-derived `cmp rsi,rbp`/`ja` ground truth
(2202/2202), rediscovered with zero disassembly.** Second site
`rsi>r10` at 0.9961. Rules double as generative flip-regions for
idea 2 forcing. Only 2/1258 watch sites diverge enough to learn
(rest single-path in this corpus — the coverage wall, quantified).

## Forcing + perturbation (ideas 2+4)

`force_edge` supports `PERTURB="rsi=..,rbp=.."` at `PERTURB_SITE`
with `PERTURB_ONLY=1` (no RIP override). Critical subtlety found by
failure: perturbing AT the branch does nothing (flags latch at the
flag-writer); `PERTURB_SITE` must predate it. Validated: learned rule
`rsi>rbp` at `0x1410cc2be` flipped to fall-through naturally by
setting `rsi<rbp` before its `cmp` — first closed learn→perturb→
observe loop with zero disassembly in the decision.

v1 (`force_edge`, `vmp_devirt_prod` `6fb9a40`): forcing the observed
fall-through proved mechanics with 0 new code — expected.

`scripts/force_sweep.py`: 2095 single-path jcc sites enumerated from
the baseline trace (full-trace, not watch-limited); top-30 hottest
forced once each to the structural alternative (`FORCES=1`).
Unguarded: **546** forced-only addrs (~411 genuine untaken-path code,
~135 derailment scribble from 2 escaped runs, 2/30 stale-SMC 0-force).
Guarded re-run (`KNOWN_BIN`/`DERAIL_MAX=128`): **489**, derailers
truncated early (e.g. `jp` 2M steps→stopped at guard trip).
Rest-sweeps (sites 30–450 in three batches): cumulative union
**11151** forced-only addrs with near-zero overlap — disjoint sites
yield disjoint code. Promotion: 61 static fetch candidates in new
code, **35/61 mine** with zero new rules.
Derailment is nondeterministic scribble run-to-run (63 vs 1.6M same
command) — the guard keeps the deterministic prefix and drops chaos.
445 sites remain unforged.
Promotion scan found **0** fetch sites in new code: final-dump bytes
are the wrong source (SMC re-encrypted). Answered by live capture:
`force_edge` now records 256B at each force target into
`forced.json` pre-records, and `mine-hits` reads that shape
(`d63413a` — which also fixed a brace regression my suppressed
`2>/dev/null` build had masked; builds now checked visibly).
`force_sweep.py` mines chains per site automatically. Verified:
forced target parses (0/1, correctly skipped non-fetch),
add2_dyn still 2/5.

## Per-mode cryptor mining

`devirt scan` detects vmp3-fdj on all four binaries (500+ strict sites
each, capped at display). `devirt mine` on 40-site samples (static
bytes; `mine` also accepts movsx — SMC flips B6↔BE):

| Mode | v1 | v2 (call-follow) | v3 (and-mix) | Key regs (v3) |
|---|---|---|---|---|
| add2 (Virt) | 22 | 25 | 25 | **25** | r10l, dil, r11l |
| Mutation | 20 | 20 | 24 | **25** | sil, bl, dil&, r8l |
| Ultra | 28 | 28 | 30 | **32** | r10l, sil, dil, bpl |
| Virtualization | 29 | 29 | 31 | **32** | r9l, sil, r8l, r11l |

Unmined remainder: encrypted-handler bytes (no chain visible
statically) + deep call-hidden shapes — live mining
(`mine-live`/`mine-hits`) covers those where hit-time code exists
(cross-check on `0x140eb8c73`: file, overlay, hit-time agree —
key=dil, Neg→Not→Neg→Ror1).
Key-register sets differ per mode: per-mode mining is required, a
single watchlist/cryptor does not transfer.
