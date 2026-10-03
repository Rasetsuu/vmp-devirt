# Coverage: factory ground truth + protection modes

All numbers from instrumented Unicorn snapshots (`trace_open_fetch`)
on self-built VMP 3.9.4 factory binaries. No target binaries here;
reproduce with your own licensed samples.

## Fetch discovery (execution-first, not spelling-first)

Primary sensor: executed byte-loads under Unicorn (which register feeds
a load that actually fires). Static pattern scans seed the watchlist
only. Measured: static-only pattern hits execute at 0% on hardened
targets; the executed watch is what mines.
Shape coverage: `movzx` ✓ / `movsx` ✓ (SMC flips `B6↔BE` mid-run, miner
accepts both) / and-gated + co-byte fetches ✓ (live capture,
`mine-live`/`mine-hits`). Uncovered shapes (e.g. string-op fetches):
open an issue with opcode bytes around the fetch — each becomes a
miner case. No chain in this repo assumes fetch == one mnemonic.

## Function coverage (VMP 3.9.4 Virtualization, default)

| Binary | Entry | Hits | End RIP | Note |
|---|---|---|---|---|---|
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
**5 perfect** (2202/2202, 88/88, 3996/3996, 779/779, 100/100).
Pushan-inspired post-state rule: hit regs are post-writer, so ZF for
reg-destination writers (`dec r9` + `jne`) reads straight from the
snapshot instead of re-applying the writer (old code double-counted,
2 misses at counter wrap). Pure writers (`cmp`/`test`) unchanged.

## Chain verification (one-site consistency + differential)

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

| Mode | v1 | v4 | v5 (identity-filtered) | Key regs |
|---|---|---|---|---|
| add2 (Virt) | 22 | 25 | **23** | r10l, dil, r11l |
| Mutation | 20 | 25 | **21** | sil, bl, dil&, r8l |
| Ultra | 28 | 32 | **29** | r10l, sil, dil, bpl |
| Virtualization | 29 | 32 | **29** | r9l, sil, r8l, r11l |

v5 drops junk identity chains (fewer, truer — the verified rate).
`devirt synth`: simplification check over mined chains — 19/19 agree.
VTIL-rule canonicalizer (ported linear subset of
`VTIL-SymEx/simplifier/directives.hpp`, BSD-3, attributed in
`src/backend/synth.rs::simplify_chain`) beats subset-deletion search
on 3 sites (5→4, 4→3, 3→1 where search found nothing) — proof the
rule donor carries weight past our lifter.

Unmined remainder: encrypted-handler bytes (no chain visible
statically) + deep call-hidden shapes — live mining
(`mine-live`/`mine-hits`) covers those where hit-time code exists
(cross-check on `0x140eb8c73`: file, overlay, hit-time agree —
key=dil, Neg→Not→Neg→Ror1).
Key-register sets differ per mode: per-mode mining is required, a
single watchlist/cryptor does not transfer.

## Diversity (same source, fresh VMProtect 3.9.4 builds, zero new rules)

`scripts/diversity/` (templates + recipe; binaries local-only):
repro (defaults re-run), divA (packing project), divB (renamed VM section).
All compute `done e38e3794`. Pipeline run unchanged:

| Binary | Scan sites | Mine /40 | Synth agree |
|---|---|---|---|
| vmp_add2 (ship) | 500+ (cap) | 23 | 19/19 |
| repro | 500 (cap) | 30 | 24/0 |
| divA (2.5MB) | 212 | 25 | 22/0 |
| divB (2.5MB) | 207 | 22 | 22/0 |

## Version matrix (same source, user-built per version, zero new rules)

| Build | Scan | Mine /40 | Synth agree | Fetch @ mined sites |
|---|---|---|---|---|
| 3.8.0 | 236 | 18 | 14/0 | movzx/movsx |
| 3.8.7 | 565 | 28 | 26/0 | movzx (eax/edx-heavy) |
| 3.9.4 ship | 500+ | 23 | 19/19 | movzx/movsx |
| 3.9.6 | 440 | 23 | 21/0 | movzx 21/21 |
| 3.9.6 costum | 1311 | 11 | 9/0 | same alphabet |

## Older versions (same source, collection engines, zero new rules)

| Build | Scan | Mine | Synth | Fetch @ mined |
|---|---|---|---|---|
| 3.3.1 licensed | 16 | 10/40 (9 chains) | 7/0 | movzx/movsx |
| 3.5.0 | 16 | 9/40 (8 chains) | 8/0 | movzx 8/8 |
| 3.9.6 ultra (mut+virt+antidbg max) | 352 | 24/40 | 24/0/0 | movzx 24/24 |
| 3.2.0 ultra (same max) | 0 | 0/40 | — | observation: no strict sites (mechanism unidentified) |
| 3.2.0 no-debug x4 (0/virt/mut/ultra) | 1 each | 0 mined (3 false-pos, 1 empty steps=0) | — | observation: antidebug shifts strict count 0→1, miner still 0; responsible fetch/VM-state representation not yet identified (negative control, see §3.2 lead) |

## 3.2 dispatch census (traced, not hypothesized)

Same capture flow both versions (entry-mode Unicorn, loose-`movzx` watches):

| Version | Trace steps | jmp-reg/call-reg sites | Dispatch shape |
|---|---|---|---|
| 3.9.6 default | 73123 | 511 | register-indirect (`jmp reg`) — current anchors catch all |
| 3.2.0 ultra | 12355 | 0 | memory-indirect: `jmp qword ptr [r12+r14*8]` @ `0x1402947d7`, 617 execs, 31 targets — anchors catch 0 |

3.2's top executed fetch *is* `movzx r14d,[rsi]` @ `0x140294526` (618 execs) feeding `r14` = the dispatch index, but `mine` rejects it (no 3.x-style key-mix chain after). So the 3.2 gap is two concrete missing pieces, not a mystery: (1) `jmp-mem` anchors with base+index seeds, (2) post-fetch transform shape. Census data: `data/work/vmp320/`, `data/work/vmp396/` (local-only, not in repo).

## 3.2 model recovered (617/617 visits, traced)

No post-fetch transform exists — 3.2 is direct-threaded, raw byte to table:

| Step | Instruction | Role |
|---|---|---|
| fetch | `movzx r14d,[rsi]` @ `0x140294526` | index byte, base `rsi` (VPC) |
| dispatch | `jmp [r12+r14*8]` @ `0x1402947d7` | 31 targets, table base `r12` |
| advance | `sub rsi,1` ×2 per cycle | VPC walks backward (stride med=-2) |

`byte → handler` through the live table: **617/617 exact**. Two traps that look like crypto and aren't: the table base is 72 bytes below the min observed read (min byte value was `0x09`, not index 0), and file bytes past the true table end are a different structure (reads as garbage — confirm against the *live* snapshot, not the file). `mine` rejecting 3.2 sites is correct behavior (nothing to mine); table-mapping is the 3.2 "decode".
| 2.0.5 demo | v1-gate true, v3-fdj 2 false-pos (miner rejects) | — | — | v2-table needs table scan check |
| 2.12.3 / 2.13.5 | v2-table true (287-entry RVA run in .vmp1, validated) + v1-gate true | — | — | first v2 frontend hit; v3-fdj candidates don't mine (correct reject) |
| 2.13.8 ultra | all false (VM packed: 1 file-backed VM section) | — | — | needs trace, not static |
| 1.54 | v1-gate true (1 gate `.text→.vmp1`, byte-verified) | live: gate execs once, trace enters VM @ `0x140178bf`, returns to `.text` (614 steps) | — | Immediate32to64 fix (matcher was dead); target-filtered scan |
| 1.70.4 | v1-gate false (4 dropped: all inside `.vmp2`, VM-internal pairs) | 0 execs in 53k-step trace | — | stubs-only scope; would need trace (packed stubs) |
| 1.7 x32 (fair-era input, runs `done e38e3794`) | v1-gate false (132 VM-internal pairs excluded; 6 of first 7 were 64-bit-misdecode phantoms) | — | — | bitness-aware decode added; packed `.text` needs 32-bit tracing (harness gap: Unicorn MODE_64 + 64-bit decoders only) |

3.5.0 is Pushan's exact version: our static miner covers its fetch
shapes with the same rules as 3.9.6 (their static-region assumption
is what differs, not the cryptors). 2.0.5 needs the table frontend;
its sections prove protection took (`.vmp0`, `/4`, `/18`).

Higher complexity multiplies code surface (3x sites), not crypto:
same key regs, same step shapes, synth 9/9. Mine-rate dip is sample
composition (first-40 lands in junk regions), not harder chains.

Key-reg alphabet same, weights reshuffled per build (repro r11l/r9l,
divA r9l-heavy, divB dil/bl) — VMP re-randomizes every protection
(repro ≠ shipped bytes). VTIL rules compress chains on all three
fresh binaries. Miner/synth transfer with no changes; trace stages
(branch/brighten-corpus/replay) queued per binary on demand.

## Saturn-subset brightening

`devirt brighten` (`src/backend/brighten.rs`): constant-pool folding +
RSP-concretized stack-slot recovery over Remill IR text (Saturn's two
moves, per-BB form; full CFG-shell global→alloca loop queued).
300-file sample: **0 folds** (post-opt reads are State-dynamic; VMP 3.9
keeps constants in the VM stream, not PE .rdata — Saturn's pool
assumption does not fire here, tool validated by unit test), **110
slots in 55 files, all `rsp+0 w=4 rd+wr`** — uniform VM stack-top
32-bit spill idiom. Pool restricted to loader-static sections
(.rdata/.pdata/.reloc/.buildid; .text/.data/VMP sections excluded —
SMC/IAT-stale, same caveat as Pushan S1). RSP-symbolic slots need no
concrete RSP; RSP+huge offsets rejected as dynamic indices.
