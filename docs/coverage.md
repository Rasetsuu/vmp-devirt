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

## Forcing (idea 2 v1 + v2 sweep)

v1 (`force_edge`, `vmp_devirt_prod` `6fb9a40`): forcing the observed
fall-through proved mechanics with 0 new code — expected.

`scripts/force_sweep.py`: 2095 single-path jcc sites enumerated from
the baseline trace (full-trace, not watch-limited); top-30 hottest
forced once each to the structural alternative (`FORCES=1`).
Unguarded: **546** forced-only addrs (~411 genuine untaken-path code,
~135 derailment scribble from 2 escaped runs, 2/30 stale-SMC 0-force).
Guarded re-run (`KNOWN_BIN`/`DERAIL_MAX=128`): **489**, derailers
truncated early (e.g. `jp` 2M steps→stopped at guard trip).
Derailment is nondeterministic scribble run-to-run (63 vs 1.6M same
command) — the guard keeps the deterministic prefix and drops chaos.
Promotion scan found **0** fetch sites in new code: final-dump bytes
are the wrong source (SMC re-encrypted); promotion needs live
hit-time capture in `force_edge` (queued). `forced.json` is now
valid JSON (was unquoted `res`).

## Per-mode cryptor mining

`devirt scan` detects vmp3-fdj on all four binaries (500+ strict sites
each, capped at display). `devirt mine` on 40-site samples (static
bytes; `mine` also accepts movsx — SMC flips B6↔BE):

| Mode | Mined | Key regs | Max chain | Note |
|---|---|---|---|---|
| add2 (Virt) | 22/40 | r10l, dil, r11l | 4 steps | e.g. Ror→Dec→Not→Xor |
| Mutation | 20/40 | sil, bl | 5 steps | sil-dominant, distinct keys |
| Ultra | 28/40 | r10l, sil, dil, bpl | 8 steps | longest chains, mixed keys |
| Virtualization | 29/40 | r9l, sil, r8l, r11l | 8 steps | r9l-dominant |

Unmined sites are call-hidden cryptors (`movzx; mov; call`):
miner v2 (`mine_cryptor_with`, call-follow depth-1, snapshot-overlay
reader) mines +3/40 on add2 static (22→25/40).
New CLI: `mine-live <snapdir> <site>` (overlay sections) and
`mine-hits <open_hits.json>` (hit-time code). Cross-check on
`0x140eb8c73`: file bytes, overlay, and hit-time agree
(key=dil, Neg→Not→Neg→Ror1). Distant call/jmp targets outside the
captured window stay unmined — full-section live dumps close that.
Key-register sets differ per mode: per-mode mining is required, a
single watchlist/cryptor does not transfer.
