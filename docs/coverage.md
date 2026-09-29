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

## Dispatch tables

`devirt dispatch <trace.bin> <binary>` (see `src/backend/dispatch.rs`):
add2 570 indirect sites (11-target max observed), sub2 515,
Mutation 226.

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

Unmined sites (~30–50%) are call-hidden cryptors (`movzx; mov; call`,
miner stops at `call`) — known 3.9.4-b2285 shape, queued as miner v2.
Key-register sets differ per mode: per-mode mining is required, a
single watchlist/cryptor does not transfer.
