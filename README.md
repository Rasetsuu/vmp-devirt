# vmp-devirt

Trace-assisted VMProtect devirtualization research: version front-ends
(1.x gate / 2.x table / 3.x FDJ) feeding one shared backend
(Remill lift → LLVM opt → semantic cards → dataflow → native objects).

Validated against self-built VMP 3.9.4 binaries across multiple
protection modes. VMP 3.8.x/3.10.x compatibility is experimental and
sample-dependent.

## Scope and limitations (read first)

This is a **research platform for analyzing VMProtect-protected binaries
you own or are licensed to reverse engineer** — not a universal,
push-button devirtualizer:

- VMP 3.7+ needs **execution**: fetch streams, keys, and handler targets
  come from instrumented Unicorn snapshots, not static analysis.
- Coverage is **trace-bound**: only executed paths are recovered.
  Multi-state runs + branch merging extend it; full-program CFG recovery
  for complex targets remains manual.
- Anti-emulation (timing gates, I/O traps, environment checks) needs
  per-target stubs — the harness provides the mechanism, you provide
  the values.
- VMP 1.x/2.x front-ends are heuristic scanners; their old static
  walkers are kept as cross-check oracles, not primary paths.

## Layout

```
src/
  lib.rs               crate root, data_dir()
  pe_loader.rs         PE parsing / VA reads
  opcode_map.rs        legacy handler-type labels (oracle only, see module docs)
  frontend/
    mod.rs             VmFrontend trait (detect/fetch_stream/handler_addrs)
    fetch_finder.rs    movzx-byte FDJ scan + watchset/snapshot helpers
    cryptor_miner.rs   per-site ValueCryptor mining (branch-following)
    site_emulator.rs   sample-specific oracle decoders (legacy)
    handler_classifier.rs  handler classification via legacy patterns
    classifier_legacy.rs   first-bytes patterns (weak; fallback only)
    v1_gate.rs         VMP 1.x gate-scan front-end
    v2_walker.rs       VMP 2.x dispatch-table front-end
    v3_fdj.rs          VMP 3.x FDJ front-end
  backend/
    value_cryptor.rs   ADD/SUB/XOR/ROL/ROR/NOT/NEG/... chains
    lifter.rs          iced-x86 text lift + Remill subprocess backend
    llvm_pipeline.rs   opt -O3 over Remill IR (real passes)
  harness/
    snapshot.rs        Unicorn snapshots: sections+scratch mapping,
                       IN hooks, import stubs, watch hits, memlog,
                       zero-slide fast-forward
tests/
  smoke.rs             synthetic PE64 + hand-built fetch chain (no fixtures)
tools/                 (analysis drivers; each documents its inputs)
scripts/               Triton/angr/Ghidra helpers (external deps)
```

## Build

```bash
# Debian/Ubuntu (LLVM 22 for optional llvm feature)
sudo apt install llvm-22-dev libclang-22-dev clang-22
cargo build --release          # pure Rust (no LLVM link)
cargo build --release --features llvm   # llvm-sys link check
pip install triton-library capstone pefile   # python helpers
# Remill (optional lifter backend): build upstream, export REMILL_LIFT=<path>/remill-lift
# Souper (optional MBA superoptimizer): external only, wire its `souper` CLI
#   to scripts/triton_handlers.py output if desired; not vendored.
```

Dockerfile reproduces the full env. CI runs `cargo build/test --release`
(default features, no LLVM link, no commercial fixtures; sample-gated
tests skip, `tests/smoke.rs` always runs). The optional `--features llvm`
link check runs as a non-blocking CI job (needs LLVM 22).

## Environment

| Var | Default | Meaning |
|---|---|---|
| `DATA_DIR` | `./data` | all tool artifacts |
| `WATCH_FILE` | `$DATA_DIR/watch.txt` | fetch VAs to watch |
| `CARDS` | `open_cards3.json` | Remill card cache file |
| `BIN_PATH` | target binary path (tools default: `./target.exe` placeholder) | target binary |
| `IAT_JSON` | — | `{api_name: iat_va}` import stub map |
| `VMP_TEST_BIN` / `VMP_ORACLE` | `tests/fixtures/…` | licensed-sample tests |
| `REMILL_LIFT` | `remill-lift-22` on PATH | Remill lift binary |
| `DEVIRT` / `FORCE_EDGE` / `REPO_ROOT` | `./target/…` / `.` | script-called binaries + repo root |
| `VMP_WORK_DIR` | system temp | lift scratch |
| `EFLAGS` / `IN_RET` / `DLL_MAIN` | — | snapshot state variants |

## Method (3.x, the proven path)

1. Snapshot the binary from its entry in Unicorn (sections + scratch,
   zero-page `ret`, import stubs, IN hook).
2. Detect fetch sites by *execution*, not by opcode spelling:
   watch which `reg` feeds an executed byte-load, whatever its
   mnemonic. Static `movzx` patterns are the fallback seed only —
   static-only hits measured 0% execution on hardened targets.
   Fetch-shape coverage: `movzx` ✓, `movsx` ✓ (SMC flips between
   them mid-run; miner accepts both), and-gated/co-byte fetches ✓
   via live capture. Measured bias (3.9.4, `devirt fetch`
   dispatch-anchored back-slices vs static strict scan): disjoint
   populations — sensor found 8 fetch-shaped byte sites the
   pattern+`mov-imm32` gate never proposed (indexed/scaled forms
   like `movzx edx,[r9+riz-1]`), 1 mined a verified chain
   (`Rol→Inc→Xor52→Ror`, key `r10l`); the rest are VM-context
   loads the miner correctly rejects. Other shapes (e.g. string
   ops): bring bytes, get a miner case — file an issue with opcode
   bytes around the fetch. Pattern-locked fetch is a documented
   non-method here.
3. Mine per-site cryptors from code (branch-following worklist).
4. Decode raw^key with the architectural key register (free sweeps
   overfit — constrain to the mined key).
5. Lift reached handlers via Remill, `opt -O3`, emit cards/dataflow,
   recompile with `llc` (`ld -r` proves composability).

## License

MIT (see LICENSE) with dependency notes (notably Unicorn GPL-2.0).
Research/educational use only, on binaries you own or may analyze.
