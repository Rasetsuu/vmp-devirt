# Re-execution of Remill-lifted VM code (replay stage of the loop).
#
# Generic sources; per-target artifacts (objects, tables, traces,
# binaries) are generated, never committed:
#
#   python3 gen_replay.py <binary> <bb-obj-dir-with-b_ll>
#   g++ -O2 -c runtime.cpp -o runtime.o
#   g++ -O2 -o replay driver.cpp runtime.o stubs.o <bb.o>
#   REPLAY_BIN=<binary> REPLAY_TRACE=<trace.bin> ./replay [bound]
#
# Design notes (see docs/coverage.md "Replay fidelity"):
# - runtime.cpp: first-arg-is-answer flag helpers (from remill's own
#   X86 Semantics/FLAGS.cpp), direct-mapped memory, throw-trampolines
#   for every control-flow intrinsic (a callee's indirect jump means
#   the call never comes back; normal return would resume wrongly).
# - driver.cpp: mmap guest image 1:1 + sparse scratch (tracer parity),
#   State init mirrors the tracer, rflag.flat seeded 0x202 (remill's
#   SerializeFlags leaves _if/must_be_1 untouched).
# - Fidelity harness: py_bb_diff2.py (research data dir) drives Unicorn
#   to each replay pc and compares regs + stack hash (16896/16896).
