// Shared control-flow unwind between runtime trampolines and driver.
//
// MECHANISM: setjmp/longjmp, not C++ exceptions. Exceptions proved
// unreliable here (terminate with main's catch on-stack — typeinfo/FDE
// fragility across llc-generated nounwind frames). longjmp restores
// rsp/rip directly; safe because no destructors or cleanups exist on
// the unwound path.
#pragma once
#include <cstdint>
#include <csetjmp>
struct VMJump {
  uint64_t target;
};
extern jmp_buf g_jmpbuf;
extern uint64_t g_pending;
static FILE *g_edge_log;
extern uint64_t g_step;
struct EdgeLogInit {
  EdgeLogInit() {
    g_edge_log = fopen("replay_edges.bin", "wb");
    if (g_edge_log) setvbuf(g_edge_log, nullptr, _IONBF, 0);
  }
};
static EdgeLogInit g_edge_log_init;
