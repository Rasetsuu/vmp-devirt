// Shared control-flow unwind between runtime trampolines and driver.
#pragma once
#include <cstdint>
struct VMJump {
  uint64_t target;
};
static FILE *g_edge_log;
extern uint64_t g_step;
struct EdgeLogInit {
  EdgeLogInit() {
    g_edge_log = fopen("replay_edges.bin", "wb");
    if (g_edge_log) setvbuf(g_edge_log, nullptr, _IONBF, 0);
  }
};
static EdgeLogInit g_edge_log_init;
