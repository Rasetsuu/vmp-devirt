// Remill runtime for replay: first-arg-is-answer flags, direct-mapped
// memory, missing_block/jump as dispatcher callbacks into driver table.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_map>

#include "vmjump.h"

struct State;
struct Memory;
using addr_t = uint64_t;
using Fn = void *(*)(void *, uint64_t, void *);

static std::unordered_map<uint64_t, Fn> *g_fns;
extern "C" void replay_register(void *m) {
  g_fns = static_cast<std::unordered_map<uint64_t, Fn> *>(m);
}
extern "C" uint64_t replay_missing_addr(void);

// ---- memory: direct host map (driver mmaps guest VAs 1:1), except
// page 0 (host mmap_min_addr forbids it): a 4KB buffer backs guest
// [0, 0x1000), e.g. the tracer's ret stub + zero reads like [0x60].
static uint8_t g_lowpage[0x1000];
extern "C" void replay_init_mem(void) { g_lowpage[0] = 0xC3; }  // ret stub
static inline uint8_t *haddr(addr_t a) {
  if (a < 0x1000) return &g_lowpage[a];
  return (uint8_t *)(uintptr_t)a;
}
extern "C" uint8_t __remill_read_memory_8(Memory *, addr_t a) { return *haddr(a); }
extern "C" uint16_t __remill_read_memory_16(Memory *, addr_t a) { return *(uint16_t *)haddr(a); }
extern "C" uint32_t __remill_read_memory_32(Memory *, addr_t a) { return *(uint32_t *)haddr(a); }
extern "C" uint64_t __remill_read_memory_64(Memory *, addr_t a) { return *(uint64_t *)haddr(a); }
extern "C" Memory *__remill_write_memory_8(Memory *m, addr_t a, uint8_t v) { *haddr(a) = v; return m; }
extern "C" Memory *__remill_write_memory_16(Memory *m, addr_t a, uint16_t v) { *(uint16_t *)haddr(a) = v; return m; }
extern "C" Memory *__remill_write_memory_32(Memory *m, addr_t a, uint32_t v) { *(uint32_t *)haddr(a) = v; return m; }
extern "C" Memory *__remill_write_memory_64(Memory *m, addr_t a, uint64_t v) { *(uint64_t *)haddr(a) = v; return m; }

// ---- undefined: zero ----
extern "C" uint8_t __remill_undefined_8(void) { return 0; }
extern "C" uint16_t __remill_undefined_16(void) { return 0; }
extern "C" uint32_t __remill_undefined_32(void) { return 0; }
extern "C" uint64_t __remill_undefined_64(void) { return 0; }

// ---- flags/compares: first arg is the precomputed answer (remill
// X86 semantics pass (answer, lhs, rhs, res); runtime returns it) ----
extern "C" bool __remill_flag_computation_zero(bool r, ...) { return r; }
extern "C" bool __remill_flag_computation_sign(bool r, ...) { return r; }
extern "C" bool __remill_flag_computation_overflow(bool r, ...) { return r; }
extern "C" bool __remill_flag_computation_carry(bool r, ...) { return r; }
extern "C" bool __remill_compare_eq(bool r) { return r; }
extern "C" bool __remill_compare_neq(bool r) { return r; }
extern "C" bool __remill_compare_slt(bool r) { return r; }
extern "C" bool __remill_compare_sle(bool r) { return r; }
extern "C" bool __remill_compare_sgt(bool r) { return r; }
extern "C" bool __remill_compare_sge(bool r) { return r; }
extern "C" bool __remill_compare_ult(bool r) { return r; }
extern "C" bool __remill_compare_ule(bool r) { return r; }
extern "C" bool __remill_compare_ugt(bool r) { return r; }
extern "C" bool __remill_compare_uge(bool r) { return r; }

// ---- control flow: trampolines THROW to the driver (a callee's
// indirect jump means the call never comes back; normal return would
// wrongly resume the caller at fallthrough) ----
static const uint64_t kRipOff = 2472;
static inline void set_rip(void *st, uint64_t v) {
  *(uint64_t *)((uint8_t *)st + kRipOff) = v;
}
static inline uint64_t get_rip(void *st) {
  return *(uint64_t *)((uint8_t *)st + kRipOff);
}
static inline void log_edge(uint64_t src, uint64_t dst) {
  if (g_edge_log) {
    fwrite(&g_step, 8, 1, g_edge_log);
    fwrite(&src, 8, 1, g_edge_log);
    fwrite(&dst, 8, 1, g_edge_log);
  }
}
uint64_t g_step;
static uint64_t g_missing = 0;
extern "C" uint64_t replay_missing(void) { return g_missing; }
extern "C" Memory *__remill_error(void *, uint64_t addr, Memory *m) {
  fprintf(stderr, "REMILL-ERROR at %#lx\n", (unsigned long)addr);
  exit(3);
  return m;
}
extern "C" Memory *__remill_missing_block(void *st, uint64_t addr, Memory *m) {
  (void)m;
  log_edge(get_rip(st), addr);
  throw VMJump{addr};
}
extern "C" Memory *__remill_jump(void *st, uint64_t addr, Memory *m) {
  (void)m;
  log_edge(get_rip(st), addr);
  throw VMJump{addr};
}
extern "C" Memory *__remill_function_call(void *st, uint64_t addr, Memory *m) {
  (void)m;
  log_edge(get_rip(st), addr);
  throw VMJump{addr};
}
extern "C" Memory *__remill_function_return(void *st, uint64_t addr, Memory *m) {
  (void)m;
  log_edge(get_rip(st), addr);
  throw VMJump{addr};
}
extern "C" Memory *__remill_barrier_store_load(Memory *m) { return m; }
extern "C" Memory *__remill_barrier_load_load(Memory *m) { return m; }
extern "C" Memory *__remill_barrier_load_store(Memory *m) { return m; }
extern "C" Memory *__remill_barrier_store_store(Memory *m) { return m; }
extern "C" Memory *__remill_atomic_begin(Memory *m) { return m; }
extern "C" Memory *__remill_atomic_end(Memory *m) { return m; }
extern "C" Memory *__remill_sync_hyper_call(void *, Memory *, ...) {
  fprintf(stderr, "HYPERCALL\n");
  exit(4);
  return nullptr;
}
