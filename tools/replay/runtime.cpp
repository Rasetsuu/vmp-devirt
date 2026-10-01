// Remill runtime for replay: first-arg-is-answer flags, direct-mapped
// memory, missing_block/jump as dispatcher callbacks into driver table.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
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
// Last trampoline target (unlifted direct edge / stub return). Declared
// by the driver; previously only provided by an out-of-tree stubs.o.
extern "C" uint64_t stub_last(void) { return g_missing; }
extern "C" Memory *__remill_error(void *, uint64_t addr, Memory *m) {
  fprintf(stderr, "REMILL-ERROR at %#lx\n", (unsigned long)addr);
  exit(3);
  return m;
}
static Memory *bounce(void *st, uint64_t addr, Memory *m) {
  (void)m;
  log_edge(get_rip(st), addr);
  g_pending = addr;
  g_missing = addr;
  longjmp(g_jmpbuf, 1);
  return m;
}
jmp_buf g_jmpbuf;
uint64_t g_pending;
extern "C" Memory *__remill_missing_block(void *st, uint64_t addr, Memory *m) {
  return bounce(st, addr, m);
}
extern "C" Memory *__remill_jump(void *st, uint64_t addr, Memory *m) {
  return bounce(st, addr, m);
}
extern "C" Memory *__remill_function_call(void *st, uint64_t addr, Memory *m) {
  return bounce(st, addr, m);
}
extern "C" Memory *__remill_function_return(void *st, uint64_t addr, Memory *m) {
  return bounce(st, addr, m);
}
extern "C" Memory *__remill_barrier_store_load(Memory *m) { return m; }
extern "C" Memory *__remill_barrier_load_load(Memory *m) { return m; }
extern "C" Memory *__remill_barrier_load_store(Memory *m) { return m; }
extern "C" Memory *__remill_barrier_store_store(Memory *m) { return m; }
extern "C" Memory *__remill_atomic_begin(Memory *m) { return m; }
extern "C" Memory *__remill_atomic_end(Memory *m) { return m; }
extern "C" Memory *__remill_sync_hyper_call(void *st, Memory *m, ...) {
  va_list ap;
  va_start(ap, m);
  unsigned name = va_arg(ap, unsigned);
  va_end(ap);
  uint8_t *s = (uint8_t *)st;
  auto wreg = [&](unsigned o, uint64_t v) { *(uint64_t *)(s + o) = v; };
  auto rreg = [&](unsigned o) { return *(uint64_t *)(s + o); };
  if (name == 0x103 || name == 0x104) {  // kX86ReadTSC/TSCP
    // Deterministic pinning (REPLAY_TSC="lo,hi", else host time):
    // wall-clock TSC is environmental input — identical values in
    // both worlds keep fidelity comparisons exact.
    unsigned lo = 0, hi = 0;
    int pinned = 0;
    if (const char *e = getenv("REPLAY_TSC")) {
      unsigned l = 0, h = 0;
      if (sscanf(e, "%i,%i", &l, &h) == 2) { lo = l; hi = h; pinned = 1; }
    }
    if (!pinned) {
      __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
      static FILE *tf;
      if (!tf) { tf = fopen("replay_tsc.bin", "wb"); if (tf) setvbuf(tf, nullptr, _IONBF, 0); }
      if (tf) { fwrite(&lo, 4, 1, tf); fwrite(&hi, 4, 1, tf); }
    }
    wreg(2216, (rreg(2216) & ~0xffffffffULL) | lo);  // RAX
    wreg(2264, (rreg(2264) & ~0xffffffffULL) | hi);  // RDX
    return m;
  }
  if (name == 0x102) {  // kX86CPUID: host cpuid (same host both worlds)
    uint32_t leaf = (uint32_t)rreg(2216), sub = (uint32_t)rreg(2264);
    uint32_t a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(leaf), "c"(sub));
    wreg(2216, (rreg(2216) & ~0xffffffffULL) | a);
    wreg(2232, (rreg(2232) & ~0xffffffffULL) | b);
    wreg(2264, (rreg(2264) & ~0xffffffffULL) | d);
    wreg(2248, (rreg(2248) & ~0xffffffffULL) | c);
    return m;
  }
  fprintf(stderr, "HYPERCALL %u\n", name);
  exit(4);
  return nullptr;
}
