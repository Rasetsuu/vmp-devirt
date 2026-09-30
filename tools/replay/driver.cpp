// Replay driver: mmap guest image 1:1, init State like the tracer,
// dispatch lifted blocks by RIP, compare RIP stream vs Unicorn trace.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <unordered_map>
#include <zlib.h>

using Fn = void *(*)(void *, uint64_t, void *);
#include "tables.h"
#include "dispatch.h"
#include "vmjump.h"
#include <signal.h>
extern "C" void replay_register(void *);
extern "C" uint64_t replay_missing(void);
extern "C" uint64_t stub_last(void);
extern "C" void replay_init_mem(void);
static uint8_t *g_st;
static void segv_dump(int) {
  const unsigned off[] = {2216, 2232, 2248, 2264, 2280, 2296, 2312, 2328,
                          2344, 2360, 2376, 2392, 2408, 2424, 2440, 2456, 2472};
  const char *nm[] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
                      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"};
  fprintf(stderr, "SEGV state:");
  for (unsigned i = 0; i < 17; i++)
    fprintf(stderr, " %s=%#lx", nm[i],
            (unsigned long)*(uint64_t *)(g_st + off[i]));
  fprintf(stderr, "\n");
  _exit(139);
}

// reg offsets harvested from lifted IR GEPs
enum : uint64_t {
  O_RAX = 2216, O_RBX = 2232, O_RCX = 2248, O_RDX = 2264, O_RSI = 2280,
  O_RDI = 2296, O_RSP = 2312, O_RBP = 2328, O_R8 = 2344, O_R9 = 2360,
  O_R10 = 2376, O_R11 = 2392, O_R12 = 2408, O_R13 = 2424, O_R14 = 2440,
  O_R15 = 2456, O_RIP = 2472,
};
static inline void wreg(uint8_t *st, uint64_t o, uint64_t v) {
  *(uint64_t *)(st + o) = v;
}
static inline uint64_t rreg(uint8_t *st, uint64_t o) {
  return *(uint64_t *)(st + o);
}

int main(int argc, char **argv) {
  const char *bin = argc > 2 ? argv[2]
      : getenv("REPLAY_BIN") ? getenv("REPLAY_BIN") : nullptr;
  if (!bin) { fprintf(stderr, "usage: replay [bound] <binary> [trace.bin]\n"); return 1; }
  uint64_t bound = argc > 1 ? strtoull(argv[1], 0, 0) : 2000000;
  int fdb = open(bin, O_RDONLY);
  if (fdb < 0) { perror("bin"); return 1; }
  // sections (file bytes straight from the binary)
  uint8_t *file = (uint8_t *)malloc(32 << 20);
  size_t fgot = 0;
  while (1) {
    ssize_t r = read(fdb, file + fgot, (32 << 20) - fgot);
    if (r < 0) { perror("bin"); return 1; }
    if (r == 0) break;
    fgot += r;
  }
  for (auto &s : kSecs) {
    void *p = mmap((void *)s.va, s.size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) { perror("mmap sec"); return 1; }
    memset(p, 0, s.size);
    if (s.raw_len) memcpy(p, file + s.file_off, s.raw_len);
  }
  // sparse scratch like the tracer (staged/heap/stack coverage).
  // Collisions are fatal: silent relocation would corrupt the guest map.
  for (uint64_t b = 0x100000; b < 0x80000000; b += 0x100000) {
    bool clash = false;
    for (auto &s : kSecs) {
      if (b + 0x100000 > s.va && b < s.va + s.size) { clash = true; break; }
    }
    if (clash) continue;
    void *p = mmap((void *)b, 0x100000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) { perror("mmap scratch"); return 1; }
  }
  if (mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) != MAP_FAILED) {
    *(uint8_t *)0 = 0xC3;  // ret page like tracer
  }
  // state (tracer-equivalent init)
  uint8_t *st = (uint8_t *)calloc(1, 8192);
  g_st = st;
  signal(SIGSEGV, segv_dump);
  replay_init_mem();
  uint64_t pool = kPool;
  wreg(st, O_RAX, pool); wreg(st, O_RBX, pool); wreg(st, O_RSI, pool);
  wreg(st, O_RDI, pool); wreg(st, O_R8, pool); wreg(st, O_R9, pool);
  wreg(st, O_R10, pool); wreg(st, O_RCX, 0); wreg(st, O_RDX, 0);
  wreg(st, O_RBP, 0x42); wreg(st, O_R11, 0x42); wreg(st, O_RSP, 0x7ffe0000);
  wreg(st, O_R12, 0); wreg(st, O_R13, 0); wreg(st, O_R14, 0); wreg(st, O_R15, 0);
  // rflag.flat: remill SerializeFlags copies aflag fields but leaves
  // _if/must_be_1 untouched (see PUSH.cpp) — seed like real EFLAGS.
  wreg(st, 2080, 0x202);
  // dispatch
  std::unordered_map<uint64_t, Fn> m;
  for (auto &e : kFns) m[e.va] = e.fn;
  replay_register(&m);
  // start: first lifted block in baseline trace order (entry stub itself
  // is unlifted; tracer-equivalent init makes mid-VM start valid)
  uint64_t pc = kEntry, missing = 0;
  // volatile: longjmp bypasses normal flow; a cached counter would stale.
  volatile uint64_t steps = 0;
  const char *tracepath = argc > 3 ? argv[3] : getenv("REPLAY_TRACE");
  {
    FILE *t = tracepath ? fopen(tracepath, "rb") : nullptr;
    uint64_t a;
    if (t) {
      while (fread(&a, 8, 1, t) == 1) {
        if (m.find(a) != m.end()) { pc = a; break; }
      }
      fclose(t);
    }
  }
  wreg(st, O_RIP, pc);
  FILE *log = fopen("replay_pcs.bin", "wb");
  FILE *rlog = fopen("replay_regs.bin", "wb");
  // Unbuffered: a crash must not leave pcs/regs/edges tails ragged
  // (different loss per file breaks leg alignment).
  if (log) setvbuf(log, nullptr, _IONBF, 0);
  if (rlog) setvbuf(rlog, nullptr, _IONBF, 0);
  // format tag: magic + regs-per-leg (py side verifies, skew fails loud)
  const uint64_t kFmt[2] = {0x5247455230303032ULL, 18};
  if (rlog) fwrite(kFmt, 8, 2, rlog);
  void *mem = nullptr;
  static const uint64_t kROff[] = {O_RAX,O_RBX,O_RCX,O_RDX,O_RSI,O_RDI,O_RBP,O_RSP,O_R8,O_R9,O_R10,O_R11,O_R12,O_R13,O_R14,O_R15,O_RIP};
  // adler32 over the FULL 1MB stack page (loop-carried frame slots live
  // below rsp, outside any rsp-relative window) plus image pool slots.
  // (zlib-speed: FNV in driver was fine, but the oracle side is Python.)
  auto stackhash = [&]() -> uint64_t {
    uLong a = adler32(0L, Z_NULL, 0);
    a = adler32(a, (const Bytef *)0x7FF00000, 0x100000);
    a = adler32(a, (const Bytef *)0x140002000, 0x3000);
    return (uint64_t)a;
  };
  uint64_t stepno = 0;
  // volatile: longjmp bypasses normal flow; cached counter would go stale.
  volatile uint64_t steps = 0;
  for (; steps < bound; steps++, stepno++) {
    g_step = stepno;
    auto it = m.find(pc);
    if (it == m.end()) { missing = pc; break; }
    if (log) { uint64_t v = pc; fwrite(&v, 8, 1, log); }
    if (rlog) { for (unsigned k = 0; k < 17; k++) { uint64_t v = rreg(st, kROff[k]); fwrite(&v, 8, 1, rlog); } uint64_t sh = stackhash(); fwrite(&sh, 8, 1, rlog); }
    if (setjmp(g_jmpbuf) != 0) {
      // trampoline bounce: continue at pending target
      pc = g_pending;
      wreg(st, O_RIP, pc);
      continue;
    }
    it->second(st, pc, mem);
    pc = rreg(st, O_RIP);
    if (pc == 0) { missing = stub_last(); break; }  // unlifted direct target
  }
  (void)0;
  if (log) fclose(log);
  printf("steps=%lu logged=%lu missing=%#lx stub=%#lx rax=%#lx rip=%#lx\n",
         (unsigned long)steps, (unsigned long)stepno, (unsigned long)missing,
         (unsigned long)stub_last(),
         (unsigned long)rreg(st, O_RAX), (unsigned long)pc);
  return 0;
}
