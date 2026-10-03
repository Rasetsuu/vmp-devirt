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
#include <string>
#include <vector>
#include <utility>
#include <zlib.h>

using Fn = void *(*)(void *, uint64_t, void *);
#include "tables.h"
#include "dispatch.h"
#include "vmjump.h"
#include "iat.h"
#include <signal.h>
#include <dlfcn.h>
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
  // Mapped ranges merge: aligned ELF sections overlap arbitrarily.
  // Subtract coverage, mmap only the gaps, merge into the list.
  std::vector<std::pair<uint64_t, uint64_t>> done;
  for (auto &s : kSecs) {
    // Page-align once here (tables carry exact spans). ELF sections are
    // not page-aligned; PE ones are (no-op there).
    uint64_t base = s.va & ~0xFFFULL;
    uint64_t end = (s.va + s.size + 0xFFF) & ~0xFFFULL;
    std::vector<std::pair<uint64_t, uint64_t>> gaps = {{base, end}};
    for (auto &d : done) {
      std::vector<std::pair<uint64_t, uint64_t>> next;
      for (auto &g : gaps) {
        if (g.second <= d.first || g.first >= d.second) { next.push_back(g); continue; }
        if (g.first < d.first) next.emplace_back(g.first, d.first);
        if (g.second > d.second) next.emplace_back(d.second, g.second);
      }
      gaps.swap(next);
    }
    for (auto &g : gaps) {
      void *p = mmap((void *)g.first, g.second - g.first, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
      if (p == MAP_FAILED) {
        fprintf(stderr, "mmap sec fail va=%#lx [%#lx,%#lx)\n",
                (unsigned long)s.va, (unsigned long)g.first, (unsigned long)g.second);
        perror("mmap sec");
        return 1;
      }
      memset((void *)g.first, 0, g.second - g.first);
      done.emplace_back(g.first, g.second);
    }
    if (s.raw_len) memcpy((void *)(uintptr_t)s.va, file + s.file_off, s.raw_len);
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
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) { perror("mmap scratch"); return 1; }
  }
  if (mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) != MAP_FAILED) {
    *(uint8_t *)0 = 0xC3;  // ret page like tracer
  }
  // Import stubs in scratch (tracer parity): heap-ret, zero-ret,
  // fixed-time-ret; poke IAT slots from the generated table.
  {
    uint8_t *sh = (uint8_t *)0x70000000, *sz = (uint8_t *)0x70000010,
            *st = (uint8_t *)0x70000020;
    // mov rax,heap_base; ret | xor eax,eax; ret | mov [rcx],FIXED; ret
    uint64_t heap = 0x71000000;
    memcpy(sh, "\x48\xB8", 2); memcpy(sh + 2, &heap, 8); sh[10] = 0xC3;
    memcpy(sz, "\x31\xC0\xC3", 3);
    uint32_t fix = 0x4C4B4000;
    memcpy(st, "\x48\xC7\x01", 3); memcpy(st + 3, &fix, 4); st[7] = 0xC3;
    for (auto &e : kIAT) {
      // Map the slot page if outside the image (packed IAT elsewhere).
      bool in_image = false;
      for (auto &s : kSecs) {
        if (e.slot >= s.va && e.slot + 8 <= s.va + s.size) { in_image = true; break; }
      }
      if (!in_image) {
        uint64_t pg = e.slot & ~0xFFFULL;
        mmap((void *)pg, 0x1000, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
      }
      uint64_t tgt;
      if (e.kind == 3) {
        // ELF GOT: resolve the real libc address (name in kGOT).
        tgt = 0;
        for (auto &g : kGOT) {
          if (g.slot == e.slot) {
            void *sym = dlsym(RTLD_DEFAULT, g.name);
            if (sym) tgt = (uint64_t)sym;
            else fprintf(stderr, "dlsym fail %s\n", g.name);
            break;
          }
        }
        if (!tgt) tgt = 0x70000010ULL;  // fall back to zero-ret
      } else tgt = (e.kind == 1) ? 0x70000000ULL
                 : (e.kind == 2) ? 0x70000020ULL : 0x70000010ULL;
      memcpy((void *)e.slot, &tgt, 8);
    }
  }
  // state (tracer-equivalent init)
  uint8_t *st = (uint8_t *)calloc(1, 8192);
  g_st = st;
  signal(SIGSEGV, segv_dump);
  replay_init_mem();
  uint64_t pool = kPool;
  // REPLAY_POOL overrides the pool-hash region (default: VMP image pool).
  uint64_t poolreg = 0x140002000ULL, poolsz = 0x3000;
  if (const char *e = getenv("REPLAY_POOL")) {
    poolreg = strtoull(e, nullptr, 0);
    if (const char *c = strchr(e, ',')) poolsz = strtoull(c + 1, nullptr, 0);
  }
  // REPLAY_FRAME=1: real frame for frame-based VMs (rbp=rsp, args honored).
  // REPLAY_ARGS="rdi=..,rsi=..,r8=..,r9=.." like the tracer ARGS.
  bool frame = getenv("REPLAY_FRAME") != nullptr;
  auto arg = [](const char *k, uint64_t dflt) -> uint64_t {
    const char *e = getenv("REPLAY_ARGS");
    if (!e) return dflt;
    std::string s(e), key(k);
    size_t p = s.find(key + "=");
    if (p == std::string::npos) return dflt;
    return strtoull(s.c_str() + p + key.size() + 1, nullptr, 0);
  };
  wreg(st, O_RAX, pool); wreg(st, O_RBX, pool);
  wreg(st, O_RSI, frame ? arg("rsi", 0) : pool);
  wreg(st, O_RDI, frame ? arg("rdi", 0) : pool);
  wreg(st, O_R8, frame ? arg("r8", 0) : pool);
  wreg(st, O_R9, frame ? arg("r9", 0) : pool);
  wreg(st, O_R10, pool); wreg(st, O_RCX, 0); wreg(st, O_RDX, 0);
  wreg(st, O_RBP, frame ? 0x7ffe0000ULL : 0x42ULL);
  wreg(st, O_R11, 0x42); wreg(st, O_RSP, 0x7ffe0000);
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
  // format tag: magic + u64s-per-leg (py side verifies, skew fails loud)
  const uint64_t kFmt[2] = {0x5247455230303033ULL, 21};
  if (rlog) fwrite(kFmt, 8, 2, rlog);
  void *mem = nullptr;
  static const uint64_t kROff[] = {O_RAX,O_RBX,O_RCX,O_RDX,O_RSI,O_RDI,O_RBP,O_RSP,O_R8,O_R9,O_R10,O_R11,O_R12,O_R13,O_R14,O_R15,O_RIP};
  // adler32 state hashes, one per region, so lockstep localizes the
  // first divergence (a combined hash only says "somewhere").
  // Regions: full 1MB stack page (loop frames live below rsp), image
  // pool slots, heap, staged scratch.
  auto reghash = [&](uint8_t *p, unsigned n) -> uint64_t {
    uLong a = adler32(0L, Z_NULL, 0);
    return (uint64_t)adler32(a, (const Bytef *)p, n);
  };
  uint64_t stepno = 0;
  uint64_t dump_at = 0;
  if (const char *e = getenv("LEG_DUMP")) dump_at = strtoull(e, nullptr, 0);
  for (; steps < bound; steps = steps + 1, stepno++) {
    g_step = stepno;
    auto it = m.find(pc);
    if (it == m.end()) { missing = pc; break; }
    if (log) { uint64_t v = pc; fwrite(&v, 8, 1, log); }
    // REPLAY_NOHASH=1: skip region hashing (regs still logged).
    // libz SIMD overreads at mapping edges fault on some hosts;
    // hashes are diagnostic (divergence localization), pcs are
    // what the align-check consumes.
    bool nohash = getenv("REPLAY_NOHASH") != nullptr;
    if (rlog) {
      for (unsigned k = 0; k < 17; k++) { uint64_t v = rreg(st, kROff[k]); fwrite(&v, 8, 1, rlog); }
      uint64_t hs = nohash ? 0 : reghash((uint8_t *)0x7FF00000, 0x100000);
      uint64_t hp = nohash ? 0 : reghash((uint8_t *)poolreg, (unsigned)poolsz);
      uint64_t hh = nohash ? 0 : reghash((uint8_t *)0x71000000, 0x100000);
      uint64_t hg = nohash ? 0 : reghash((uint8_t *)0x300000, 0x100000);
      fwrite(&hs, 8, 1, rlog); fwrite(&hp, 8, 1, rlog);
      fwrite(&hh, 8, 1, rlog); fwrite(&hg, 8, 1, rlog);
    }
    if (setjmp(g_jmpbuf) != 0) {
      // trampoline bounce: continue at pending target
      pc = g_pending;
      wreg(st, O_RIP, pc);
      continue;
    }
    if (dump_at && stepno == dump_at) {
      FILE *a = fopen("dump_stack.bin", "wb");
      FILE *b = fopen("dump_pool.bin", "wb");
      if (a) { fwrite((void *)0x7FF00000, 1, 0x100000, a); fclose(a); }
      if (b) { fwrite((void *)poolreg, 1, (size_t)poolsz, b); fclose(b); }
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
  // End-state page dumps for byte-exact diffing (small, diagnostic).
  {
    FILE *a = fopen("end_stack.bin", "wb");
    FILE *b = fopen("end_pool.bin", "wb");
    if (a) { fwrite((void *)0x7FF00000, 1, 0x100000, a); fclose(a); }
    if (b) { fwrite((void *)poolreg, 1, (size_t)poolsz, b); fclose(b); }
  }
  // End-state hashes: full mapped ranges (sections + heap + staged +
  // stack + pool). Two runs that truly finished the same program agree
  // on all of them; anything less is a different end.
  {
    auto rh = [&](uint8_t *p, unsigned n) -> uint64_t {
      uLong a = adler32(0L, Z_NULL, 0);
      return (uint64_t)adler32(a, (const Bytef *)p, n);
    };
    bool nohash2 = getenv("REPLAY_NOHASH") != nullptr;
    printf("final stack=%#lx pool=%#lx heap=%#lx staged=%#lx\n",
           nohash2 ? 0 : (unsigned long)rh((uint8_t *)0x7FF00000, 0x100000),
           nohash2 ? 0 : (unsigned long)rh((uint8_t *)poolreg, (unsigned)poolsz),
           nohash2 ? 0 : (unsigned long)rh((uint8_t *)0x71000000, 0x100000),
           nohash2 ? 0 : (unsigned long)rh((uint8_t *)0x300000, 0x100000));
    uint64_t him = 0;
    for (auto &s : kSecs) {
      uLong a = adler32(0L, Z_NULL, 0);
      him ^= (uint64_t)adler32(a, (const Bytef *)(uintptr_t)s.va, (unsigned)(s.size > 0x200000 ? 0x200000 : s.size));
      him = him * 1099511628211ULL + s.va;
    }
    printf("final image=%#lx\n", (unsigned long)him);
  }
  return 0;
}
