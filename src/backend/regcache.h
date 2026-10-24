#ifndef DOLRECOMP_REGCACHE_H
#define DOLRECOMP_REGCACHE_H

#include "../common/types.h"
#include <stdio.h>

// Register cache for function-level (fast) regions.
//
// The emitter writes a region with each instruction's C text between the
// marker lines REGCACHE_BEGIN and REGCACHE_END. The rewrite keeps the guest
// registers gpr[n], fpr[n] and ps1[n] in C locals inside each basic block:
// a register is loaded from CPUState on its first use after a label, kept in
// the local while the block runs, and stored back only on the paths that
// leave the block (return, goto, the fall-through into the next label) and
// before any helper that may read or write CPUState registers (calls into
// other regions, fallbacks, exceptions that need the full state). Memory
// helpers and the floating-point helpers that only touch FPSCR are known
// not to read the registers, so stores to guest RAM no longer force the
// compiler to reload them from the context.

#define REGCACHE_BEGIN "\x01\n"
#define REGCACHE_END "\x02\n"

// Off by default (no measured gain in BT3, 17 Oct 2026); --register-cache turns it on.
void regcache_set_enabled(bool enabled);
bool regcache_enabled(void);

// Rewrites the marked region text (NUL-terminated) to `out`. Returns 0 on
// an allocation failure.
int regcache_rewrite(FILE* out, const char* text);

#endif /* DOLRECOMP_REGCACHE_H */
