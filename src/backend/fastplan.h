#ifndef DOLRECOMP_BACKEND_FASTPLAN_H
#define DOLRECOMP_BACKEND_FASTPLAN_H

// Function-level ("fast") code generation plan.
//
// The legacy chunk functions accept any instruction address as an entry, so
// every guest instruction is a switch target and every call or return goes
// back through the host dispatcher. The fast plan partitions the same code
// into regions that start at direct-call targets (and at chunk boundaries, so
// a region never spans two SMC verification chunks). Each region becomes one
// C function whose entries are limited to addresses where control can
// legitimately resume from the dispatcher: region starts, call return points,
// block successors, loop heads and cross-region branch targets. Direct calls
// between regions become C calls. Any other address still resumes in the
// legacy chunk code, which remains the exact fallback.

#include "common/types.h"
#include "analysis/code_section.h"
#include <stdbool.h>
#include <stdio.h>

typedef struct {
    u32 base;
    u32 count;
    const u8* entry;     // per instruction: nonzero if the dispatcher may enter here
    const u8* code;      // per instruction: nonzero if decoded code (not data)
} FastPlanSection;

typedef struct FastPlan {
    FastPlanSection* sections;
    u32 section_count;
    u32* regions;        // sorted region start addresses
    u32 region_count;
    u32* chunks;         // sorted chunk start addresses (module chunk-table order)
    u32 chunk_count;
    u32* hooks;          // sorted native hook addresses (all region starts)
    u32 hook_count;
} FastPlan;

// Native hooks: guest function starts the host runtime may replace with its
// own implementation (e.g. SDK functions). Each becomes a region start, and
// native calls into it first test a per-hook flag set by the runtime: when
// set, control returns to the dispatcher with pc at the function. Load the
// list (text, one hex address per line, '#' comments) before planning.
int fast_plan_load_native_hooks(const char* path);
// Index of `address` in plan->hooks, or -1.
int fast_plan_native_hook_index(const FastPlan* plan, u32 address);

int fast_plan_build(FastPlan* plan, const LoadedCodeSection* sections,
                    u32 section_count, u32 chunk_instructions, u32 entry_point);
void fast_plan_free(FastPlan* plan);

bool fast_plan_is_entry(const FastPlan* plan, u32 address);
// Region containing `address`, or -1 when it is outside planned code.
int fast_plan_region_index(const FastPlan* plan, u32 address);
// End (exclusive) of region `index`: the next region start or the section end.
u32 fast_plan_region_end(const FastPlan* plan, u32 index);
// Index of the chunk containing `address` in sorted chunk order, or -1.
int fast_plan_chunk_index(const FastPlan* plan, u32 address);

// Header block: prototypes, lookup tables and the inline call helpers used by
// fast code and by the dispatcher. Emitted after DolRecompFunction exists.
void fast_plan_emit_declarations(const FastPlan* plan, FILE* header);
// Separate translation unit holding the function/chunk/entry tables.
int fast_plan_emit_tables(const FastPlan* plan, const char* path,
                          const char* include_name);

#endif /* DOLRECOMP_BACKEND_FASTPLAN_H */
