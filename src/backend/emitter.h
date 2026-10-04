#ifndef DOLRECOMP_EMITTER_H
#define DOLRECOMP_EMITTER_H

#include "../common/types.h"
#include "../frontend/decoder.h"
#include <stdio.h>

typedef enum {
    DOLRECOMP_CPU_GEKKO,
    DOLRECOMP_CPU_BROADWAY,
    DOLRECOMP_CPU_ESPRESSO,
} DolRecompCPU;

// Split C emitter used by the command-line recompiler.

// emit the boilerplate header (includes, typedefs, etc)
void emit_header(FILE* out);
void emit_header_for_cpu(FILE* out, DolRecompCPU cpu);

// emit a single recompiled function as C code
void emit_function(FILE* out, const PPCInst* insts, u32 count, u32 func_addr);

// emit a single instruction as C code
void emit_instruction(FILE* out, const PPCInst* inst);

// emit the boilerplate footer
void emit_footer(FILE* out);

typedef struct FastPlan FastPlan;

// true when the instruction ends a basic block in generated code
bool emitter_inst_ends_block(const PPCInst* inst);

// emit the function-level (fast) regions of one chunk; see fastplan.h
int emit_fast_functions(FILE* out, const PPCInst* insts, u32 count, u32 chunk_addr,
                        const FastPlan* plan);

#endif /* DOLRECOMP_EMITTER_H */
