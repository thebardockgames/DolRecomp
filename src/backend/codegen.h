#ifndef DOLRECOMP_BACKEND_CODEGEN_H
#define DOLRECOMP_BACKEND_CODEGEN_H

#include "common/types.h"
#include "frontend/decoder.h"
#include "backend/emitter.h"
#include "analysis/code_section.h"

#define EMIT_CHUNK_INSTRUCTIONS 4096u

typedef struct FastPlan FastPlan;

typedef struct {
    const PPCInst* insts;
    u32 count;
    u32 func_addr;
    char path[1200];
    char include_name[512];
    // Optional function-level output for the same instructions, written to a
    // separate translation unit to keep per-file compile cost bounded.
    const FastPlan* fast_plan;
    char fast_path[1200];
} ChunkJob;

int run_chunk_jobs(const ChunkJob* jobs, u32 job_count, u32 requested_jobs);
u32 effective_chunk_jobs(u32 job_count, u32 requested_jobs);

#endif
