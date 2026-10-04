#include "backend/fastplan.h"
#include "backend/emitter.h"
#include "frontend/decoder.h"
#include <stdlib.h>
#include <string.h>

// Bound on nested native calls; deeper calls resume through the dispatcher.
// Guest call depth in practice is far smaller, and each level is one host
// frame of a generated function.
#define FAST_MAX_DEPTH 64u

typedef struct {
    u32* items;
    u32 count;
    u32 capacity;
} U32Vec;

static int vec_push(U32Vec* vec, u32 value) {
    if (vec->count == vec->capacity) {
        u32 capacity = vec->capacity ? vec->capacity * 2u : 1024u;
        u32* items = (u32*)realloc(vec->items, capacity * sizeof(*items));
        if (!items)
            return 0;
        vec->items = items;
        vec->capacity = capacity;
    }
    vec->items[vec->count++] = value;
    return 1;
}

static int compare_u32(const void* a, const void* b) {
    u32 x = *(const u32*)a;
    u32 y = *(const u32*)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static void vec_sort_unique(U32Vec* vec) {
    u32 out = 0;
    if (vec->count == 0)
        return;
    qsort(vec->items, vec->count, sizeof(u32), compare_u32);
    for (u32 i = 0; i < vec->count; i++) {
        if (out == 0 || vec->items[out - 1u] != vec->items[i])
            vec->items[out++] = vec->items[i];
    }
    vec->count = out;
}

// Index of the last element <= value, or -1.
static int upper_index(const u32* items, u32 count, u32 value) {
    u32 lo = 0, hi = count;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2u;
        if (items[mid] <= value)
            lo = mid + 1u;
        else
            hi = mid;
    }
    return (int)lo - 1;
}

static U32Vec s_native_hooks;

int fast_plan_load_native_hooks(const char* path) {
    FILE* file = fopen(path, "r");
    char line[256];
    if (!file) {
        fprintf(stderr, "error: can't open native hook list '%s'\n", path);
        return 0;
    }
    while (fgets(line, sizeof(line), file)) {
        char* end;
        unsigned long value;
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        value = strtoul(line, &end, 16);
        if (end == line || (value & 3u) != 0u || !vec_push(&s_native_hooks, (u32)value)) {
            fprintf(stderr, "error: bad native hook line in '%s': %s", path, line);
            fclose(file);
            return 0;
        }
    }
    fclose(file);
    vec_sort_unique(&s_native_hooks);
    return 1;
}

int fast_plan_native_hook_index(const FastPlan* plan, u32 address) {
    int index = upper_index(plan->hooks, plan->hook_count, address);
    return index >= 0 && plan->hooks[index] == address ? index : -1;
}

static const FastPlanSection* find_section(const FastPlan* plan, u32 address) {
    for (u32 i = 0; i < plan->section_count; i++) {
        const FastPlanSection* s = &plan->sections[i];
        if (address >= s->base && ((address - s->base) >> 2) < s->count &&
            (address & 3u) == 0u)
            return s;
    }
    return NULL;
}

static bool is_code(const FastPlan* plan, u32 address) {
    const FastPlanSection* s = find_section(plan, address);
    return s && s->code[(address - s->base) >> 2];
}

static void mark_entry(const FastPlan* plan, u32 address) {
    const FastPlanSection* s = find_section(plan, address);
    if (s && s->code[(address - s->base) >> 2])
        ((u8*)s->entry)[(address - s->base) >> 2] = 1;
}

bool fast_plan_is_entry(const FastPlan* plan, u32 address) {
    const FastPlanSection* s = find_section(plan, address);
    return s && s->entry[(address - s->base) >> 2];
}

int fast_plan_region_index(const FastPlan* plan, u32 address) {
    const FastPlanSection* s = find_section(plan, address);
    int index;
    if (!s)
        return -1;
    index = upper_index(plan->regions, plan->region_count, address);
    if (index < 0 || plan->regions[index] < s->base)
        return -1;
    return index;
}

u32 fast_plan_region_end(const FastPlan* plan, u32 index) {
    u32 start = plan->regions[index];
    const FastPlanSection* s = find_section(plan, start);
    u32 section_end = s->base + s->count * 4u;
    if (index + 1u < plan->region_count && plan->regions[index + 1u] < section_end)
        return plan->regions[index + 1u];
    return section_end;
}

int fast_plan_chunk_index(const FastPlan* plan, u32 address) {
    const FastPlanSection* s = find_section(plan, address);
    if (!s)
        return -1;
    return upper_index(plan->chunks, plan->chunk_count, address);
}

static bool is_timebase_read(const PPCInst* inst) {
    return inst->op == PPC_OP_MFTB ||
           (inst->op == PPC_OP_MFSPR && (inst->spr == 268 || inst->spr == 269));
}

void fast_plan_free(FastPlan* plan) {
    for (u32 i = 0; i < plan->section_count; i++) {
        free((void*)plan->sections[i].entry);
        free((void*)plan->sections[i].code);
    }
    free(plan->sections);
    free(plan->regions);
    free(plan->chunks);
    free(plan->hooks);
    memset(plan, 0, sizeof(*plan));
}

int fast_plan_build(FastPlan* plan, const LoadedCodeSection* sections,
                    u32 section_count, u32 chunk_instructions, u32 entry_point) {
    U32Vec regions = {0}, chunks = {0}, hooks = {0};
    PPCInst** decoded = NULL;
    int ok = 0;

    memset(plan, 0, sizeof(*plan));
    plan->sections = (FastPlanSection*)calloc(section_count ? section_count : 1u,
                                              sizeof(FastPlanSection));
    decoded = (PPCInst**)calloc(section_count ? section_count : 1u, sizeof(PPCInst*));
    if (!plan->sections || !decoded)
        goto done;

    for (u32 s = 0; s < section_count; s++) {
        const LoadedCodeSection* section = &sections[s];
        FastPlanSection* out;
        u8* code;
        if (section->size == 0 || !section->data)
            continue;
        out = &plan->sections[plan->section_count++];
        out->base = section->address;
        out->count = section->size / 4u;
        out->entry = (u8*)calloc(out->count ? out->count : 1u, 1u);
        code = (u8*)calloc(out->count ? out->count : 1u, 1u);
        out->code = code;
        decoded[plan->section_count - 1u] =
            (PPCInst*)malloc((out->count ? out->count : 1u) * sizeof(PPCInst));
        if (!out->entry || !code || !decoded[plan->section_count - 1u])
            goto done;
        for (u32 i = 0; i < out->count; i++) {
            u32 raw = read_be32(section->data + i * 4u);
            PPCInst* inst = &decoded[plan->section_count - 1u][i];
            *inst = ppc_decode(raw, out->base + i * 4u);
            if (inst->op == PPC_OP_UNKNOWN &&
                embedded_data_word(section->embedded_data_mode, raw))
                inst->embedded_data = true;
            code[i] = inst->embedded_data ? 0u : 1u;
        }
        // Chunk boundaries must match the legacy emitter exactly: the module
        // chunk table (and thus the chassis SMC state index) is derived from
        // the legacy chunk functions.
        for (u32 i = 0; i < out->count; i += chunk_instructions) {
            if (!vec_push(&chunks, out->base + i * 4u) ||
                !vec_push(&regions, out->base + i * 4u))
                goto done;
        }
    }

    // Region starts: direct-call targets plus the program entry point.
    if (is_code(plan, entry_point) && !vec_push(&regions, entry_point))
        goto done;
    for (u32 s = 0; s < plan->section_count; s++) {
        const FastPlanSection* section = &plan->sections[s];
        for (u32 i = 0; i < section->count; i++) {
            const PPCInst* inst = &decoded[s][i];
            if (!section->code[i] || !inst->lk)
                continue;
            if (inst->op != PPC_OP_B && inst->op != PPC_OP_BC)
                continue;
            // `bcl 20,31,$+4` reads the PC; it is not a call.
            if (inst->branch_target == inst->address + 4u)
                continue;
            if (is_code(plan, inst->branch_target) &&
                !vec_push(&regions, inst->branch_target))
                goto done;
        }
    }
    // Native hooks start their own region, so every transfer into one from
    // other code goes through a call or jump site that tests the hook flag.
    for (u32 i = 0; i < s_native_hooks.count; i++) {
        u32 address = s_native_hooks.items[i];
        if (!is_code(plan, address)) {
            fprintf(stderr, "warning: native hook 0x%08X is not code; ignored\n", address);
            continue;
        }
        if (!vec_push(&regions, address) || !vec_push(&hooks, address))
            goto done;
    }
    vec_sort_unique(&regions);
    vec_sort_unique(&chunks);
    plan->regions = regions.items;
    plan->region_count = regions.count;
    plan->chunks = chunks.items;
    plan->chunk_count = chunks.count;
    plan->hooks = hooks.items;
    plan->hook_count = hooks.count;
    regions.items = NULL;
    chunks.items = NULL;
    hooks.items = NULL;

    // Entries: every address the dispatcher (or a native caller) may need to
    // resume at. All entries become block leaders in the region emitter.
    for (u32 r = 0; r < plan->region_count; r++)
        mark_entry(plan, plan->regions[r]);
    for (u32 s = 0; s < plan->section_count; s++) {
        const FastPlanSection* section = &plan->sections[s];
        for (u32 i = 0; i < section->count; i++) {
            const PPCInst* inst = &decoded[s][i];
            u32 next = inst->address + 4u;
            if (!section->code[i])
                continue;
            if (emitter_inst_ends_block(inst))
                mark_entry(plan, next);
            if (is_timebase_read(inst))
                mark_entry(plan, inst->address);
            if ((inst->op == PPC_OP_B || inst->op == PPC_OP_BC) && !inst->lk) {
                u32 target = inst->branch_target;
                if (target <= inst->address ||
                    fast_plan_region_index(plan, target) !=
                        fast_plan_region_index(plan, inst->address))
                    mark_entry(plan, target);
            }
        }
    }
    ok = 1;

done:
    if (decoded) {
        for (u32 s = 0; s < section_count; s++)
            free(decoded[s]);
        free(decoded);
    }
    free(regions.items);
    free(chunks.items);
    free(hooks.items);
    if (!ok) {
        fprintf(stderr, "error: out of memory while planning fast functions\n");
        fast_plan_free(plan);
    }
    return ok;
}

static const char* index_type(const FastPlan* plan) {
    return plan->region_count < 0xFFFFu ? "u16" : "u32";
}

void fast_plan_emit_declarations(const FastPlan* plan, FILE* out) {
    fprintf(out, "\n// Function-level native code (see DolRecomp backend/fastplan.h).\n");
    fprintf(out, "#define DOLRECOMP_FAST_FUNCTIONS 1\n");
    fprintf(out, "#define DOLRECOMP_FAST_MAX_DEPTH %uu\n", FAST_MAX_DEPTH);
    fprintf(out, "#define DOLRECOMP_FAST_CHUNK_COUNT %uu\n", plan->chunk_count);
    fprintf(out, "#define DOLRECOMP_FAST_REGION_COUNT %uu\n", plan->region_count);
    // Optional diagnostic: per-region entry counters (define at module build).
    fprintf(out,
        "#ifdef DOLRECOMP_ENTRY_COUNTERS\n"
        "extern unsigned long long dolrecomp_entry_counts[];\n"
        "#define DOLRECOMP_COUNT_ENTRY(region) (++dolrecomp_entry_counts[region])\n"
        "#else\n"
        "#define DOLRECOMP_COUNT_ENTRY(region) ((void)0)\n"
        "#endif\n");
    fprintf(out, "typedef %s DolRecompFastIndex;\n", index_type(plan));
    for (u32 r = 0; r < plan->region_count; r++)
        fprintf(out, "void fast_%08X(CPUState* ctx);\n", plan->regions[r]);
    fprintf(out,
        "extern const DolRecompFunction dolrecomp_fast_functions[];\n"
        "extern const u16 dolrecomp_fast_chunks[];\n"
        "extern const u32 dolrecomp_fast_chunk_starts[];\n"
        "extern const u32 dolrecomp_fast_region_starts[];\n"
        "extern unsigned dolrecomp_fast_depth;\n"
        "extern int dolrecomp_fast_enabled;\n");
    for (u32 s = 0; s < plan->section_count; s++)
        fprintf(out, "extern const DolRecompFastIndex dolrecomp_fast_index_%u[];\n", s);

    // Native hooks (see fast_plan_load_native_hooks): the runtime sets a flag
    // to take over a function; native calls into it then exit to the dispatcher.
    if (plan->hook_count) {
        fprintf(out,
            "\n#define DOLRECOMP_NATIVE_HOOKS 1\n"
            "#define DOLRECOMP_NATIVE_HOOK_COUNT %uu\n"
            "extern unsigned char dolrecomp_native_hooks[];\n"
            "extern const u32 dolrecomp_native_hook_addresses[];\n"
            "extern int dolrecomp_native_hooks_any;\n"
            "\n"
            "static inline int dolrecomp_native_hooked(u32 address) {\n"
            "    u32 lo = 0u, hi = DOLRECOMP_NATIVE_HOOK_COUNT;\n"
            "    if (!dolrecomp_native_hooks_any) return 0;\n"
            "    while (lo < hi) {\n"
            "        u32 mid = lo + (hi - lo) / 2u;\n"
            "        u32 value = dolrecomp_native_hook_addresses[mid];\n"
            "        if (value == address) return dolrecomp_native_hooks[mid];\n"
            "        if (value < address) lo = mid + 1u; else hi = mid;\n"
            "    }\n"
            "    return 0;\n"
            "}\n", plan->hook_count);
    } else {
        fprintf(out,
            "\nstatic inline int dolrecomp_native_hooked(u32 address) { (void)address; return 0; }\n");
    }

    // Lookup: entry index + 1, or 0 when `address` is not a fast entry.
    fprintf(out, "\nstatic inline u32 dolrecomp_fast_lookup(u32 address) {\n");
    for (u32 s = 0; s < plan->section_count; s++) {
        const FastPlanSection* section = &plan->sections[s];
        fprintf(out,
            "    if ((u32)(address - 0x%08Xu) < 0x%08Xu)\n"
            "        return (address & 3u) ? 0u : dolrecomp_fast_index_%u[(address - 0x%08Xu) >> 2];\n",
            section->base, section->count * 4u, s, section->base);
    }
    fprintf(out, "    return 0u;\n}\n");

    fprintf(out,
        "\n"
        "// Native code may keep running while the chassis cycle budget lasts.\n"
        "static inline int dolrecomp_fast_budget_ok(const CPUState* ctx) {\n"
        "    return ctx->dispatch_budget > 0 && ctx->downcount > -ctx->dispatch_budget;\n"
        "}\n"
        "\n"
        "// Chunk verified by the chassis SMC guard (state 1).\n"
        "static inline int dolrecomp_fast_chunk_ok(const CPUState* ctx, u32 chunk) {\n"
        "    return ctx->chunk_state && ctx->chunk_state[chunk] == 1u;\n"
        "}\n"
        "\n"
        "static inline int dolrecomp_fast_continue(const CPUState* ctx, u32 chunk) {\n"
        "    return dolrecomp_fast_budget_ok(ctx) && dolrecomp_fast_chunk_ok(ctx, chunk);\n"
        "}\n"
        "\n"
        "// Call `fn` at `target` (pc must name a fast entry). Returns nonzero only\n"
        "// when the callee returned normally to `ret` and the caller may continue\n"
        "// natively; otherwise ctx->pc holds where the dispatcher must resume.\n"
        "static inline int dolrecomp_fast_call(CPUState* ctx, DolRecompFunction fn, u32 target,\n"
        "                                      u32 chunk, u32 ret, u32 own_chunk) {\n"
        "    ctx->pc = target;\n"
        "    if (dolrecomp_fast_depth >= DOLRECOMP_FAST_MAX_DEPTH || !dolrecomp_fast_continue(ctx, chunk))\n"
        "        return 0;\n"
        "    ++dolrecomp_fast_depth;\n"
        "    fn(ctx);\n"
        "    --dolrecomp_fast_depth;\n"
        "    return ctx->pc == ret && dolrecomp_fast_continue(ctx, own_chunk);\n"
        "}\n"
        "\n"
        "// Transfer to `target` without return (tail branch). On return the caller\n"
        "// must itself return; ctx->pc says where execution continues.\n"
        "static inline void dolrecomp_fast_jump(CPUState* ctx, DolRecompFunction fn, u32 target,\n"
        "                                       u32 chunk) {\n"
        "    ctx->pc = target;\n"
        "    if (dolrecomp_fast_depth >= DOLRECOMP_FAST_MAX_DEPTH || !dolrecomp_fast_continue(ctx, chunk))\n"
        "        return;\n"
        "    ++dolrecomp_fast_depth;\n"
        "    fn(ctx);\n"
        "    --dolrecomp_fast_depth;\n"
        "}\n"
        "\n"
        "static inline int dolrecomp_fast_call_dynamic(CPUState* ctx, u32 target, u32 ret,\n"
        "                                              u32 own_chunk) {\n"
        "    u32 entry = dolrecomp_fast_lookup(target);\n"
        "    ctx->pc = target;\n"
        "    if (!entry || dolrecomp_native_hooked(target)) return 0;\n"
        "    return dolrecomp_fast_call(ctx, dolrecomp_fast_functions[entry - 1u], target,\n"
        "                               dolrecomp_fast_chunks[entry - 1u], ret, own_chunk);\n"
        "}\n"
        "\n"
        "static inline void dolrecomp_fast_jump_dynamic(CPUState* ctx, u32 target) {\n"
        "    u32 entry = dolrecomp_fast_lookup(target);\n"
        "    ctx->pc = target;\n"
        "    if (entry && !dolrecomp_native_hooked(target))\n"
        "        dolrecomp_fast_jump(ctx, dolrecomp_fast_functions[entry - 1u], target,\n"
        "                            dolrecomp_fast_chunks[entry - 1u]);\n"
        "}\n");
}

int fast_plan_emit_tables(const FastPlan* plan, const char* path,
                          const char* include_name) {
    FILE* out = fopen(path, "w");
    const char* type = index_type(plan);
    if (!out) {
        fprintf(stderr, "error: can't open output '%s'\n", path);
        return 0;
    }
    fprintf(out, "// DolRecomp output: fast function tables\n");
    fprintf(out, "#include \"../%s\"\n\n", include_name);
    fprintf(out, "unsigned dolrecomp_fast_depth;\n");
    fprintf(out, "// Set by the module glue once its chunk table is proven to match.\n");
    fprintf(out, "int dolrecomp_fast_enabled;\n\n");
    fprintf(out, "#ifdef DOLRECOMP_ENTRY_COUNTERS\n");
    fprintf(out, "unsigned long long dolrecomp_entry_counts[DOLRECOMP_FAST_REGION_COUNT];\n");
    fprintf(out, "#endif\n\n");

    fprintf(out, "const DolRecompFunction dolrecomp_fast_functions[] = {\n");
    for (u32 r = 0; r < plan->region_count; r++)
        fprintf(out, "    fast_%08X,\n", plan->regions[r]);
    fprintf(out, "};\n\n");

    fprintf(out, "const u16 dolrecomp_fast_chunks[] = {\n");
    for (u32 r = 0; r < plan->region_count; r++)
        fprintf(out, "    %uu,\n", (u32)fast_plan_chunk_index(plan, plan->regions[r]));
    fprintf(out, "};\n\n");

    fprintf(out, "const u32 dolrecomp_fast_chunk_starts[] = {\n");
    for (u32 c = 0; c < plan->chunk_count; c++)
        fprintf(out, "    0x%08Xu,\n", plan->chunks[c]);
    fprintf(out, "};\n\n");

    fprintf(out, "const u32 dolrecomp_fast_region_starts[] = {\n");
    for (u32 r = 0; r < plan->region_count; r++)
        fprintf(out, "    0x%08Xu,\n", plan->regions[r]);
    fprintf(out, "};\n");

    if (plan->hook_count) {
        fprintf(out, "\n// Native hook flags, set by the runtime before code runs.\n");
        fprintf(out, "unsigned char dolrecomp_native_hooks[%uu];\n", plan->hook_count);
        fprintf(out, "int dolrecomp_native_hooks_any;\n");
        fprintf(out, "const u32 dolrecomp_native_hook_addresses[] = {\n");
        for (u32 h = 0; h < plan->hook_count; h++)
            fprintf(out, "    0x%08Xu,\n", plan->hooks[h]);
        fprintf(out, "};\n");
    }

    for (u32 s = 0; s < plan->section_count; s++) {
        const FastPlanSection* section = &plan->sections[s];
        fprintf(out, "\nconst %s dolrecomp_fast_index_%u[] = {", type, s);
        for (u32 i = 0; i < section->count; i++) {
            u32 value = 0;
            if (section->entry[i])
                value = (u32)fast_plan_region_index(plan, section->base + i * 4u) + 1u;
            fprintf(out, "%s%u,", (i % 32u) == 0u ? "\n    " : "", value);
        }
        fprintf(out, "\n};\n");
    }

    if (fclose(out) != 0) {
        fprintf(stderr, "error: failed writing '%s'\n", path);
        return 0;
    }
    return 1;
}
