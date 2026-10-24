#include "regcache.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

// Register slots: 0..31 gpr, 32..63 fpr (ps0), 64..95 ps1.
#define SLOTS 96

static bool s_enabled = false;

void regcache_set_enabled(bool enabled) { s_enabled = enabled; }
bool regcache_enabled(void) { return s_enabled; }

typedef struct {
    char* data;
    size_t size;
    size_t capacity;
    bool failed;
} Buf;

static void buf_put(Buf* b, const char* s, size_t n) {
    if (b->failed)
        return;
    if (b->size + n + 1 > b->capacity) {
        size_t capacity = b->capacity ? b->capacity * 2 : 4096;
        while (capacity < b->size + n + 1)
            capacity *= 2;
        char* data = (char*)realloc(b->data, capacity);
        if (!data) {
            b->failed = true;
            return;
        }
        b->data = data;
        b->capacity = capacity;
    }
    memcpy(b->data + b->size, s, n);
    b->size += n;
    b->data[b->size] = 0;
}

static void buf_str(Buf* b, const char* s) { buf_put(b, s, strlen(s)); }

static const char* const kArray[3] = {"ctx->gpr[", "ctx->fpr[", "ctx->ps1["};
static const char* const kLocal[3] = {"R_g", "R_f", "R_p"};

static void slot_name(char* out, size_t size, int slot) {
    snprintf(out, size, "%s%d", kLocal[slot / 32], slot % 32);
}

static void slot_array(char* out, size_t size, int slot) {
    snprintf(out, size, "%s%d]", kArray[slot / 32], slot % 32);
}

static bool is_ident(char c) { return isalnum((unsigned char)c) || c == '_'; }

// Helpers that take the context but neither read nor write gpr/fpr/ps1:
// guest memory, FPSCR-only floating-point helpers, the budget/SMC checks and
// the paired-single quantized helpers (rewritten to take the locals).
static const char* const kSafeCalls[] = {
    "mem_read8", "mem_read16", "mem_read32", "mem_read64",
    "mem_write8", "mem_write16", "mem_write32", "mem_write64",
    "ppc_fp_available", "ppc_fma", "ppc_fctiw", "ppc_fres", "ppc_frsqrte",
    "dolrecomp_fast_continue", "dolrecomp_fast_budget_ok", "dolrecomp_fast_chunk_ok",
    "ppc_psq_load_inline", "ppc_psq_store_inline",
};

static bool safe_call(const char* text, const char* paren) {
    const char* end = paren;
    const char* start;
    size_t i;
    while (end > text && end[-1] == ' ')
        end--;
    start = end;
    while (start > text && is_ident(start[-1]))
        start--;
    for (i = 0; i < sizeof(kSafeCalls) / sizeof(kSafeCalls[0]); i++) {
        if ((size_t)(end - start) == strlen(kSafeCalls[i]) &&
            memcmp(start, kSafeCalls[i], (size_t)(end - start)) == 0)
            return true;
    }
    return false;
}

// "ctx->gpr[12]" at p: returns the slot and sets *length, or -1 when p does
// not start a register access, -2 when the index is not a literal.
static int parse_register(const char* p, size_t* length) {
    int kind;
    for (kind = 0; kind < 3; kind++) {
        size_t n = strlen(kArray[kind]);
        if (strncmp(p, kArray[kind], n) == 0) {
            const char* q = p + n;
            int index = 0;
            if (!isdigit((unsigned char)*q))
                return -2;
            while (isdigit((unsigned char)*q))
                index = index * 10 + (*q++ - '0');
            if (*q != ']' || index > 31)
                return -2;
            *length = (size_t)(q + 1 - p);
            return kind * 32 + index;
        }
    }
    return -1;
}

static bool is_write(const char* text, const char* begin, const char* after) {
    const char* q = after;
    const char* b = begin;
    while (*q == ' ')
        q++;
    if (q[0] == '=' && q[1] != '=')
        return true;
    if ((q[0] == '+' && q[1] == '+') || (q[0] == '-' && q[1] == '-'))
        return true;
    if (strchr("+-*/%|&^", q[0]) && q[0] && q[1] == '=')
        return true;
    if ((q[0] == '<' && q[1] == '<' && q[2] == '=') || (q[0] == '>' && q[1] == '>' && q[2] == '='))
        return true;
    while (b > text && b[-1] == ' ')
        b--;
    if (b - text >= 2 && ((b[-1] == '+' && b[-2] == '+') || (b[-1] == '-' && b[-2] == '-')))
        return true;
    return false;
}

// "ppc_psq_load_inline(ctx, 12u," at p: the register index, length in *length.
static int parse_psq(const char* p, const char* name, size_t* length) {
    size_t n = strlen(name);
    const char* q;
    int index = 0;
    if (strncmp(p, name, n) != 0 || strncmp(p + n, "(ctx, ", 6) != 0)
        return -1;
    q = p + n + 6;
    if (!isdigit((unsigned char)*q))
        return -1;
    while (isdigit((unsigned char)*q))
        index = index * 10 + (*q++ - '0');
    if (q[0] != 'u' || q[1] != ',' || index > 31)
        return -1;
    *length = (size_t)(q + 2 - p);
    return index;
}

typedef struct {
    bool opaque;
    bool mention[SLOTS];
    bool write[SLOTS];
} Unit;

static void analyze(const char* s, size_t n, Unit* u) {
    const char* end = s + n;
    const char* p;
    memset(u, 0, sizeof(*u));
    for (p = s; p < end; p++) {
        size_t length;
        int slot;
        int psq;
        if (p > s && is_ident(p[-1]))
            continue;
        if ((psq = parse_psq(p, "ppc_psq_load_inline", &length)) >= 0) {
            u->mention[32 + psq] = u->mention[64 + psq] = true;
            u->write[32 + psq] = u->write[64 + psq] = true;
            p += length - 1;
            continue;
        }
        if ((psq = parse_psq(p, "ppc_psq_store_inline", &length)) >= 0) {
            u->mention[32 + psq] = u->mention[64 + psq] = true;
            p += length - 1;
            continue;
        }
        slot = parse_register(p, &length);
        if (slot == -2 || (slot >= 0 && p > s && p[-1] == '&')) {
            u->opaque = true;
            return;
        }
        if (slot >= 0) {
            u->mention[slot] = true;
            if (is_write(s, p, p + length))
                u->write[slot] = true;
            p += length - 1;
            continue;
        }
        // A bare `ctx` (not ctx->field) handed to anything but a safe helper.
        if (strncmp(p, "ctx", 3) == 0 && !is_ident(p[3]) && strncmp(p + 3, "->", 2) != 0) {
            const char* b = p;
            while (b > s && b[-1] == ' ')
                b--;
            if (!(b > s && b[-1] == '(' && safe_call(s, b - 1))) {
                u->opaque = true;
                return;
            }
        }
    }
}

typedef struct {
    bool loaded[SLOTS];
    bool dirty[SLOTS];
    bool used[SLOTS];
} State;

static void emit_store(Buf* b, int slot) {
    char name[16], array[24], line[64];
    slot_name(name, sizeof(name), slot);
    slot_array(array, sizeof(array), slot);
    snprintf(line, sizeof(line), "%s = %s; ", array, name);
    buf_str(b, line);
}

static void flush_dirty(Buf* b, State* st) {
    int slot;
    bool any = false;
    for (slot = 0; slot < SLOTS; slot++) {
        if (!st->dirty[slot])
            continue;
        if (!any)
            buf_str(b, "    ");
        any = true;
        emit_store(b, slot);
    }
    if (any)
        buf_str(b, "\n");
}

// Exit path inside a unit: the dirty registers plus the ones the unit has
// written so far (textually).
static void emit_exit_flush(Buf* b, const State* st, const bool* written) {
    int slot;
    for (slot = 0; slot < SLOTS; slot++)
        if (st->dirty[slot] || written[slot])
            emit_store(b, slot);
}

static bool exit_flush_empty(const State* st, const bool* written) {
    int slot;
    for (slot = 0; slot < SLOTS; slot++)
        if (st->dirty[slot] || written[slot])
            return false;
    return true;
}

static void rewrite_unit(Buf* b, State* st, const char* s, size_t n) {
    Unit u;
    bool written[SLOTS];
    const char* end = s + n;
    const char* p;
    const char* copied;
    int slot;
    char name[16], array[24], line[96];

    analyze(s, n, &u);
    if (u.opaque) {
        flush_dirty(b, st);
        buf_put(b, s, n);
        memset(st->loaded, 0, sizeof(st->loaded));
        memset(st->dirty, 0, sizeof(st->dirty));
        return;
    }
    for (slot = 0; slot < SLOTS; slot++) {
        if (!u.mention[slot] || st->loaded[slot])
            continue;
        slot_name(name, sizeof(name), slot);
        slot_array(array, sizeof(array), slot);
        snprintf(line, sizeof(line), "    %s = %s;\n", name, array);
        buf_str(b, line);
        st->loaded[slot] = true;
        st->used[slot] = true;
    }

    memset(written, 0, sizeof(written));
    copied = s;
    for (p = s; p < end; p++) {
        size_t length;
        int psq;
        if (p > s && is_ident(p[-1]))
            continue;
        if ((psq = parse_psq(p, "ppc_psq_load_inline", &length)) >= 0) {
            buf_put(b, copied, (size_t)(p - copied));
            snprintf(line, sizeof(line), "ppc_psq_load_to(ctx, &R_f%d, &R_p%d,", psq, psq);
            buf_str(b, line);
            written[32 + psq] = written[64 + psq] = true;
            p += length - 1;
            copied = p + 1;
            continue;
        }
        if ((psq = parse_psq(p, "ppc_psq_store_inline", &length)) >= 0) {
            buf_put(b, copied, (size_t)(p - copied));
            snprintf(line, sizeof(line), "ppc_psq_store_from(ctx, R_f%d, R_p%d,", psq, psq);
            buf_str(b, line);
            p += length - 1;
            copied = p + 1;
            continue;
        }
        slot = parse_register(p, &length);
        if (slot >= 0) {
            buf_put(b, copied, (size_t)(p - copied));
            slot_name(name, sizeof(name), slot);
            buf_str(b, name);
            if (u.write[slot] && is_write(s, p, p + length))
                written[slot] = true;
            p += length - 1;
            copied = p + 1;
            continue;
        }
        if (strncmp(p, "return;", 7) == 0 || (strncmp(p, "goto ", 5) == 0)) {
            const char* stop = strchr(p, ';');
            if (!stop || stop >= end)
                continue;
            buf_put(b, copied, (size_t)(p - copied));
            if (exit_flush_empty(st, written)) {
                buf_put(b, p, (size_t)(stop + 1 - p));
            } else {
                buf_str(b, "{ ");
                emit_exit_flush(b, st, written);
                buf_put(b, p, (size_t)(stop + 1 - p));
                buf_str(b, " }");
            }
            p = stop;
            copied = p + 1;
            continue;
        }
    }
    buf_put(b, copied, (size_t)(end - copied));
    for (slot = 0; slot < SLOTS; slot++)
        if (u.write[slot])
            st->dirty[slot] = true;
}

static bool is_label_line(const char* s, size_t n) {
    size_t i = 0;
    while (i < n && is_ident(s[i]))
        i++;
    return i > 0 && i + 2 == n && s[i] == ':' && s[i + 1] == '\n';
}

int regcache_rewrite(FILE* out, const char* text) {
    Buf body = {0};
    State st;
    const char* p = text;
    const char* header_end = strchr(text, '\n');
    int slot;
    if (!header_end)
        return 0;
    memset(&st, 0, sizeof(st));
    p = header_end + 1;
    while (*p) {
        const char* line_end = strchr(p, '\n');
        size_t n = line_end ? (size_t)(line_end + 1 - p) : strlen(p);
        if (strncmp(p, REGCACHE_BEGIN, 2) == 0) {
            const char* unit = p + 2;
            const char* stop = strstr(unit, REGCACHE_END);
            if (!stop) {
                free(body.data);
                return 0;
            }
            rewrite_unit(&body, &st, unit, (size_t)(stop - unit));
            p = stop + 2;
            continue;
        }
        if (is_label_line(p, n)) {
            flush_dirty(&body, &st);
            memset(st.loaded, 0, sizeof(st.loaded));
            memset(st.dirty, 0, sizeof(st.dirty));
            buf_put(&body, p, n);
        } else {
            rewrite_unit(&body, &st, p, n);
        }
        p += n;
    }
    if (body.failed) {
        free(body.data);
        return 0;
    }
    fwrite(text, 1, (size_t)(header_end + 1 - text), out);
    for (slot = 0; slot < SLOTS; slot++) {
        if (!st.used[slot])
            continue;
        fprintf(out, "    %s %s%d;\n", slot < 32 ? "u32" : "f64", kLocal[slot / 32], slot % 32);
    }
    if (body.data)
        fwrite(body.data, 1, body.size, out);
    free(body.data);
    return 1;
}
