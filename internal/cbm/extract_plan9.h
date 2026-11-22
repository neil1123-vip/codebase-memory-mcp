#ifndef CBM_EXTRACT_PLAN9_H
#define CBM_EXTRACT_PLAN9_H

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* The assembly grammar handles labels, but not Go's TEXT directives. Keep
 * this supplement limited to entry points and direct static-symbol calls. */
static char *cbm_plan9_code_view(const char *source, int len, bool mask_directives) {
    char *code = malloc((size_t)len + 1);
    if (!code)
        return NULL;
    memcpy(code, source, (size_t)len);
    code[len] = '\0';
    bool block = false, continuation = false;
    for (int start = 0; start < len;) {
        int end = start;
        while (end < len && code[end] != '\n')
            end++;
        char quote = 0;
        for (int i = start; i < end; i++) {
            if (block) {
                if (i + 1 < end && code[i] == '*' && code[i + 1] == '/') {
                    code[i++] = ' ';
                    block = false;
                }
                code[i] = ' ';
            } else if (quote) {
                if (code[i] == '\\' && i + 1 < end)
                    i++;
                else if (code[i] == quote)
                    quote = 0;
            } else if (code[i] == '"' || code[i] == '\'') {
                quote = code[i];
            } else if (i + 1 < end && code[i] == '/' && code[i + 1] == '/') {
                memset(code + i, ' ', (size_t)(end - i));
                break;
            } else if (i + 1 < end && code[i] == '/' && code[i + 1] == '*') {
                code[i++] = ' ';
                code[i] = ' ';
                block = true;
            }
        }
        int first = start, last = end;
        while (first < end && isspace((unsigned char)code[first]))
            first++;
        while (last > first && isspace((unsigned char)code[last - 1]))
            last--;
        bool directive = continuation || (first < end && code[first] == '#');
        continuation = directive && last > first && code[last - 1] == '\\';
        if (directive && mask_directives)
            memset(code + start, ' ', (size_t)(end - start));
        start = end + 1;
    }
    return code;
}

static char *cbm_plan9_code(const char *source, int len) {
    return cbm_plan9_code_view(source, len, true);
}

static const char *cbm_plan9_skip_space(const char *p, const char *end) {
    while (p < end && isspace((unsigned char)*p))
        p++;
    return p;
}

static bool cbm_plan9_opcode(const char **p, const char *end, const char *opcode) {
    size_t len = strlen(opcode);
    if ((size_t)(end - *p) <= len || memcmp(*p, opcode, len) != 0 ||
        !isspace((unsigned char)(*p)[len]))
        return false;
    *p = cbm_plan9_skip_space(*p + len, end);
    return true;
}

static const char *cbm_plan9_symbol(const char *p, const char *end, size_t *len,
                                   bool declaration) {
    const char *symbol = p;
    if (p == end || *p == '*' || *p == '$')
        return NULL;
    while (p < end && !isspace((unsigned char)*p) && *p != '(')
        p++;
    *len = (size_t)(p - symbol);
    if (*len == 0 || end - p < 4 || memcmp(p, "(SB)", 4) != 0)
        return NULL;
    p = cbm_plan9_skip_space(p + 4, end);
    if (declaration ? (p == end || *p != ',') : (p != end && *p != ';'))
        return NULL;
    if (*len > 2 && memcmp(symbol, "\xC2\xB7", 2) == 0) {
        symbol += 2;
        *len -= 2;
    }
    return symbol;
}

static const char *cbm_plan9_word(const char *p, const char *end) {
    const char *start = p;
    while (p < end) {
        if (isalnum((unsigned char)*p) || *p == '_' || *p == '.') {
            p++;
        } else if (end - p >= 2 && memcmp(p, "\xC2\xB7", 2) == 0) {
            p += 2;
        } else {
            break;
        }
    }
    return p == start ? NULL : p;
}

static bool cbm_plan9_expression(const char *p, const char *end) {
    bool atom = true;
    int depth = 0;
    p = cbm_plan9_skip_space(p, end);
    while (p < end) {
        if (atom) {
            if (*p == '+' || *p == '-' || *p == '~') {
                p++;
                continue;
            }
            if (*p == '(') {
                depth++;
                p++;
                continue;
            }
            if (isdigit((unsigned char)*p)) {
                if (end - p >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
                    p += 2;
                    if (p == end || !isxdigit((unsigned char)*p))
                        return false;
                    while (p < end && isxdigit((unsigned char)*p))
                        p++;
                } else {
                    while (p < end && isdigit((unsigned char)*p))
                        p++;
                    if (p < end && *p == '.') {
                        p++;
                        if (p == end || !isdigit((unsigned char)*p))
                            return false;
                        while (p < end && isdigit((unsigned char)*p))
                            p++;
                    }
                }
            } else {
                const char *word = cbm_plan9_word(p, end);
                if (!word)
                    return false;
                p = word;
            }
            atom = false;
        } else if (*p == ')' && depth > 0) {
            depth--;
            p++;
        } else if (strchr("+-*/%|&^", *p)) {
            atom = true;
            p++;
        } else if (end - p >= 2 &&
                   (memcmp(p, "<<", 2) == 0 || memcmp(p, ">>", 2) == 0)) {
            atom = true;
            p += 2;
        } else {
            return false;
        }
        p = cbm_plan9_skip_space(p, end);
    }
    return !atom && depth == 0;
}

static bool cbm_plan9_vector(const char *p, const char *end) {
    if (p == end || isdigit((unsigned char)*p))
        return false;
    const char *word = cbm_plan9_word(p, end);
    if (!word)
        return false;
    if (word == end)
        return true;
    const char *reg = p;
    if (*reg++ != 'V' || reg == word || !isdigit((unsigned char)*reg))
        return false;
    while (reg < word && isdigit((unsigned char)*reg))
        reg++;
    if (word - reg != 2 || *reg++ != '.' || !strchr("BHSDQ", *reg))
        return false;
    if (*word++ != '[' || word == end || !isdigit((unsigned char)*word))
        return false;
    while (word < end && isdigit((unsigned char)*word))
        word++;
    return end - word == 1 && *word == ']';
}

static bool cbm_plan9_operand(const char *p, const char *end) {
    while (end > p && isspace((unsigned char)end[-1]))
        end--;
    if (p == end)
        return false;
    if (*p == '$')
        return cbm_plan9_expression(p + 1, end);
    if (*p == '[') {
        if (end[-1] != ']')
            return false;
        p++;
        end--;
        while (p < end) {
            const char *comma = memchr(p, ',', (size_t)(end - p));
            const char *last = comma ? comma : end;
            p = cbm_plan9_skip_space(p, last);
            while (last > p && isspace((unsigned char)last[-1]))
                last--;
            const char *reg = p;
            if (reg == last || *reg++ != 'V' || reg == last ||
                !isdigit((unsigned char)*reg))
                return false;
            while (reg < last && isdigit((unsigned char)*reg))
                reg++;
            if (last - reg < 3 || *reg++ != '.' || !strchr("BHSDQ", *reg++))
                return false;
            while (reg < last && isdigit((unsigned char)*reg))
                reg++;
            if (reg != last)
                return false;
            if (!comma)
                return true;
            p = comma + 1;
        }
        return false;
    }
    const char *open = memchr(p, '(', (size_t)(end - p));
    if (!open)
        return cbm_plan9_vector(p, end) || cbm_plan9_expression(p, end);
    if (open > p && !cbm_plan9_expression(p, open))
        return false;
    int groups = 0;
    p = open;
    while (p < end && *p == '(' && groups < 2) {
        const char *close = memchr(p, ')', (size_t)(end - p));
        if (!close)
            return false;
        const char *reg = cbm_plan9_word(p + 1, close);
        if (!reg || isdigit((unsigned char)p[1]))
            return false;
        if (reg != close) {
            if (*reg++ != '*' || reg == close ||
                !(close - reg == 1 && strchr("1248", *reg)))
                return false;
        }
        p = close + 1;
        groups++;
    }
    return p == end;
}

static void cbm_plan9_project_ident(char *out, const char *code,
                                    const char *p, const char *end) {
    for (const char *q = p; q < end; q++)
        if (!(isalnum((unsigned char)*q) || *q == '_') ||
            (q == p && isdigit((unsigned char)*q)))
            out[q - code] = '_';
}

typedef struct CBMPlan9Macro {
    const char *name;
    size_t len;
    int argc;
    struct CBMPlan9Macro *next;
} CBMPlan9Macro;

/* Validate Plan 9-only forms before projecting them into equal-sized grammar
 * tokens. Original source remains authoritative for definitions and call spans. */
static char *cbm_plan9_compat_source(const char *source, int len) {
    char *masked = cbm_plan9_code(source, len);
    char *code = cbm_plan9_code_view(source, len, false);
    char *out = malloc((size_t)len + 1);
    CBMPlan9Macro *macros = NULL;
    bool plan9 = false, continuation = false, ok = masked && code && out;
    if (!ok)
        goto done;
    memcpy(out, source, (size_t)len);
    out[len] = '\0';
    const char *limit = code + len;
    for (const char *start = masked; start < masked + len;) {
        const char *end = memchr(start, '\n', (size_t)(masked + len - start));
        if (!end)
            end = masked + len;
        const char *p = cbm_plan9_skip_space(start, end);
        size_t symbol_len = 0;
        if (cbm_plan9_opcode(&p, end, "TEXT") &&
            cbm_plan9_symbol(p, end, &symbol_len, true))
            plan9 = true;
        start = end < masked + len ? end + 1 : masked + len;
    }
    if (!plan9) {
        ok = false;
        goto done;
    }
    for (const char *start = code; start < limit;) {
        const char *end = memchr(start, '\n', (size_t)(limit - start));
        if (!end)
            end = limit;
        const char *p = cbm_plan9_skip_space(start, end), *last = end;
        while (last > p && isspace((unsigned char)last[-1]))
            last--;
        bool was_continuation = continuation;
        continuation = last > p && last[-1] == '\\';
        if (continuation)
            out[--last - code] = ' ';
        if (p < last && *p == '#') {
            const char *directive = ++p;
            p = cbm_plan9_word(p, last);
            if (!p)
                goto invalid;
            size_t keyword_len = (size_t)(p - directive);
            p = cbm_plan9_skip_space(p, last);
            if (keyword_len == 7 && memcmp(directive, "include", 7) == 0) {
                if (continuation || last - p < 2 || *p != '"' || last[-1] != '"')
                    goto invalid;
                out[directive - code - 1] = '.';
                goto next_line;
            }
            if (keyword_len != 6 || memcmp(directive, "define", 6) != 0)
                goto invalid;
            const char *name = p, *name_end = cbm_plan9_word(p, last);
            if (!name_end || name_end == last || *name_end != '(')
                goto invalid;
            p = name_end + 1;
            int argc = 0;
            if (p < last && *p != ')') {
                for (;;) {
                    p = cbm_plan9_skip_space(p, last);
                    const char *param_end = cbm_plan9_word(p, last);
                    if (!param_end)
                        goto invalid;
                    argc++;
                    p = cbm_plan9_skip_space(param_end, last);
                    if (p == last || *p != ',')
                        break;
                    p++;
                }
            }
            if (p == last || *p++ != ')' ||
                cbm_plan9_skip_space(p, last) != last || !continuation)
                goto invalid;
            CBMPlan9Macro *macro = malloc(sizeof(*macro));
            if (!macro)
                goto invalid;
            *macro = (CBMPlan9Macro){name, (size_t)(name_end - name), argc, macros};
            macros = macro;
            out[directive - code - 1] = '.';
            cbm_plan9_project_ident(out, code, name, p);
            goto next_line;
        }
        if (continuation && !was_continuation)
            goto invalid;
        if (was_continuation && p < last && *p == ';')
            out[p++ - code] = ' ';
        p = cbm_plan9_skip_space(p, last);
        if (p == last)
            goto next_line;
        const char *opcode = p, *opcode_end = cbm_plan9_word(p, last);
        if (!opcode_end)
            goto invalid;
        if (opcode_end < last && *opcode_end == ':') {
            p = cbm_plan9_skip_space(opcode_end + 1, last);
            if (p == last)
                goto next_line;
            /* Generic grammar requires standalone labels; keep both tokens in
             * its instruction view while extraction reads the original colon. */
            out[opcode_end - code] = ' ';
            opcode = p;
            opcode_end = cbm_plan9_word(p, last);
            if (!opcode_end)
                goto invalid;
        }
        size_t opcode_len = (size_t)(opcode_end - opcode);
        bool text = opcode_len == 4 && memcmp(opcode, "TEXT", 4) == 0;
        bool call = (opcode_len == 4 && memcmp(opcode, "CALL", 4) == 0) ||
                    (opcode_len == 2 && memcmp(opcode, "BL", 2) == 0);
        if ((was_continuation && call) ||
            (text && opcode != cbm_plan9_skip_space(start, end)))
            goto invalid;
        cbm_plan9_project_ident(out, code, opcode, opcode_end);
        p = cbm_plan9_skip_space(opcode_end, last);
        int expected = -1;
        if (p == opcode_end && p < last && *p == '(') {
            if (text || call)
                goto invalid;
            for (CBMPlan9Macro *macro = macros; macro; macro = macro->next)
                if (macro->len == opcode_len &&
                    memcmp(macro->name, opcode, opcode_len) == 0)
                    expected = macro->argc;
            if (expected < 0 || last[-1] != ')')
                goto invalid;
            out[p++ - code] = ' ';
            out[--last - code] = ' ';
        } else if (p == opcode_end && p < last) {
            goto invalid;
        }
        int argc = 0;
        while ((p = cbm_plan9_skip_space(p, last)) < last) {
            const char *arg = p;
            int parens = 0, brackets = 0;
            while (p < last) {
                if (*p == '(')
                    parens++;
                else if (*p == ')')
                    parens--;
                else if (*p == '[')
                    brackets++;
                else if (*p == ']')
                    brackets--;
                if (parens < 0 || brackets < 0 || *p == ';')
                    goto invalid;
                if (*p == ',' && parens == 0 && brackets == 0)
                    break;
                p++;
            }
            const char *arg_end = p;
            while (arg_end > arg && isspace((unsigned char)arg_end[-1]))
                arg_end--;
            if (parens || brackets || !cbm_plan9_operand(arg, arg_end))
                goto invalid;
            size_t symbol_len = 0;
            if (text) {
                if (argc == 0) {
                    if (!cbm_plan9_symbol(arg, last, &symbol_len, true))
                        goto invalid;
                } else if (p == last) {
                    if (*arg != '$')
                        goto invalid;
                } else if (!cbm_plan9_expression(arg, arg_end)) {
                    goto invalid;
                }
            }
            if (call && arg_end - arg >= 4 &&
                memcmp(arg_end - 4, "(SB)", 4) == 0 &&
                !cbm_plan9_symbol(arg, arg_end, &symbol_len, false))
                goto invalid;
            cbm_plan9_project_ident(out, code, arg, arg_end);
            argc++;
            if (p < last) {
                p++;
                if (cbm_plan9_skip_space(p, last) == last)
                    goto invalid;
            }
        }
        if ((expected >= 0 && argc != expected) || (call && argc != 1) ||
            (text && argc != 2 && argc != 3))
            goto invalid;
next_line:
        start = end < limit ? end + 1 : limit;
    }
    if (continuation)
        ok = false;
    goto done;
invalid:
    ok = false;
done:
    while (macros) {
        CBMPlan9Macro *next = macros->next;
        free(macros);
        macros = next;
    }
    free(masked);
    free(code);
    if (!ok) {
        free(out);
        return NULL;
    }
    return out;
}

static bool cbm_extract_plan9_assembly(CBMExtractCtx *ctx) {
    if (ctx->language != CBM_LANG_ASSEMBLY || ctx->source_len <= 0)
        return false;
    char *code = cbm_plan9_code(ctx->source, ctx->source_len);
    if (!code)
        return false;
    const char *limit = code + ctx->source_len;
    int first_def = ctx->result->defs.count;
    int previous_def = -1;
    uint32_t line = 1;
    TSPoint end_point = ts_node_end_point(ctx->root);
    uint32_t file_end = end_point.row + (end_point.column > 0);
    for (const char *start = code; start < limit; line++) {
        const char *end = memchr(start, '\n', (size_t)(limit - start));
        if (!end)
            end = limit;
        const char *p = cbm_plan9_skip_space(start, end);
        size_t len = 0;
        const char *symbol = cbm_plan9_opcode(&p, end, "TEXT")
                                 ? cbm_plan9_symbol(p, end, &len, true)
                                 : NULL;
        if (symbol) {
            if (previous_def < 0) {
                CBMDefinition module = {
                    .name = ctx->rel_path,
                    .qualified_name = ctx->module_qn,
                    .label = "Module",
                    .file_path = ctx->rel_path,
                    .start_line = 1,
                    .end_line = file_end,
                    .is_exported = true,
                    .is_test = ctx->result->is_test_file,
                };
                cbm_defs_push(&ctx->result->defs, ctx->arena, module);
            } else {
                CBMDefinition *previous = &ctx->result->defs.items[previous_def];
                previous->end_line = line - 1;
                previous->lines = (int)(previous->end_line - previous->start_line + 1);
            }
            const char *name = cbm_arena_strndup(ctx->arena, symbol, len);
            CBMDefinition def = {
                .name = name,
                .qualified_name = cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->module_qn, name),
                .label = "Function",
                .file_path = ctx->rel_path,
                .start_line = line,
                .end_line = file_end,
                .lines = (int)(file_end - line + 1),
                .is_exported = cbm_is_exported(name, CBM_LANG_GO),
                .is_test = ctx->result->is_test_file,
            };
            previous_def = ctx->result->defs.count;
            cbm_defs_push(&ctx->result->defs, ctx->arena, def);
        }
        start = end < limit ? end + 1 : limit;
    }
    if (previous_def < 0) {
        free(code);
        return false;
    }

    const char *caller = ctx->module_qn;
    int next_def = first_def + 1;
    line = 1;
    for (const char *start = code; start < limit; line++) {
        const char *end = memchr(start, '\n', (size_t)(limit - start));
        if (!end)
            end = limit;
        while (next_def < ctx->result->defs.count &&
               ctx->result->defs.items[next_def].start_line <= line)
            caller = ctx->result->defs.items[next_def++].qualified_name;
        const char *site = cbm_plan9_skip_space(start, end);
        const char *label_end = cbm_plan9_word(site, end);
        if (label_end && label_end < end && *label_end == ':')
            site = cbm_plan9_skip_space(label_end + 1, end);
        const char *p = site;
        size_t len = 0;
        bool direct = cbm_plan9_opcode(&p, end, "CALL") || cbm_plan9_opcode(&p, end, "BL");
        const char *symbol = direct ? cbm_plan9_symbol(p, end, &len, false) : NULL;
        if (symbol) {
            const char *name = cbm_arena_strndup(ctx->arena, symbol, len);
            const char *target = NULL;
            for (int i = first_def + 1; i < ctx->result->defs.count; i++) {
                const CBMDefinition *def = &ctx->result->defs.items[i];
                if (strcmp(def->name, name) == 0) {
                    target = def->qualified_name;
                    break;
                }
            }
            const char *site_end = end;
            while (site_end > site && isspace((unsigned char)site_end[-1]))
                site_end--;
            CBMCall call = {
                .callee_name = name,
                .enclosing_func_qn = caller,
                .start_line = (int)line,
                .site_start_byte = (uint32_t)(site - code),
                .site_end_byte = (uint32_t)(site_end - code),
                .requires_lsp_resolution = true,
            };
            cbm_calls_push(&ctx->result->calls, ctx->arena, call);
            CBMResolvedCall resolved = {
                .caller_qn = caller,
                .callee_qn = target ? target : name,
                .strategy = target ? "assembly_direct" : "lsp_unresolved",
                .confidence = target ? 1.0f : 0.0f,
                .reason = target ? NULL : "assembly_symbol_not_in_file",
                .kind = CBM_RESOLVED_INVOCATION,
                .site_start_byte = call.site_start_byte,
                .site_end_byte = call.site_end_byte,
            };
            cbm_resolvedcall_push(&ctx->result->resolved_calls, ctx->arena, resolved);
        }
        start = end < limit ? end + 1 : limit;
    }
    free(code);
    return true;
}

#endif
