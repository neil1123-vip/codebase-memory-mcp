#include "go_lsp.h"
#include "lsp_node_iter.h"
#include "lsp_neg_memo.h"
#include "lsp_work.h"
#include "../../../src/foundation/hash_table.h"
#include "../helpers.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include "go_stdlib_packages.h"

// Forward declarations
static void resolve_calls_in_node_inner(GoLSPContext *ctx, TSNode node);

/* Depth-guarded entry for the AST call-resolution walk. The walk recurses once
 * per nesting level; a deeply-nested or cyclic file can overflow the native
 * stack (SIGSEGV) and take down the whole index. Past the cap the subtree is
 * skipped — its calls stay unresolved, which is graceful degradation, not a
 * crash. The cap is CBM_LSP_MAX_WALK_DEPTH, env-overridable via the same name.
 * The walk_depth-- runs after the inner returns, so early returns in the body
 * never leak the counter. */
static void resolve_calls_in_node(GoLSPContext *ctx, TSNode node) {
    if (ctx->walk_depth >= cbm_lsp_max_walk_depth())
        return;
    CBMScope *saved_floor = ctx->assignment_floor;
    ctx->walk_depth++;
    resolve_calls_in_node_inner(ctx, node);
    ctx->walk_depth--;
    ctx->assignment_floor = saved_floor;
}
static void emit_resolved_call(GoLSPContext *ctx, const char *callee_qn, const char *strategy,
                               float confidence, TSNode site);
static const char *go_exact_callable_target(GoLSPContext *ctx, TSNode node);
static const char *go_requalify_via_imports(GoLSPContext *ctx, const char *type_qn);
typedef struct {
    const CBMType *field;
    const CBMRegisteredFunc *method;
    const CBMType *signature;
} GoMember;
static GoMember go_lookup_member(GoLSPContext *ctx, const CBMType *type, const char *name);
static void go_bind_parameter_list(GoLSPContext *ctx, TSNode params);
static void extract_type_params_from_ast(GoLSPContext *ctx, CBMTypeRegistry *reg, TSNode root);
static const char *go_embedded_spelling(const char **next, size_t *len);
static const char *go_embedded_field_name(CBMArena *a, const char *s, size_t len);
static const CBMTypeRegistry *go_stdlib_shared(void);

static bool go_private_stdlib_name(const char *package_qn, size_t package_len, const char *name) {
    return name && name[0] >= 'a' && name[0] <= 'z' &&
           go_is_stdlib_package(package_qn, package_len);
}
extern const TSLanguage *tree_sitter_go(void);

// --- Initialization ---

void go_lsp_init(GoLSPContext *ctx, CBMArena *arena, const char *source, int source_len,
                 const CBMTypeRegistry *registry, const char *package_qn,
                 CBMResolvedCallArray *out) {
    memset(ctx, 0, sizeof(GoLSPContext));
    ctx->arena = arena;
    ctx->source = source;
    ctx->source_len = source_len;
    ctx->registry = registry;
    ctx->package_qn = package_qn;
    ctx->resolved_calls = out;
    ctx->current_scope = cbm_scope_push(arena, NULL); // root scope

    {
        const char *debug_env = getenv("CBM_LSP_DEBUG");
        ctx->debug = (debug_env && debug_env[0]);
    }
}

void go_lsp_add_import(GoLSPContext *ctx, const char *local_name, const char *pkg_qn) {
    // Store in parallel arrays (arena-allocated, grow by doubling)
    if (ctx->import_count % 32 == 0) {
        int new_cap = ctx->import_count + 32;
        const char **new_names =
            (const char **)cbm_arena_alloc(ctx->arena, (new_cap + 1) * sizeof(const char *));
        const char **new_qns =
            (const char **)cbm_arena_alloc(ctx->arena, (new_cap + 1) * sizeof(const char *));
        if (!new_names || !new_qns)
            return;
        if (ctx->import_local_names && ctx->import_count > 0) {
            memcpy(new_names, ctx->import_local_names, ctx->import_count * sizeof(const char *));
            memcpy(new_qns, ctx->import_package_qns, ctx->import_count * sizeof(const char *));
        }
        ctx->import_local_names = new_names;
        ctx->import_package_qns = new_qns;
    }
    ctx->import_local_names[ctx->import_count] = cbm_arena_strdup(ctx->arena, local_name);
    ctx->import_package_qns[ctx->import_count] = cbm_arena_strdup(ctx->arena, pkg_qn);
    ctx->import_count++;
}

// --- Helper: get node text ---

static char *lsp_node_text(GoLSPContext *ctx, TSNode node) {
    return cbm_node_text(ctx->arena, node, ctx->source);
}

// --- Helper: resolve import alias to package QN ---

/* The first import of this local name. Found by name (lsp_name_rows.h): a scan
 * per use made a file of thousands of imports quadratic. */
static const char *resolve_import(GoLSPContext *ctx, const char *local_name) {
    if (!local_name)
        return NULL;
    int i = cbm_name_rows_first(&ctx->import_rows, ctx->arena, ctx->import_local_names,
                                ctx->import_count, local_name);
    return i >= 0 ? ctx->import_package_qns[i] : NULL;
}

static bool go_cgo_builtin(const char *name) {
    return strcmp(name, "CString") == 0 || strcmp(name, "CBytes") == 0 ||
           strcmp(name, "GoString") == 0 || strcmp(name, "GoStringN") == 0 ||
           strcmp(name, "GoBytes") == 0 || strcmp(name, "malloc") == 0;
}

static bool go_imported_type_not_indexed(GoLSPContext *ctx, const char *type_qn) {
    if (!type_qn || cbm_registry_lookup_type(ctx->registry, type_qn))
        return false;
    for (int i = 0; i < ctx->import_count; i++) {
        const char *module_qn = ctx->import_package_qns[i];
        if (!module_qn || !module_qn[0])
            continue;
        size_t len = strlen(module_qn);
        if (strncmp(type_qn, module_qn, len) == 0 && type_qn[len] == '.' && type_qn[len + 1])
            return true;
    }
    return false;
}

static void go_lsp_add_source_imports(GoLSPContext *ctx, TSNode root) {
    CBMFileResult imports = {0};
    CBMExtractCtx extract = {
        .arena = ctx->arena,
        .result = &imports,
        .source = ctx->source,
        .source_len = ctx->source_len,
        .language = CBM_LANG_GO,
        .root = root,
    };
    cbm_extract_imports(&extract);
    ctx->has_cgo_import = extract.go_has_cgo_import;
    for (int i = 0; i < imports.imports.count; i++) {
        const CBMImport *imp = &imports.imports.items[i];
        if (imp->local_name && strcmp(imp->local_name, ".") == 0)
            ctx->has_dot_import = true;
        if (!imp->local_name || !imp->module_path || strcmp(imp->local_name, "_") == 0 ||
            strcmp(imp->local_name, ".") == 0 || resolve_import(ctx, imp->local_name))
            continue;
        /* Caller mappings already canonicalize project packages. Source-only
         * imports, including standard libraries, retain their import paths. */
        go_lsp_add_import(ctx, imp->local_name, imp->module_path);
    }
}

static int go_source_def_cmp(const void *a, const void *b) {
    const CBMLSPDef *left = *(const CBMLSPDef *const *)a;
    const CBMLSPDef *right = *(const CBMLSPDef *const *)b;
    return strcmp(left->qualified_name, right->qualified_name);
}

static void go_index_source_defs(CBMTypeRegistry *reg, const CBMLSPDef *defs, int def_count) {
    int count = 0;
    bool has_typed_variable = false;
    for (int i = 0; i < def_count; i++) {
        const CBMLSPDef *def = &defs[i];
        if (def->qualified_name) {
            count++;
            if (def->go_source_path && def->return_types && def->label &&
                strcmp(def->label, "Variable") == 0)
                has_typed_variable = true;
        }
    }
    if (!has_typed_variable)
        return;
    const CBMLSPDef **rows = cbm_arena_alloc(reg->arena, (size_t)count * sizeof(*rows));
    if (!rows)
        return;
    int used = 0;
    for (int i = 0; i < def_count; i++) {
        if (defs[i].qualified_name)
            rows[used++] = &defs[i];
    }
    qsort(rows, (size_t)used, sizeof(*rows), go_source_def_cmp);
    reg->go_source_defs = rows;
    reg->go_source_def_count = used;
}

static const CBMLSPDef *const *go_source_defs(const CBMTypeRegistry *reg, int *count) {
    for (; reg; reg = reg->fallback) {
        if (reg->go_source_defs) {
            *count = reg->go_source_def_count;
            return reg->go_source_defs;
        }
    }
    return NULL;
}

static const CBMLSPDef *go_unique_source_def(const CBMLSPDef *const *rows, int count,
                                            const char *qn, bool *ambiguous) {
    if (!qn)
        return NULL;
    const CBMLSPDef key = {.qualified_name = qn};
    const CBMLSPDef *needle = &key;
    const CBMLSPDef *const *hit = bsearch(&needle, rows, (size_t)count, sizeof(*rows),
                                          go_source_def_cmp);
    if (!hit)
        return NULL;
    if ((hit > rows && strcmp(hit[-1]->qualified_name, qn) == 0) ||
        (hit + 1 < rows + count && strcmp(hit[1]->qualified_name, qn) == 0)) {
        if (ambiguous)
            *ambiguous = true;
        return NULL;
    }
    return *hit;
}

static bool go_source_in_package(const CBMLSPDef *def, const GoLSPContext *ctx) {
    if (!def || !def->go_source_path || !def->go_source_package || !ctx->rel_path ||
        !ctx->source_package ||
        strcmp(def->go_source_package, ctx->source_package) != 0)
        return false;
    const char *dir_end = strrchr(ctx->rel_path, '/');
    const char *decl_end = strrchr(def->go_source_path, '/');
    size_t dir_len = dir_end ? (size_t)(dir_end - ctx->rel_path) : 0;
    size_t decl_len = decl_end ? (size_t)(decl_end - def->go_source_path) : 0;
    return dir_len == decl_len && memcmp(ctx->rel_path, def->go_source_path, dir_len) == 0;
}

/* shortcut: use direct methods of local named structs; promoted and generic
 * methods need a proof of the full member set. */
static const char *go_package_variable_method(GoLSPContext *ctx, const char *name,
                                               const char *method, bool *conflict) {
    if (!ctx->source_package || !ctx->rel_path || ctx->has_dot_import ||
        cbm_scope_contains(ctx->current_scope, name) || resolve_import(ctx, name))
        return NULL;
    int count = 0;
    const CBMLSPDef *const *rows = go_source_defs(ctx->registry, &count);
    if (!rows)
        return NULL;
    char qn[1024];
    int len = snprintf(qn, sizeof(qn), "%s.%s", ctx->package_qn, name);
    if (len < 0 || (size_t)len >= sizeof(qn))
        return NULL;
    const CBMLSPDef *var = go_unique_source_def(rows, count, qn, NULL);
    if (!go_source_in_package(var, ctx) || !var->label || strcmp(var->label, "Variable") != 0 ||
        !var->return_types || strcmp(var->go_source_path, ctx->rel_path) == 0)
        return NULL;
    const char *type_name = var->return_types + (var->return_types[0] == '*');
    len = snprintf(qn, sizeof(qn), "%s.%s", ctx->package_qn, type_name);
    if (len < 0 || (size_t)len >= sizeof(qn))
        return NULL;
    const CBMLSPDef *type = go_unique_source_def(rows, count, qn, conflict);
    if (type && type->go_source_package && !go_source_in_package(type, ctx))
        *conflict = true;
    if (!go_source_in_package(type, ctx) || !type->label || strcmp(type->label, "Struct") != 0 ||
        type->go_generic_declaration || !type->short_name || strcmp(type->short_name, type_name) != 0)
        return NULL;
    int added = snprintf(qn + len, sizeof(qn) - (size_t)len, ".%s", method);
    if (added < 0 || (size_t)added >= sizeof(qn) - (size_t)len)
        return NULL;
    const CBMLSPDef *target = go_unique_source_def(rows, count, qn, conflict);
    if (target && target->go_source_package && !go_source_in_package(target, ctx))
        *conflict = true;
    if (!go_source_in_package(target, ctx) || !target->label ||
        strcmp(target->label, "Method") != 0 || !target->receiver_type ||
        strcmp(target->receiver_type, type->qualified_name) != 0)
        return NULL;
    return target->qualified_name;
}

// --- Helper: check if name is a Go builtin type ---

static const CBMType *resolve_builtin_type(GoLSPContext *ctx, const char *name) {
    if (strcmp(name, "error") == 0)
        return cbm_type_named(ctx->arena, "builtin.error");
    static const char *builtin_types[] = {
        "int",    "int8",   "int16",   "int32",   "int64",     "uint",       "uint8",  "uint16",
        "uint32", "uint64", "float32", "float64", "complex64", "complex128", "string", "bool",
        "byte",   "rune",   "error",   "uintptr", "any",       NULL};
    for (const char **b = builtin_types; *b; b++) {
        if (strcmp(name, *b) == 0) {
            return cbm_type_builtin(ctx->arena, name);
        }
    }
    return NULL;
}

// --- go_parse_type_node: AST type node -> CBMType ---

/* ── Type names a function declares itself ────────────────────────────
 *
 * A function's type parameters (and its receiver's) and the types it declares
 * in its body are not the package's types of those names: `func F[T any](x T)`
 * and `func F() { type T struct{...}; var t T }` in a package with its own T.
 * The walker types such a name as unknown (it abstains) instead of the
 * package-level type. Each one is bound in the walker's own lexical scope
 * under a key no identifier can spell ("#T"), so it holds exactly where Go's
 * does: a type parameter for the function, a local type from its declaration
 * to the end of its block or closure. */
#define GO_SHADOW_KEY_MAX 256

static bool go_shadow_key(const char *name, char *key) {
    size_t n = name ? strlen(name) : 0;
    if (n == 0 || n + 2 > GO_SHADOW_KEY_MAX) {
        return false;
    }
    key[0] = '#';
    memcpy(key + 1, name, n + 1);
    return true;
}

static bool go_type_shadowed(const GoLSPContext *ctx, const char *name) {
    char key[GO_SHADOW_KEY_MAX];
    return go_shadow_key(name, key) && cbm_scope_contains(ctx->current_scope, key);
}

static void go_shadow_add(GoLSPContext *ctx, TSNode name_node) {
    char *name = ts_node_is_null(name_node) ? NULL : lsp_node_text(ctx, name_node);
    char key[GO_SHADOW_KEY_MAX];
    if (!name || strcmp(name, "_") == 0 || !go_shadow_key(name, key)) {
        return;
    }
    cbm_scope_bind(ctx->current_scope, cbm_arena_strdup(ctx->arena, key), cbm_type_unknown());
}

/* `[K comparable, V any]`: every name of every type_parameter_declaration. */
static void go_shadow_type_params(GoLSPContext *ctx, TSNode list) {
    uint32_t n = ts_node_is_null(list) ? 0 : ts_node_named_child_count(list);
    for (uint32_t i = 0; i < n; i++) {
        TSNode decl = ts_node_named_child(list, i);
        if (strcmp(ts_node_type(decl), "type_parameter_declaration") != 0) {
            continue;
        }
        uint32_t cc = ts_node_child_count(decl);
        for (uint32_t k = 0; k < cc; k++) {
            const char *field = ts_node_field_name_for_child(decl, k);
            if (field && strcmp(field, "name") == 0) {
                go_shadow_add(ctx, ts_node_child(decl, k));
            }
        }
    }
}

/* A generic receiver `(s *Set[K, V])` declares K and V: the type identifiers
 * inside the receiver type's type arguments. */
static void go_shadow_receiver_params(GoLSPContext *ctx, TSNode node, bool in_args, int depth) {
    if (ts_node_is_null(node) || depth > CBM_LSP_MAX_LOOKUP_DEPTH) {
        return;
    }
    const char *kind = ts_node_type(node);
    if (in_args && strcmp(kind, "type_identifier") == 0) {
        go_shadow_add(ctx, node);
        return;
    }
    bool args = in_args || strcmp(kind, "type_arguments") == 0;
    uint32_t n = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < n; i++) {
        go_shadow_receiver_params(ctx, ts_node_named_child(node, i), args, depth + 1);
    }
}

/* `type T struct{...}` / `type T = U` inside the function being walked. */
static void go_shadow_declared_types(GoLSPContext *ctx, TSNode decl) {
    uint32_t n = ts_node_named_child_count(decl);
    for (uint32_t i = 0; i < n; i++) {
        TSNode spec = ts_node_named_child(decl, i);
        const char *sk = ts_node_type(spec);
        if (strcmp(sk, "type_spec") == 0 || strcmp(sk, "type_alias") == 0) {
            go_shadow_add(ctx, ts_node_child_by_field_name(spec, "name", 4));
        }
    }
}
static const CBMType *go_parse_type_node_inner(GoLSPContext *ctx, TSNode node);
static int cbm_go_lsp_signature_param_multiplicity(TSNode param);

static const CBMType **go_parse_signature_types(GoLSPContext *ctx, TSNode list,
                                                bool variadic_slice) {
    uint32_t nc = ts_node_named_child_count(list);
    size_t count = 0;
    for (uint32_t i = 0; i < nc; i++)
        count += cbm_go_lsp_signature_param_multiplicity(ts_node_named_child(list, i));
    const CBMType **types = cbm_arena_alloc(ctx->arena, (count + 1) * sizeof(*types));
    if (!types)
        return NULL;
    count = 0;
    for (uint32_t i = 0; i < nc; i++) {
        TSNode param = ts_node_named_child(list, i);
        int names = cbm_go_lsp_signature_param_multiplicity(param);
        if (!names)
            continue;
        const CBMType *type =
            go_parse_type_node(ctx, ts_node_child_by_field_name(param, "type", 4));
        if (variadic_slice &&
            strcmp(ts_node_type(param), "variadic_parameter_declaration") == 0)
            type = cbm_type_slice(ctx->arena, type);
        for (int j = 0; j < names; j++)
            types[count++] = type;
    }
    types[count] = NULL;
    return types;
}

const CBMType *go_parse_type_node(GoLSPContext *ctx, TSNode node) {
    if (ctx->type_depth >= CBM_LSP_MAX_WALK_DEPTH)
        return cbm_type_unknown();
    ctx->type_depth++;
    const CBMType *type = go_parse_type_node_inner(ctx, node);
    ctx->type_depth--;
    return type;
}

static const CBMType *go_parse_type_node_inner(GoLSPContext *ctx, TSNode node) {
    if (ts_node_is_null(node))
        return cbm_type_unknown();

    const char *kind = ts_node_type(node);

    // type_identifier: simple named type
    if (strcmp(kind, "type_identifier") == 0 || strcmp(kind, "identifier") == 0) {
        char *name = lsp_node_text(ctx, node);
        if (!name)
            return cbm_type_unknown();
        if (go_type_shadowed(ctx, name))
            return cbm_type_unknown(); /* the function's own T, not the package's */
        const CBMVarBinding *binding = cbm_scope_lookup_binding(ctx->current_scope, name);
        if (binding && binding->is_type)
            return binding->type ? binding->type : cbm_type_unknown();
        if (binding && strcmp(kind, "identifier") == 0)
            return cbm_type_unknown();
        for (int i = 0; ctx->signature_type_params && ctx->signature_type_params[i]; i++) {
            if (strcmp(name, ctx->signature_type_params[i]) == 0)
                return cbm_type_type_param(ctx->arena, name);
        }
        const CBMType *builtin = resolve_builtin_type(ctx, name);
        if (builtin)
            return builtin;
        // Resolve as local type: package_qn.TypeName
        return cbm_type_named(ctx->arena,
                              cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->package_qn, name));
    }

    // qualified_type: pkg.Type
    if (strcmp(kind, "qualified_type") == 0 || strcmp(kind, "selector_expression") == 0) {
        bool selector = strcmp(kind, "selector_expression") == 0;
        TSNode pkg_node = selector ? ts_node_child_by_field_name(node, "operand", 7)
                                   : ts_node_child_by_field_name(node, "package", 7);
        TSNode name_node = selector ? ts_node_child_by_field_name(node, "field", 5)
                                    : ts_node_child_by_field_name(node, "name", 4);
        if (!ts_node_is_null(pkg_node) && !ts_node_is_null(name_node)) {
            char *pkg = lsp_node_text(ctx, pkg_node);
            char *name = lsp_node_text(ctx, name_node);
            const char *pkg_qn = selector && cbm_scope_contains(ctx->current_scope, pkg)
                                     ? NULL : resolve_import(ctx, pkg);
            if (pkg_qn && !go_private_stdlib_name(pkg_qn, strlen(pkg_qn), name)) {
                return cbm_type_named(ctx->arena,
                                      cbm_arena_sprintf(ctx->arena, "%s.%s", pkg_qn, name));
            }
        }
        return cbm_type_unknown();
    }

    // pointer_type: *T
    if (strcmp(kind, "pointer_type") == 0) {
        uint32_t nc = ts_node_named_child_count(node);
        if (nc > 0) {
            return cbm_type_pointer(ctx->arena,
                                    go_parse_type_node(ctx, ts_node_named_child(node, nc - 1)));
        }
        return cbm_type_unknown();
    }

    // slice_type: []T
    if (strcmp(kind, "slice_type") == 0) {
        TSNode elem = ts_node_child_by_field_name(node, "element", 7);
        if (ts_node_is_null(elem) && ts_node_named_child_count(node) > 0) {
            elem = ts_node_named_child(node, ts_node_named_child_count(node) - 1);
        }
        return cbm_type_slice(ctx->arena, go_parse_type_node(ctx, elem));
    }

    // array_type: [N]T — treat as slice for our purposes
    if (strcmp(kind, "array_type") == 0) {
        TSNode elem = ts_node_child_by_field_name(node, "element", 7);
        if (ts_node_is_null(elem) && ts_node_named_child_count(node) > 0) {
            elem = ts_node_named_child(node, ts_node_named_child_count(node) - 1);
        }
        return cbm_type_slice(ctx->arena, go_parse_type_node(ctx, elem));
    }

    // map_type: map[K]V
    if (strcmp(kind, "map_type") == 0) {
        TSNode key = ts_node_child_by_field_name(node, "key", 3);
        TSNode value = ts_node_child_by_field_name(node, "value", 5);
        return cbm_type_map(ctx->arena, go_parse_type_node(ctx, key),
                            go_parse_type_node(ctx, value));
    }

    // channel_type: chan T
    if (strcmp(kind, "channel_type") == 0) {
        TSNode value = ts_node_child_by_field_name(node, "value", 5);
        if (ts_node_is_null(value) && ts_node_named_child_count(node) > 0) {
            value = ts_node_named_child(node, ts_node_named_child_count(node) - 1);
        }
        // Determine direction from text
        char *text = lsp_node_text(ctx, node);
        int dir = 0;
        if (text) {
            if (strncmp(text, "chan<-", 6) == 0 || strncmp(text, "chan <-", 7) == 0)
                dir = 1;
            else if (strncmp(text, "<-chan", 6) == 0 || strncmp(text, "<- chan", 7) == 0)
                dir = 2;
        }
        return cbm_type_channel(ctx->arena, go_parse_type_node(ctx, value), dir);
    }

    // Function types and literals share the same signature fields.
    if (strcmp(kind, "function_type") == 0 || strcmp(kind, "func_literal") == 0) {
        const CBMType **params = go_parse_signature_types(
            ctx, ts_node_child_by_field_name(node, "parameters", 10), true);
        if (!params)
            return cbm_type_unknown();
        TSNode result = ts_node_child_by_field_name(node, "result", 6);
        if (ts_node_is_null(result)) {
            const CBMType *returns[] = {NULL};
            return cbm_type_func(ctx->arena, NULL, params, returns);
        }
        if (strcmp(ts_node_type(result), "parameter_list") == 0) {
            const CBMType **returns = go_parse_signature_types(ctx, result, true);
            if (!returns)
                return cbm_type_unknown();
            return cbm_type_func(ctx->arena, NULL, params, returns);
        }
        const CBMType *ret = go_parse_type_node(ctx, result);
        const CBMType *returns[] = {ret, NULL};
        return cbm_type_func(ctx->arena, NULL, params,
                             ret->kind == CBM_TYPE_TUPLE ? ret->data.tuple.elems : returns);
    }

    // interface_type
    if (strcmp(kind, "interface_type") == 0) {
        CBMType *t = (CBMType *)cbm_arena_alloc(ctx->arena, sizeof(CBMType));
        memset(t, 0, sizeof(CBMType));
        t->kind = CBM_TYPE_INTERFACE;
        return t;
    }

    // struct_type
    if (strcmp(kind, "struct_type") == 0) {
        CBMType *t = (CBMType *)cbm_arena_alloc(ctx->arena, sizeof(CBMType));
        if (!t)
            return cbm_type_unknown();
        memset(t, 0, sizeof(CBMType));
        t->kind = CBM_TYPE_STRUCT;
        TSNode body = ts_node_child_by_field_name(node, "body", 4);
        if (ts_node_is_null(body) && ts_node_named_child_count(node))
            body = ts_node_named_child(node, 0);
        if (ts_node_is_null(body))
            return t;
        uint32_t count = 0, embeds = 0, nc = ts_node_named_child_count(body);
        for (uint32_t i = 0; i < nc; i++) {
            TSNode field = ts_node_named_child(body, i);
            if (strcmp(ts_node_type(field), "field_declaration") != 0)
                continue;
            if (ts_node_is_null(ts_node_child_by_field_name(field, "name", 4))) {
                count++;
                embeds++;
            }
            for (uint32_t j = 0; j < ts_node_child_count(field); j++) {
                const char *name = ts_node_field_name_for_child(field, j);
                if (name && strcmp(name, "name") == 0)
                    count++;
            }
        }
        const char **names = cbm_arena_alloc(ctx->arena, (count + 1) * sizeof(*names));
        const CBMType **types = cbm_arena_alloc(ctx->arena, (count + 1) * sizeof(*types));
        const CBMType **embedded =
            cbm_arena_alloc(ctx->arena, (embeds + 1) * sizeof(*embedded));
        if (!names || !types || !embedded)
            return t;
        count = embeds = 0;
        for (uint32_t i = 0; i < nc; i++) {
            TSNode field = ts_node_named_child(body, i);
            TSNode type = ts_node_child_by_field_name(field, "type", 4);
            if (ts_node_is_null(type))
                continue;
            const CBMType *field_type = go_parse_type_node(ctx, type);
            if (ts_node_is_null(ts_node_child_by_field_name(field, "name", 4))) {
                const CBMType *base = cbm_type_deref(field_type);
                if (base && (base->kind == CBM_TYPE_NAMED || base->kind == CBM_TYPE_TEMPLATE)) {
                    const char *qn = base->kind == CBM_TYPE_TEMPLATE
                                         ? base->data.template_type.template_name
                                         : base->data.named.qualified_name;
                    const char *dot = strrchr(qn, '.');
                    if (strcmp(ts_node_type(ts_node_child(field, 0)), "*") == 0 &&
                        field_type->kind != CBM_TYPE_POINTER)
                        field_type = cbm_type_pointer(ctx->arena, field_type);
                    names[count] = dot ? dot + 1 : qn;
                    types[count++] = field_type;
                    embedded[embeds++] = field_type;
                }
                continue;
            }
            for (uint32_t j = 0; j < ts_node_child_count(field); j++) {
                const char *name = ts_node_field_name_for_child(field, j);
                if (name && strcmp(name, "name") == 0) {
                    names[count] = lsp_node_text(ctx, ts_node_child(field, j));
                    types[count++] = field_type;
                }
            }
        }
        names[count] = NULL;
        types[count] = NULL;
        embedded[embeds] = NULL;
        t->data.struct_type.field_names = names;
        t->data.struct_type.field_types = types;
        t->data.struct_type.embedded_types = embedded;
        return t;
    }

    // parenthesized_type: (T)
    if (strcmp(kind, "parenthesized_type") == 0 && ts_node_named_child_count(node) > 0) {
        return go_parse_type_node(ctx, ts_node_named_child(node, 0));
    }

    // type_elem: wrapper in type_arguments, unwrap to inner type
    if (strcmp(kind, "type_elem") == 0 && ts_node_named_child_count(node) > 0) {
        return go_parse_type_node(ctx, ts_node_named_child(node, 0));
    }

    // Keep arguments at the use site so registered compiler shapes can substitute them.
    if (strcmp(kind, "generic_type") == 0) {
        TSNode type_node = ts_node_child_by_field_name(node, "type", 4);
        TSNode arguments = ts_node_child_by_field_name(node, "type_arguments", 14);
        const CBMType *base = go_parse_type_node(ctx, type_node);
        if (base->kind != CBM_TYPE_NAMED)
            return cbm_type_unknown();
        const CBMType *args[17];
        int count = 0;
        for (uint32_t i = 0; i < ts_node_named_child_count(arguments); i++) {
            TSNode argument = ts_node_named_child(arguments, i);
            if (ts_node_is_extra(argument))
                continue;
            if (count == 16)
                return cbm_type_unknown();
            args[count++] = go_parse_type_node(ctx, argument);
        }
        if (!count)
            return cbm_type_unknown();
        args[count] = NULL;
        return cbm_type_template(ctx->arena, base->data.named.qualified_name, args, (int)count);
    }

    // parameter_list used as result type (multi-return)
    if (strcmp(kind, "parameter_list") == 0) {
        const CBMType **elems = go_parse_signature_types(ctx, node, true);
        if (!elems)
            return cbm_type_unknown();
        int count = 0;
        while (elems[count])
            count++;
        if (count == 1)
            return elems[0];
        if (count > 1)
            return cbm_type_tuple(ctx->arena, elems, count);
    }

    return cbm_type_unknown();
}

// --- Implicit generics: type unification ---

static bool go_inferred_types_conflict(GoLSPContext *ctx, const CBMType *a, const CBMType *b,
                                       int depth);

// Unify a parameter type pattern (containing TYPE_PARAM) against a concrete argument type.
// Fills inferred[i] with the concrete type bound to type_param_names[i].
static bool go_unify_type(GoLSPContext *ctx, const CBMType *param_type, const CBMType *arg_type,
                          const char **type_param_names, const CBMType **inferred,
                          int param_count, int supplied, bool top_level) {
    if (!param_type || !arg_type || cbm_type_is_unknown(arg_type))
        return true;

    if (param_type->kind == CBM_TYPE_TYPE_PARAM) {
        for (int i = 0; i < param_count; i++) {
            if (strcmp(param_type->data.type_param.name, type_param_names[i]) == 0) {
                if (!inferred[i])
                    inferred[i] = arg_type;
                else if (i >= supplied &&
                         go_inferred_types_conflict(ctx, inferred[i], arg_type, 0))
                    return false;
                break;
            }
        }
        return true;
    }

    // Structural matching — recurse into composite types
    if (param_type->kind == CBM_TYPE_SLICE && arg_type->kind == CBM_TYPE_SLICE) {
        return go_unify_type(ctx, param_type->data.slice.elem, arg_type->data.slice.elem,
                              type_param_names, inferred, param_count, supplied, false);
    }
    if (param_type->kind == CBM_TYPE_POINTER && arg_type->kind == CBM_TYPE_POINTER) {
        return go_unify_type(ctx, param_type->data.pointer.elem, arg_type->data.pointer.elem,
                              type_param_names, inferred, param_count, supplied, false);
    }
    if (param_type->kind == CBM_TYPE_MAP && arg_type->kind == CBM_TYPE_MAP) {
        return go_unify_type(ctx, param_type->data.map.key, arg_type->data.map.key,
                              type_param_names, inferred, param_count, supplied, false) &&
               go_unify_type(ctx, param_type->data.map.value, arg_type->data.map.value,
                              type_param_names, inferred, param_count, supplied, false);
    }
    if (param_type->kind == CBM_TYPE_CHANNEL && arg_type->kind == CBM_TYPE_CHANNEL) {
        if (param_type->data.channel.direction != arg_type->data.channel.direction &&
            (!top_level || arg_type->data.channel.direction != 0))
            return false;
        return go_unify_type(ctx, param_type->data.channel.elem, arg_type->data.channel.elem,
                              type_param_names, inferred, param_count, supplied, false);
    }
    if (param_type->kind == CBM_TYPE_FUNC && arg_type->kind == CBM_TYPE_FUNC) {
        const CBMType **patterns[] = {param_type->data.func.param_types,
                                      param_type->data.func.return_types};
        const CBMType **arguments[] = {arg_type->data.func.param_types,
                                       arg_type->data.func.return_types};
        for (int list = 0; list < 2; list++) {
            /* NULL is missing metadata; a present empty list proves zero arity. */
            if (!patterns[list] || !arguments[list])
                continue;
            for (int i = 0;; i++) {
                const CBMType *p = patterns[list][i];
                const CBMType *a = arguments[list][i];
                if (!p || !a) {
                    if (p != a)
                        return false;
                    break;
                }
                if (!go_unify_type(ctx, p, a, type_param_names, inferred, param_count, supplied,
                                   false))
                    return false;
            }
        }
    }
    return true;
}

static const CBMType *go_member_base_type(const CBMType *type) {
    return cbm_type_resolve_alias(cbm_type_deref(cbm_type_resolve_alias(type)));
}

static const CBMType *go_instantiate_type(GoLSPContext *ctx, const CBMType *type,
                                         const char **params, const CBMType **args, int depth);

static bool go_type_arguments_match(const CBMType *type, const char **params) {
    /* An empty, present list marks a declaration we could not safely parse. */
    if (params && !params[0])
        return false;
    if (!type || type->kind != CBM_TYPE_TEMPLATE)
        return true;
    const CBMType **args = type->data.template_type.template_args;
    int count = type->data.template_type.arg_count;
    if (!args || count <= 0 || count > 16)
        return false;
    for (int i = 0; i < count; i++) {
        if (!args[i] || cbm_type_is_unknown(args[i]) || (params && !params[i]))
            return false;
    }
    return !args[count] && (!params || !params[count]);
}

/* Shape lookup never changes the method identity of a Go defined type. */
static const CBMType *go_underlying_type(GoLSPContext *ctx, const CBMType *type) {
    for (int depth = 0; depth < 64; depth++) {
        type = cbm_type_resolve_alias(type);
        if (!type || (type->kind != CBM_TYPE_NAMED && type->kind != CBM_TYPE_TEMPLATE))
            return type ? type : cbm_type_unknown();
        const char *qn = type->kind == CBM_TYPE_TEMPLATE
                             ? type->data.template_type.template_name
                             : type->data.named.qualified_name;
        const CBMRegisteredType *registered =
            cbm_registry_lookup_type(ctx->registry, qn);
        if (!registered || !registered->underlying_type)
            return cbm_type_unknown();
        if (type->kind == CBM_TYPE_TEMPLATE) {
            const char **params = registered->type_param_names;
            const CBMType **args = type->data.template_type.template_args;
            if (!params || !go_type_arguments_match(type, params))
                return cbm_type_unknown();
            type = go_instantiate_type(ctx, registered->underlying_type, params, args, 0);
        } else {
            type = registered->underlying_type;
        }
    }
    return cbm_type_unknown();
}

static const CBMType *go_index_element_type(GoLSPContext *ctx, const CBMType *type) {
    type = go_underlying_type(ctx, type);
    if (type->kind == CBM_TYPE_MAP)
        return type->data.map.value;
    if (type->kind == CBM_TYPE_SLICE)
        return type->data.slice.elem;
    return cbm_type_unknown();
}

static const CBMType *go_conversion_index_callable(GoLSPContext *ctx, TSNode type) {
    if (ts_node_is_null(type) || strcmp(ts_node_type(type), "generic_type") != 0)
        return cbm_type_unknown();
    TSNode base = ts_node_child_by_field_name(type, "type", 4);
    TSNode index = ts_node_child_by_field_name(type, "type_arguments", 14);
    if (ts_node_is_null(base) || strcmp(ts_node_type(base), "type_identifier") != 0 ||
        ts_node_is_null(index) || ts_node_named_child_count(index) != 1)
        return cbm_type_unknown();
    const CBMVarBinding *binding =
        cbm_scope_lookup_binding(ctx->current_scope, lsp_node_text(ctx, base));
    return binding && !binding->is_type
               ? go_underlying_type(ctx, go_index_element_type(ctx, binding->type))
               : cbm_type_unknown();
}

static const char *go_member_type_qn(const CBMType *type) {
    if (!type)
        return NULL;
    if (type->kind == CBM_TYPE_NAMED)
        return type->data.named.qualified_name;
    if (type->kind == CBM_TYPE_TEMPLATE)
        return type->data.template_type.template_name;
    return NULL;
}

static const CBMType *go_identity_type(GoLSPContext *ctx, const CBMType *type) {
    for (int depth = 0; depth < CBM_LSP_MAX_LOOKUP_DEPTH; depth++) {
        type = cbm_type_resolve_alias(type);
        const char *qn = go_member_type_qn(type);
        const CBMRegisteredType *rt = qn ? cbm_registry_lookup_type(ctx->registry, qn) : NULL;
        if (!rt || (rt->go_identity != CBM_GO_IDENTITY_ALIAS && !rt->alias_of))
            return type;
        if (!go_type_arguments_match(type, rt->type_param_names))
            return cbm_type_unknown();
        if (type->kind == CBM_TYPE_TEMPLATE) {
            if (!rt->type_param_names || !rt->underlying_type)
                return cbm_type_unknown();
            type = go_instantiate_type(ctx, rt->underlying_type, rt->type_param_names,
                                        type->data.template_type.template_args, 0);
        } else {
            type = rt->underlying_type ? rt->underlying_type
                   : rt->alias_of ? cbm_type_named(ctx->arena, rt->alias_of)
                                  : cbm_type_unknown();
        }
    }
    return cbm_type_unknown();
}

static bool go_is_concrete_definition(GoLSPContext *ctx, const CBMType *type) {
    for (int depth = 0; type && depth < CBM_LSP_MAX_LOOKUP_DEPTH; depth++) {
        type = go_identity_type(ctx, type);
        const char *qn = go_member_type_qn(type);
        if (!qn)
            return type && (type->kind == CBM_TYPE_STRUCT || type->kind == CBM_TYPE_POINTER ||
                           type->kind == CBM_TYPE_SLICE || type->kind == CBM_TYPE_MAP ||
                           type->kind == CBM_TYPE_CHANNEL || type->kind == CBM_TYPE_FUNC ||
                           (type->kind == CBM_TYPE_BUILTIN && type->data.builtin.name &&
                            strcmp(type->data.builtin.name, "any") != 0));
        const CBMRegisteredType *rt = cbm_registry_lookup_type(ctx->registry, qn);
        if (!rt || !go_type_arguments_match(type, rt->type_param_names) ||
            rt->go_identity == CBM_GO_IDENTITY_INTERFACE || rt->is_interface)
            return false;
        if (rt->go_identity == CBM_GO_IDENTITY_CONCRETE)
            return true;
        type = rt->underlying_type;
    }
    return false;
}

/* shortcut: missing constant/anonymous-type identity stays unknown until the Go type model carries it. */
static bool go_inferred_types_conflict(GoLSPContext *ctx, const CBMType *a, const CBMType *b,
                                       int depth) {
    if (depth >= CBM_LSP_MAX_LOOKUP_DEPTH)
        return false;
    a = go_identity_type(ctx, a);
    b = go_identity_type(ctx, b);
    if (!a || !b || a == b)
        return false;
    const char *aqn = go_member_type_qn(a), *bqn = go_member_type_qn(b);
    if (aqn && bqn && strcmp(aqn, bqn) != 0)
        return go_is_concrete_definition(ctx, a) && go_is_concrete_definition(ctx, b);
    if (a->kind != b->kind)
        return false;
    switch (a->kind) {
    case CBM_TYPE_POINTER:
        return go_inferred_types_conflict(ctx, a->data.pointer.elem, b->data.pointer.elem, depth + 1);
    case CBM_TYPE_SLICE:
        return go_inferred_types_conflict(ctx, a->data.slice.elem, b->data.slice.elem, depth + 1);
    case CBM_TYPE_MAP:
        return go_inferred_types_conflict(ctx, a->data.map.key, b->data.map.key, depth + 1) ||
               go_inferred_types_conflict(ctx, a->data.map.value, b->data.map.value, depth + 1);
    case CBM_TYPE_CHANNEL:
        return go_inferred_types_conflict(ctx, a->data.channel.elem, b->data.channel.elem, depth + 1);
    case CBM_TYPE_TEMPLATE:
        if (!aqn || !bqn || !go_is_concrete_definition(ctx, a) ||
            !go_is_concrete_definition(ctx, b) ||
            a->data.template_type.arg_count != b->data.template_type.arg_count ||
            !a->data.template_type.template_args || !b->data.template_type.template_args)
            return false;
        for (int i = 0; i < a->data.template_type.arg_count; i++)
            if (go_inferred_types_conflict(ctx, a->data.template_type.template_args[i],
                                           b->data.template_type.template_args[i], depth + 1))
                return true;
        return false;
    case CBM_TYPE_FUNC: {
        const CBMType **as[] = {a->data.func.param_types, a->data.func.return_types};
        const CBMType **bs[] = {b->data.func.param_types, b->data.func.return_types};
        for (int list = 0; list < 2; list++) {
            if (!as[list] || !bs[list])
                continue;
            for (int i = 0; as[list][i] && bs[list][i]; i++)
                if (go_inferred_types_conflict(ctx, as[list][i], bs[list][i], depth + 1))
                    return true;
        }
        return false;
    }
    default:
        return false;
    }
}

static const CBMRegisteredType *go_member_registered_type(GoLSPContext *ctx,
                                                        const CBMType **type) {
    const char *qn = go_member_type_qn(*type);
    for (int depth = 0; qn && depth <= CBM_LSP_MAX_LOOKUP_DEPTH; depth++) {
        const CBMRegisteredType *rt = cbm_registry_lookup_type(ctx->registry, qn);
        if (!rt) {
            const char *alt = go_requalify_via_imports(ctx, qn);
            if (alt)
                rt = cbm_registry_lookup_type(ctx->registry, alt);
        }
        if (!rt || !go_type_arguments_match(*type, rt->type_param_names))
            return NULL;
        if (!rt->alias_of)
            return rt;
        if (*type && (*type)->kind == CBM_TYPE_TEMPLATE) {
            if (!rt->type_param_names || !rt->underlying_type)
                return NULL;
            *type = go_member_base_type(go_instantiate_type(
                ctx, rt->underlying_type, rt->type_param_names,
                (*type)->data.template_type.template_args, 0));
            qn = go_member_type_qn(*type);
            if (!qn || strcmp(qn, rt->alias_of) != 0)
                return NULL;
            continue;
        }
        /* Only explicit aliases inherit methods; defined underlying types do not. */
        if (rt->underlying_type && rt->underlying_type->kind == CBM_TYPE_TEMPLATE) {
            if (strcmp(rt->alias_of, rt->underlying_type->data.template_type.template_name) != 0)
                return NULL;
            *type = rt->underlying_type;
        }
        qn = rt->alias_of;
    }
    return NULL;
}

static const CBMType **go_instantiate_types(GoLSPContext *ctx, const CBMType **types,
                                           const char **params, const CBMType **args, int depth) {
    if (!types)
        return NULL;
    int count = 0;
    while (types[count])
        count++;
    const CBMType **out = cbm_arena_calloc(ctx->arena, (count + 1) * sizeof(*out));
    if (out) {
        for (int i = 0; i < count; i++)
            out[i] = go_instantiate_type(ctx, types[i], params, args, depth + 1);
    }
    return out;
}

/* Go parameters have explicit TYPE_PARAM identities. The shared C/C++ helper
 * also substitutes NAMED short names, which would rebind a real pkg.T here. */
static const CBMType *go_instantiate_type(GoLSPContext *ctx, const CBMType *type,
                                         const char **params, const CBMType **args, int depth) {
    if (!type || depth > CBM_LSP_MAX_LOOKUP_DEPTH)
        return cbm_type_unknown();
    if (!params || !args)
        return type;
    if (type->kind == CBM_TYPE_TYPE_PARAM) {
        for (int i = 0; params[i]; i++) {
            if (!args[i])
                return cbm_type_unknown();
            if (strcmp(params[i], type->data.type_param.name) == 0)
                return args[i];
        }
        return type;
    }
    switch (type->kind) {
    case CBM_TYPE_POINTER:
    case CBM_TYPE_SLICE:
    case CBM_TYPE_MAP:
    case CBM_TYPE_CHANNEL:
    case CBM_TYPE_FUNC:
    case CBM_TYPE_TEMPLATE:
    case CBM_TYPE_TUPLE:
    case CBM_TYPE_STRUCT:
    case CBM_TYPE_INTERFACE:
    case CBM_TYPE_ALIAS:
        break;
    default:
        return type;
    }
    CBMType *out = cbm_arena_alloc(ctx->arena, sizeof(*out));
    if (!out)
        return cbm_type_unknown();
    *out = *type;
    switch (type->kind) {
    case CBM_TYPE_POINTER:
        out->data.pointer.elem =
            go_instantiate_type(ctx, type->data.pointer.elem, params, args, depth + 1);
        break;
    case CBM_TYPE_SLICE:
        out->data.slice.elem =
            go_instantiate_type(ctx, type->data.slice.elem, params, args, depth + 1);
        break;
    case CBM_TYPE_MAP:
        out->data.map.key =
            go_instantiate_type(ctx, type->data.map.key, params, args, depth + 1);
        out->data.map.value =
            go_instantiate_type(ctx, type->data.map.value, params, args, depth + 1);
        break;
    case CBM_TYPE_CHANNEL:
        out->data.channel.elem =
            go_instantiate_type(ctx, type->data.channel.elem, params, args, depth + 1);
        break;
    case CBM_TYPE_FUNC:
        out->data.func.param_types =
            go_instantiate_types(ctx, type->data.func.param_types, params, args, depth);
        out->data.func.return_types =
            go_instantiate_types(ctx, type->data.func.return_types, params, args, depth);
        if ((type->data.func.param_types && !out->data.func.param_types) ||
            (type->data.func.return_types && !out->data.func.return_types))
            return cbm_type_unknown();
        break;
    case CBM_TYPE_TEMPLATE:
        out->data.template_type.template_args =
            go_instantiate_types(ctx, type->data.template_type.template_args, params, args, depth);
        if (type->data.template_type.template_args && !out->data.template_type.template_args)
            return cbm_type_unknown();
        break;
    case CBM_TYPE_TUPLE:
        out->data.tuple.elems =
            go_instantiate_types(ctx, type->data.tuple.elems, params, args, depth);
        if (type->data.tuple.elems && !out->data.tuple.elems)
            return cbm_type_unknown();
        break;
    case CBM_TYPE_STRUCT:
        out->data.struct_type.field_types =
            go_instantiate_types(ctx, type->data.struct_type.field_types, params, args, depth);
        out->data.struct_type.embedded_types =
            go_instantiate_types(ctx, type->data.struct_type.embedded_types, params, args, depth);
        if ((type->data.struct_type.field_types && !out->data.struct_type.field_types) ||
            (type->data.struct_type.embedded_types && !out->data.struct_type.embedded_types))
            return cbm_type_unknown();
        break;
    case CBM_TYPE_INTERFACE:
        out->data.interface_type.method_sigs =
            go_instantiate_types(ctx, type->data.interface_type.method_sigs, params, args, depth);
        if (type->data.interface_type.method_sigs && !out->data.interface_type.method_sigs)
            return cbm_type_unknown();
        break;
    case CBM_TYPE_ALIAS:
        out->data.alias.underlying =
            go_instantiate_type(ctx, type->data.alias.underlying, params, args, depth + 1);
        break;
    default:
        break;
    }
    return out;
}

static const CBMRegisteredFunc *go_registered_callable(GoLSPContext *ctx, TSNode node) {
    if (ts_node_is_null(node))
        return NULL;
    TSNode base = node;
    const char *kind = ts_node_type(node);
    if (strcmp(kind, "index_expression") == 0) {
        const CBMRegisteredFunc *function = go_registered_callable(
            ctx, ts_node_child_by_field_name(node, "operand", 7));
        return function && function->type_param_names && function->type_param_names[0]
                   ? function : NULL;
    }
    if (strcmp(kind, "selector_expression") == 0)
        base = ts_node_child_by_field_name(node, "operand", 7);
    else if (strcmp(kind, "qualified_type") == 0)
        base = ts_node_child_by_field_name(node, "package", 7);
    const char *base_kind = ts_node_is_null(base) ? "" : ts_node_type(base);
    if (strcmp(base_kind, "identifier") != 0 && strcmp(base_kind, "type_identifier") != 0 &&
        strcmp(base_kind, "package_identifier") != 0)
        return NULL;
    const char *target = go_exact_callable_target(ctx, node);
    return target ? cbm_registry_lookup_func(ctx->registry, target) : NULL;
}

static bool go_callee_is_type_name(GoLSPContext *ctx, TSNode node) {
    while (strcmp(ts_node_type(node), "parenthesized_expression") == 0 &&
           ts_node_named_child_count(node) == 1)
        node = ts_node_named_child(node, 0);
    const char *kind = ts_node_type(node);
    if (strcmp(kind, "identifier") == 0) {
        const char *name = lsp_node_text(ctx, node);
        if (!name)
            return false;
        const CBMVarBinding *binding = cbm_scope_lookup_binding(ctx->current_scope, name);
        if (binding)
            return binding->is_type;
        return resolve_builtin_type(ctx, name) ||
               cbm_registry_lookup_type(
                   ctx->registry, cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->package_qn, name));
    }
    if (strcmp(kind, "selector_expression") == 0) {
        TSNode base = ts_node_child_by_field_name(node, "operand", 7);
        TSNode field = ts_node_child_by_field_name(node, "field", 5);
        if (ts_node_is_null(base) || ts_node_is_null(field) ||
            strcmp(ts_node_type(base), "identifier") != 0)
            return false;
        const char *local = lsp_node_text(ctx, base);
        const char *name = lsp_node_text(ctx, field);
        const char *package = local && !cbm_scope_contains(ctx->current_scope, local)
                                  ? resolve_import(ctx, local) : NULL;
        return package && name && cbm_registry_lookup_type(
                   ctx->registry, cbm_arena_sprintf(ctx->arena, "%s.%s", package, name));
    }
    return false;
}

// --- go_eval_expr_type: recursive expression type evaluator ---

/* Walk a closure's body in a child scope (inheriting every outer binding)
 * with its declared parameters bound: `func(reg *httpmock.Registry) {
 * reg.Register(...) }` types `reg` wherever the literal stands (an
 * argument, an assignment, a composite literal's field value). */
static void go_walk_func_literal(GoLSPContext *ctx, TSNode node) {
    TSNode body = ts_node_child_by_field_name(node, "body", 4);
    if (ts_node_is_null(body)) {
        return;
    }
    CBMScope *saved = ctx->current_scope;
    CBMScope *saved_capture_parent = ctx->capture_parent;
    ctx->current_scope = cbm_scope_push(ctx->arena, saved);
    if (ctx->current_scope == saved) {
        ctx->callable_tracking_failed = true;
        return;
    }
    ctx->capture_parent = saved;
    ctx->assignment_floor = ctx->current_scope;
    go_bind_parameter_list(ctx, ts_node_child_by_field_name(node, "parameters", 10));
    go_bind_parameter_list(ctx, ts_node_child_by_field_name(node, "result", 6));
    resolve_calls_in_node(ctx, body);
    ctx->current_scope = saved;
    ctx->capture_parent = saved_capture_parent;
}

/* The type a package-level symbol has as an expression: a value's declared
 * type (CBM_FUNC_FLAG_VALUE: the signature's single result), a function's
 * own signature. NULL when unknown. */
static const CBMType *go_symbol_type(const CBMRegisteredFunc *f) {
    if (!f || !f->signature) {
        return NULL;
    }
    if ((f->flags & CBM_FUNC_FLAG_VALUE) == 0) {
        return f->signature;
    }
    const CBMType **rets =
        f->signature->kind == CBM_TYPE_FUNC ? f->signature->data.func.return_types : NULL;
    return rets && rets[0] ? rets[0] : NULL;
}

/* A package-level symbol a call can target: a function, never a value. */
static const CBMRegisteredFunc *go_lookup_callable(const CBMTypeRegistry *reg,
                                                   const char *package_qn, const char *name) {
    const CBMRegisteredFunc *f = cbm_registry_lookup_symbol(reg, package_qn, name);
    return f && (f->flags & CBM_FUNC_FLAG_VALUE) ? NULL : f;
}

/* The same rule for a lookup by full QN (the fast resolve path). */
static const CBMRegisteredFunc *go_lookup_func_callable(const CBMTypeRegistry *reg,
                                                        const char *qn) {
    const CBMRegisteredFunc *f = cbm_registry_lookup_func(reg, qn);
    return f && (f->flags & CBM_FUNC_FLAG_VALUE) ? NULL : f;
}

const CBMType *go_eval_expr_type(GoLSPContext *ctx, TSNode node) {
    if (ts_node_is_null(node))
        return cbm_type_unknown();

    const char *kind = ts_node_type(node);

    // --- Identifier: scope lookup ---
    if (strcmp(kind, "identifier") == 0) {
        char *name = lsp_node_text(ctx, node);
        if (!name)
            return cbm_type_unknown();

        // Check scope first
        const CBMType *t = cbm_scope_lookup(ctx->current_scope, name);
        if (cbm_scope_contains(ctx->current_scope, name))
            return t ? t : cbm_type_unknown();
        // A type the function declares itself (a conversion `T(x)`)
        if (go_type_shadowed(ctx, name))
            return cbm_type_unknown();

        // A package-level function or value (of any file of the package)
        const CBMRegisteredFunc *symbol =
            cbm_registry_lookup_symbol(ctx->registry, ctx->package_qn, name);
        if (symbol && (symbol->flags & CBM_FUNC_FLAG_VALUE)) {
            int count = 0;
            const CBMLSPDef *const *rows = go_source_defs(ctx->registry, &count);
            const CBMLSPDef *value =
                rows ? go_unique_source_def(rows, count, symbol->qualified_name, NULL) : NULL;
            if (value && value->go_source_package &&
                (!go_source_in_package(value, ctx) || ctx->has_dot_import ||
                 resolve_import(ctx, name)))
                return cbm_type_unknown();
        }
        const CBMType *st = go_symbol_type(symbol);
        if (st)
            return st;

        // Check if it's a builtin type (for type conversions like string(x), int(x))
        const CBMType *bt = resolve_builtin_type(ctx, name);
        if (bt)
            return bt->kind == CBM_TYPE_NAMED ? bt : cbm_type_named(ctx->arena, name);

        // Check if it's a registered type (for type conversions like MyType(x))
        const char *type_qn = cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->package_qn, name);
        const CBMRegisteredType *rt = cbm_registry_lookup_type(ctx->registry, type_qn);
        if (rt)
            return cbm_type_named(ctx->arena, type_qn);

        return cbm_type_unknown();
    }

    // --- Selector expression: a.B ---
    if (strcmp(kind, "selector_expression") == 0) {
        TSNode operand = ts_node_child_by_field_name(node, "operand", 7);
        TSNode field = ts_node_child_by_field_name(node, "field", 5);
        if (ts_node_is_null(operand) || ts_node_is_null(field))
            return cbm_type_unknown();

        char *field_name = lsp_node_text(ctx, field);
        if (!field_name)
            return cbm_type_unknown();

        // Check if operand is an import alias (pkg.Symbol)
        if (strcmp(ts_node_type(operand), "identifier") == 0) {
            char *pkg_name = lsp_node_text(ctx, operand);
            if (pkg_name) {
                const char *pkg_qn = resolve_import(ctx, pkg_name);
                if (pkg_qn && !cbm_scope_contains(ctx->current_scope, pkg_name)) {
                    if (go_private_stdlib_name(pkg_qn, strlen(pkg_qn), field_name))
                        return cbm_type_unknown();
                    // Look up pkg.Symbol as a function, a value or a type
                    const CBMType *st = go_symbol_type(
                        cbm_registry_lookup_symbol(ctx->registry, pkg_qn, field_name));
                    if (st)
                        return st;
                    // Check if it's a type
                    char *type_qn = cbm_arena_sprintf(ctx->arena, "%s.%s", pkg_qn, field_name);
                    const CBMRegisteredType *rt = cbm_registry_lookup_type(ctx->registry, type_qn);
                    if (rt)
                        return cbm_type_named(ctx->arena, type_qn);
                    const CBMType *variable = type_qn ? cbm_go_stdlib_variable_type(type_qn) : NULL;
                    if (variable)
                        return variable;
                    return cbm_type_unknown();
                }
            }
        }

        // Evaluate operand type
        const CBMType *recv_type = go_eval_expr_type(ctx, operand);
        if (cbm_type_is_unknown(recv_type))
            return cbm_type_unknown();

        // Auto-deref pointers for method calls
        const CBMType *base_type = go_member_base_type(recv_type);

        if (base_type && (go_member_type_qn(base_type) ||
                          base_type->kind == CBM_TYPE_STRUCT)) {
            GoMember member = go_lookup_member(ctx, base_type, field_name);
            if (member.field)
                return member.field;
            if (member.signature)
                return member.signature;
            const char *qn = go_member_type_qn(base_type);
            if (qn) {
                const CBMRegisteredType *rt = go_member_registered_type(ctx, &base_type);
                if (rt && rt->is_interface) {
                    const CBMRegisteredFunc *method =
                        cbm_registry_lookup_method(ctx->registry, rt->qualified_name, field_name);
                    if (method && method->signature &&
                        go_type_arguments_match(base_type, method->type_param_names))
                        return go_instantiate_type(
                            ctx, method->signature,
                            method->type_param_names ? method->type_param_names
                                                     : rt->type_param_names,
                            base_type->kind == CBM_TYPE_TEMPLATE
                                ? base_type->data.template_type.template_args : NULL, 0);
                }
            }
        }

        return cbm_type_unknown();
    }

    // A single-argument generic call can share the grammar's conversion form.
    if (strcmp(kind, "call_expression") == 0 ||
        strcmp(kind, "type_conversion_expression") == 0) {
        bool conversion = strcmp(kind, "type_conversion_expression") == 0;
        TSNode func_node = conversion ? ts_node_child_by_field_name(node, "type", 4)
                                      : ts_node_child_by_field_name(node, "function", 8);
        TSNode args_node = ts_node_child_by_field_name(node, "arguments", 9);
        TSNode targs_node = ts_node_child_by_field_name(node, "type_arguments", 14);
        if (ts_node_is_null(func_node))
            return cbm_type_unknown();
        TSNode conversion_type = func_node;
        if (conversion && strcmp(ts_node_type(func_node), "generic_type") == 0) {
            targs_node = ts_node_child_by_field_name(func_node, "type_arguments", 14);
            func_node = ts_node_child_by_field_name(func_node, "type", 4);
        }
        if (ts_node_is_null(func_node))
            return cbm_type_unknown();
        const CBMRegisteredFunc *rfunc = go_registered_callable(ctx, func_node);
        /* The grammar also parses a single generic argument as an index. */
        bool single_type_arg = rfunc && strcmp(ts_node_type(func_node), "index_expression") == 0;
        if (single_type_arg) {
            targs_node = ts_node_child_by_field_name(func_node, "index", 5);
            func_node = ts_node_child_by_field_name(func_node, "operand", 7);
        }
        const CBMType *indexed = conversion ? go_conversion_index_callable(ctx, conversion_type)
                                          : cbm_type_unknown();
        if (conversion && (!rfunc || !rfunc->type_param_names) &&
            indexed->kind != CBM_TYPE_FUNC) {
            TSNode name = func_node;
            if (strcmp(ts_node_type(func_node), "qualified_type") == 0)
                name = ts_node_child_by_field_name(func_node, "package", 7);
            char *local = lsp_node_text(ctx, name);
            if (local && cbm_scope_contains(ctx->current_scope, local))
                return cbm_type_unknown();
            return go_parse_type_node(ctx, conversion_type);
        }

        // Check for builtin calls
        if (!conversion && strcmp(ts_node_type(func_node), "identifier") == 0) {
            char *name = lsp_node_text(ctx, func_node);
            if (name && cbm_go_is_builtin_func(name) &&
                !cbm_scope_contains(ctx->current_scope, name) &&
                !cbm_registry_lookup_symbol(ctx->registry, ctx->package_qn, name)) {
                return go_eval_builtin_call(ctx, name, args_node);
            }
        }

        // Evaluate function type
        const CBMType *call_type = indexed->kind == CBM_TYPE_FUNC ? indexed :
                                  conversion ? rfunc->signature : go_eval_expr_type(ctx, func_node);
        /* Converting to a named function type does not call that function. */
        if (call_type && call_type->kind == CBM_TYPE_NAMED &&
            go_callee_is_type_name(ctx, func_node))
            return call_type;
        const CBMType *func_type = go_underlying_type(ctx, call_type);

        // If it's a FUNC type, return its return type
        if (func_type && func_type->kind == CBM_TYPE_FUNC && func_type->data.func.return_types &&
            func_type->data.func.return_types[0]) {

            if (rfunc && rfunc->type_param_names) {
                int tpc = 0;
                while (rfunc->type_param_names[tpc])
                    tpc++;
                if (tpc > 16 && !ts_node_is_null(targs_node))
                    return cbm_type_unknown();
                if (tpc > 0 && tpc <= 16) {
                    const CBMType *inferred[17] = {0};
                    int supplied = 0;
                    if (!ts_node_is_null(targs_node)) {
                        uint32_t count = single_type_arg ? 1 : ts_node_named_child_count(targs_node);
                        for (uint32_t i = 0; i < count; i++) {
                            TSNode arg = single_type_arg ? targs_node
                                                        : ts_node_named_child(targs_node, i);
                            if (strcmp(ts_node_type(arg), "comment") == 0)
                                continue;
                            if (supplied == tpc)
                                return cbm_type_unknown();
                            inferred[supplied++] = go_parse_type_node(ctx, arg);
                        }
                        if (supplied == 0)
                            return cbm_type_unknown();
                    }

                    /* Explicit arguments fix a prefix; infer the remaining parameters. */
                    bool single_arg = conversion && ts_node_is_null(args_node);
                    TSNode arguments = single_arg
                        ? ts_node_child_by_field_name(node, "operand", 7) : args_node;
                    if (supplied < tpc && func_type->data.func.param_types &&
                        !ts_node_is_null(arguments)) {
                        uint32_t count = single_arg ? 1 : ts_node_named_child_count(arguments);
                        int pi = 0;
                        for (uint32_t i = 0; i < count && func_type->data.func.param_types[pi]; i++) {
                            TSNode arg = single_arg ? arguments : ts_node_named_child(arguments, i);
                            if (strcmp(ts_node_type(arg), "comment") == 0)
                                continue;
                            const CBMType *argument_type;
                            bool expanded = strcmp(ts_node_type(arg), "variadic_argument") == 0;
                            if (expanded) {
                                const CBMType *slice_type = go_underlying_type(
                                    ctx, go_eval_expr_type(ctx, ts_node_named_child(arg, 0)));
                                argument_type = slice_type->kind == CBM_TYPE_SLICE
                                                    ? slice_type->data.slice.elem
                                                    : cbm_type_unknown();
                            } else {
                                argument_type = go_eval_expr_type(ctx, arg);
                                /* Only the outer composite matches by underlying type. */
                                CBMTypeKind kind = func_type->data.func.param_types[pi]->kind;
                                if (kind == CBM_TYPE_SLICE || kind == CBM_TYPE_POINTER ||
                                    kind == CBM_TYPE_MAP || kind == CBM_TYPE_CHANNEL ||
                                    kind == CBM_TYPE_FUNC)
                                    argument_type = go_underlying_type(ctx, argument_type);
                            }
                            if (!go_unify_type(ctx, func_type->data.func.param_types[pi],
                                               argument_type, rfunc->type_param_names, inferred,
                                               tpc, supplied, !expanded))
                                return cbm_type_unknown();
                            pi++;
                        }
                    }

                    bool complete = true;
                    for (int i = 0; i < tpc; i++) {
                        if (!inferred[i]) {
                            complete = false;
                            break;
                        }
                    }
                    if (complete) {
                        if (!func_type->data.func.return_types[1])
                            return go_instantiate_type(ctx, func_type->data.func.return_types[0],
                                                        rfunc->type_param_names, inferred, 0);
                        int count = 0;
                        while (func_type->data.func.return_types[count])
                            count++;
                        const CBMType **returns = cbm_arena_calloc(
                            ctx->arena, (count + 1) * sizeof(*returns));
                        if (!returns)
                            return cbm_type_unknown();
                        for (int i = 0; i < count; i++)
                            returns[i] = go_instantiate_type(
                                ctx, func_type->data.func.return_types[i],
                                rfunc->type_param_names, inferred, 0);
                        return cbm_type_tuple(ctx->arena, returns, count);
                    }
                }
            }

            // No type arguments or no substitution needed — return as-is
            if (!func_type->data.func.return_types[1]) {
                return func_type->data.func.return_types[0];
            }
            int count = 0;
            while (func_type->data.func.return_types[count])
                count++;
            if (count > 1) {
                return cbm_type_tuple(ctx->arena, func_type->data.func.return_types, count);
            }
        }

        // Type conversion with composite type syntax: []byte(s), map[K]V(x), etc.
        // The function node is a type node (slice_type, map_type, etc.)
        {
            const char *fk = ts_node_type(func_node);
            if (strcmp(fk, "slice_type") == 0 || strcmp(fk, "array_type") == 0 ||
                strcmp(fk, "map_type") == 0 || strcmp(fk, "pointer_type") == 0 ||
                strcmp(fk, "channel_type") == 0) {
                return go_parse_type_node(ctx, func_node);
            }
        }

        return cbm_type_unknown();
    }

    // --- Composite literal: Type{...} ---
    if (strcmp(kind, "composite_literal") == 0) {
        TSNode type_node = ts_node_child_by_field_name(node, "type", 4);
        if (!ts_node_is_null(type_node)) {
            return go_parse_type_node(ctx, type_node);
        }
        return cbm_type_unknown();
    }

    // --- Unary expression: &x, *x, <-ch, !x ---
    if (strcmp(kind, "unary_expression") == 0) {
        TSNode operand = ts_node_child_by_field_name(node, "operand", 7);
        if (ts_node_is_null(operand))
            return cbm_type_unknown();

        // Get operator
        for (uint32_t i = 0; i < ts_node_child_count(node); i++) {
            TSNode child = ts_node_child(node, i);
            if (!ts_node_is_named(child)) {
                char *op = lsp_node_text(ctx, child);
                if (!op)
                    continue;
                if (strcmp(op, "&") == 0) {
                    return cbm_type_pointer(ctx->arena, go_eval_expr_type(ctx, operand));
                }
                if (strcmp(op, "*") == 0) {
                    return cbm_type_deref(go_eval_expr_type(ctx, operand));
                }
                if (strcmp(op, "<-") == 0) {
                    const CBMType *ch_type = go_eval_expr_type(ctx, operand);
                    if (ch_type && ch_type->kind == CBM_TYPE_CHANNEL) {
                        return ch_type->data.channel.elem;
                    }
                    return cbm_type_unknown();
                }
                if (strcmp(op, "!") == 0) {
                    return cbm_type_builtin(ctx->arena, "bool");
                }
                break;
            }
        }
        return cbm_type_unknown();
    }

    // --- Index expression: a[i] ---
    if (strcmp(kind, "index_expression") == 0) {
        TSNode operand = ts_node_child_by_field_name(node, "operand", 7);
        if (ts_node_is_null(operand))
            return cbm_type_unknown();
        return go_index_element_type(ctx, go_eval_expr_type(ctx, operand));
    }

    // --- Type assertion: x.(Type) ---
    if (strcmp(kind, "type_assertion_expression") == 0) {
        TSNode type_node = ts_node_child_by_field_name(node, "type", 4);
        if (!ts_node_is_null(type_node)) {
            return go_parse_type_node(ctx, type_node);
        }
        return cbm_type_unknown();
    }

    // --- Parenthesized expression: (x) ---
    if (strcmp(kind, "parenthesized_expression") == 0 && ts_node_named_child_count(node) > 0) {
        return go_eval_expr_type(ctx, ts_node_named_child(node, 0));
    }

    // --- Binary expression ---
    if (strcmp(kind, "binary_expression") == 0) {
        // For comparisons, return bool
        // For arithmetic, return left operand type
        TSNode left = ts_node_child_by_field_name(node, "left", 4);
        for (uint32_t i = 0; i < ts_node_child_count(node); i++) {
            TSNode child = ts_node_child(node, i);
            if (!ts_node_is_named(child)) {
                char *op = lsp_node_text(ctx, child);
                if (op && (strcmp(op, "==") == 0 || strcmp(op, "!=") == 0 || strcmp(op, "<") == 0 ||
                           strcmp(op, ">") == 0 || strcmp(op, "<=") == 0 || strcmp(op, ">=") == 0 ||
                           strcmp(op, "&&") == 0 || strcmp(op, "||") == 0)) {
                    return cbm_type_builtin(ctx->arena, "bool");
                }
                break;
            }
        }
        if (!ts_node_is_null(left))
            return go_eval_expr_type(ctx, left);
        return cbm_type_unknown();
    }

    // --- Slice expression: a[low:high] ---
    if (strcmp(kind, "slice_expression") == 0) {
        TSNode operand = ts_node_child_by_field_name(node, "operand", 7);
        if (!ts_node_is_null(operand))
            return go_eval_expr_type(ctx, operand);
        return cbm_type_unknown();
    }

    // --- Literals ---
    if (strcmp(kind, "interpreted_string_literal") == 0 ||
        strcmp(kind, "raw_string_literal") == 0) {
        return cbm_type_builtin(ctx->arena, "string");
    }
    if (strcmp(kind, "int_literal") == 0) {
        return cbm_type_builtin(ctx->arena, "int");
    }
    if (strcmp(kind, "float_literal") == 0) {
        return cbm_type_builtin(ctx->arena, "float64");
    }
    if (strcmp(kind, "true") == 0 || strcmp(kind, "false") == 0) {
        return cbm_type_builtin(ctx->arena, "bool");
    }
    if (strcmp(kind, "nil") == 0) {
        return cbm_type_unknown(); // nil has no concrete type
    }

    // --- Func literal (closure) ---
    if (strcmp(kind, "func_literal") == 0)
        return go_parse_type_node(ctx, node);

    return cbm_type_unknown();
}

// --- go_eval_builtin_call ---

const CBMType *go_eval_builtin_call(GoLSPContext *ctx, const char *name, TSNode args) {
    // make(Type, ...) -> Type
    if (strcmp(name, "make") == 0 && !ts_node_is_null(args)) {
        uint32_t nc = ts_node_named_child_count(args);
        if (nc > 0) {
            TSNode first_arg = ts_node_named_child(args, 0);
            return go_parse_type_node(ctx, first_arg);
        }
    }

    // new(Type) / new(value) -> pointer to the type or value's inferred type
    if (strcmp(name, "new") == 0 && !ts_node_is_null(args)) {
        uint32_t nc = ts_node_named_child_count(args);
        if (nc > 0) {
            TSNode first_arg = ts_node_named_child(args, 0);
            const CBMType *type = NULL;
            const char *kind = ts_node_type(first_arg);
            /* Older grammars classify new(v)'s value as a type_identifier. */
            if (strcmp(kind, "type_identifier") == 0 || strcmp(kind, "identifier") == 0) {
                const char *name = lsp_node_text(ctx, first_arg);
                if (name && cbm_scope_contains(ctx->current_scope, name)) {
                    type = cbm_scope_lookup(ctx->current_scope, name);
                    return cbm_type_pointer(ctx->arena, type ? type : cbm_type_unknown());
                }
            }
            type = go_parse_type_node(ctx, first_arg);
            if (cbm_type_is_unknown(type))
                type = go_eval_expr_type(ctx, first_arg);
            return cbm_type_pointer(ctx->arena, type);
        }
    }

    // append(slice, ...) -> same slice type
    if (strcmp(name, "append") == 0 && !ts_node_is_null(args)) {
        uint32_t nc = ts_node_named_child_count(args);
        if (nc > 0) {
            return go_eval_expr_type(ctx, ts_node_named_child(args, 0));
        }
    }

    // len, cap -> int
    if (strcmp(name, "len") == 0 || strcmp(name, "cap") == 0) {
        return cbm_type_builtin(ctx->arena, "int");
    }

    // delete -> void (no return)
    if (strcmp(name, "delete") == 0) {
        return cbm_type_unknown();
    }

    return cbm_type_unknown();
}

// --- Import-alias re-qualification ------------------------------------
//
// parse_field_defs qualifies a struct field type text the defining file's
// scope did not resolve (no identity in the def's type_scope) as
// "<def_module>.<text>". Written through an import alias ("Svc:svc.Svc" in
// module test.main), that yields a QN ("test.main.svc.Svc") that exists
// nowhere in the project-wide registry. On an exact-QN miss this rewrites the
// alias segment through the calling file's imports; returns NULL when no alias
// segment is involved.

static const char *go_requalify_via_imports(GoLSPContext *ctx, const char *type_qn) {
    if (!ctx || !type_qn || !type_qn[0] || ctx->import_count <= 0)
        return NULL;
    for (int j = 0; j < ctx->import_count; j++) {
        const char *alias = ctx->import_local_names[j];
        const char *alias_qn = ctx->import_package_qns[j];
        if (!alias || !alias[0] || !alias_qn || strchr(alias, '.'))
            continue;
        size_t alias_len = strlen(alias);
        /* Last occurrence of a "<dot>alias<dot>" segment in type_qn. */
        const char *hit = NULL;
        for (const char *p = type_qn;;) {
            p = strstr(p, ".");
            if (!p)
                break;
            p++;
            if (strncmp(p, alias, alias_len) == 0 && p[alias_len] == '.') {
                hit = p;
                p += alias_len;
            }
        }
        if (hit) {
            const char *rest = hit + alias_len + 1; /* past "<alias>." */
            return cbm_arena_sprintf(ctx->arena, "%s.%s", alias_qn, rest);
        }
    }
    return NULL;
}

const CBMRegisteredFunc *go_lookup_field_or_method(GoLSPContext *ctx, const char *type_qn,
                                                   const char *member_name) {
    CBMType type = {.kind = CBM_TYPE_NAMED, .data.named.qualified_name = type_qn};
    return go_lookup_member(ctx, &type, member_name).method;
}

static GoMember go_lookup_member(GoLSPContext *ctx, const CBMType *type, const char *name) {
    GoMember none = {0};
    if (!ctx || !type || !name)
        return none;
    struct {
        const CBMType *type;
        const char *qn;
    } queue[128] = {{type, NULL}};
    int head = 0, tail = 1;
    /* Keep separate embedding paths: a diamond is ambiguous even when both
     * paths reach the same declaration. Bounds also stop recursive embeds. */
    for (int depth = 0; head < tail && depth <= CBM_LSP_MAX_LOOKUP_DEPTH; depth++) {
        int end = tail, matches = 0;
        bool incomplete = false, overflow = false;
        GoMember found = {0};
        while (head < end) {
            const CBMType *base = queue[head].type;
            const char *qn = queue[head++].qn;
            if (base) {
                base = go_member_base_type(base);
                const char *base_qn = go_member_type_qn(base);
                if (base_qn)
                    qn = base_qn;
            }
            const char **fields = NULL, **embedded_qns = NULL;
            const CBMType **field_types = NULL, **embedded = NULL;
            const CBMRegisteredType *rt = NULL;
            if (qn) {
                if (!base)
                    base = cbm_type_named(ctx->arena, qn);
                rt = go_member_registered_type(ctx, &base);
                if (!rt || rt->is_interface) {
                    incomplete = true;
                    continue;
                }
                qn = rt->qualified_name;
                fields = rt->field_names;
                field_types = rt->field_types;
                embedded_qns = rt->embedded_types;
            } else if (base && base->kind == CBM_TYPE_STRUCT) {
                fields = base->data.struct_type.field_names;
                field_types = base->data.struct_type.field_types;
                embedded = base->data.struct_type.embedded_types;
            } else {
                incomplete = true;
                continue;
            }
            const CBMType **args = base && base->kind == CBM_TYPE_TEMPLATE
                                       ? base->data.template_type.template_args : NULL;
            GoMember member = {0};
            for (int i = 0; fields && fields[i]; i++) {
                if (strcmp(fields[i], name) == 0) {
                    member.field = field_types && field_types[i]
                                       ? field_types[i] : cbm_type_unknown();
                    if (rt && args)
                        member.field = go_instantiate_type(
                            ctx, member.field, rt->type_param_names, args, 0);
                    break;
                }
            }
            if (!member.field && qn) {
                member.method = cbm_registry_lookup_method(ctx->registry, qn, name);
                if (member.method &&
                    !go_type_arguments_match(base, member.method->type_param_names))
                    member.method = NULL;
                if (member.method)
                    member.signature = go_instantiate_type(
                        ctx, member.method->signature,
                        member.method->type_param_names
                            ? member.method->type_param_names : rt ? rt->type_param_names : NULL,
                        args, 0);
            }
            /* Registered named structs may store embeds separately from fields. */
            for (int i = 0; !member.field && !member.method &&
                            embedded_qns && embedded_qns[i]; i++) {
                const char *embed = embedded_qns[i];
                const char *dot = strrchr(embed, '.');
                if (strcmp(dot ? dot + 1 : embed, name) == 0 &&
                    (!dot || !go_private_stdlib_name(embed, (size_t)(dot - embed), name)))
                    member.field = cbm_type_named(ctx->arena, embed);
            }
            if (member.field || member.method) {
                found = member;
                matches++;
                continue;
            }
            for (int i = 0; (embedded && embedded[i]) ||
                            (embedded_qns && embedded_qns[i]); i++) {
                if (tail == (int)(sizeof(queue) / sizeof(queue[0]))) {
                    overflow = true;
                    break;
                }
                const CBMType *embedded_type = embedded ? embedded[i] : NULL;
                if (!embedded_type && embedded_qns && embedded_qns[i]) {
                    const char *dot = strrchr(embedded_qns[i], '.');
                    const char *short_name = dot ? dot + 1 : embedded_qns[i];
                    for (int j = 0; fields && fields[j]; j++) {
                        if (strcmp(fields[j], short_name) == 0 && field_types) {
                            embedded_type = field_types[j];
                            break;
                        }
                    }
                    if (rt && embedded_type && args)
                        embedded_type = go_instantiate_type(
                            ctx, embedded_type, rt->type_param_names, args, 0);
                }
                queue[tail].type = embedded_type;
                queue[tail++].qn = embedded_qns ? embedded_qns[i] : NULL;
            }
        }
        if (matches)
            return matches == 1 && !incomplete ? found : none;
        if (incomplete || overflow)
            return none;
    }
    return none;
}

typedef struct GoCallableBinding {
    struct GoCallableBinding *origin;
    bool captured_write;
} GoCallableBinding;

static GoCallableBinding *go_callable_binding(GoLSPContext *ctx,
                                              const CBMVarBinding *binding, bool create) {
    if (!binding || !ctx->callable_bindings || ctx->callable_tracking_failed)
        return NULL;
    char key[2 * sizeof(void *) + 8];
    snprintf(key, sizeof(key), "%p", (const void *)binding);
    GoCallableBinding *entry = cbm_ht_get(ctx->callable_bindings, key);
    if (!entry && create) {
        entry = cbm_arena_calloc(ctx->arena, sizeof(*entry));
        char *owned_key = cbm_arena_strdup(ctx->arena, key);
        if (entry && owned_key) {
            entry->origin = entry;
            cbm_ht_set(ctx->callable_bindings, owned_key, entry);
        }
        if (!entry || !owned_key || cbm_ht_get(ctx->callable_bindings, key) != entry) {
            ctx->callable_tracking_failed = true;
            return NULL;
        }
    }
    return entry;
}

static const char *go_lexical_callable_target(GoLSPContext *ctx, const char *name) {
    if (ctx->callable_tracking_failed)
        return NULL;
    /* shortcut: captured callable cells stay dynamic until closure execution is modeled. */
    for (const CBMScope *scope = ctx->current_scope;
         scope && scope != ctx->capture_parent; scope = scope->parent) {
        const CBMVarBinding *binding = cbm_scope_lookup_local(scope, name);
        if (binding) {
            GoCallableBinding *entry = go_callable_binding(ctx, binding, false);
            return entry && entry->origin->captured_write ? NULL : binding->callable_qn;
        }
    }
    return NULL;
}

/* Resolve only source forms that prove one callable identity.  This is
 * intentionally narrower than go_eval_expr_type: conditional expressions,
 * indexed dispatch tables, interfaces, and unknown
 * locals remain ordinary values. */
static const char *go_exact_callable_target(GoLSPContext *ctx, TSNode node) {
    if (!ctx || ts_node_is_null(node))
        return NULL;
    const char *kind = ts_node_type(node);

    if (strcmp(kind, "index_expression") == 0) {
        const CBMRegisteredFunc *function = go_registered_callable(ctx, node);
        return function ? function->qualified_name : NULL;
    }

    if (strcmp(kind, "parenthesized_expression") == 0 && ts_node_named_child_count(node) == 1) {
        return go_exact_callable_target(ctx, ts_node_named_child(node, 0));
    }

    if (strcmp(kind, "identifier") == 0 || strcmp(kind, "type_identifier") == 0) {
        char *name = lsp_node_text(ctx, node);
        if (!name)
            return NULL;
        /* A local value shadows the package declaration even when its type is
         * UNKNOWN.  Only an explicitly tracked callable alias may pass. */
        if (cbm_scope_contains(ctx->current_scope, name)) {
            return go_lexical_callable_target(ctx, name);
        }
        const CBMRegisteredFunc *f = go_lookup_callable(ctx->registry, ctx->package_qn, name);
        return f ? f->qualified_name : NULL;
    }

    if (strcmp(kind, "selector_expression") == 0 || strcmp(kind, "qualified_type") == 0) {
        bool qualified_type = strcmp(kind, "qualified_type") == 0;
        TSNode operand = qualified_type ? ts_node_child_by_field_name(node, "package", 7)
                                        : ts_node_child_by_field_name(node, "operand", 7);
        TSNode field = qualified_type ? ts_node_child_by_field_name(node, "name", 4)
                                      : ts_node_child_by_field_name(node, "field", 5);
        if (ts_node_is_null(operand) || ts_node_is_null(field))
            return NULL;
        char *member = lsp_node_text(ctx, field);
        if (!member)
            return NULL;

        if (strcmp(ts_node_type(operand), "identifier") == 0 ||
            strcmp(ts_node_type(operand), "package_identifier") == 0) {
            char *local = lsp_node_text(ctx, operand);
            const char *package_qn = local ? resolve_import(ctx, local) : NULL;
            if (package_qn && !cbm_scope_contains(ctx->current_scope, local)) {
                const CBMRegisteredFunc *f = go_lookup_callable(ctx->registry, package_qn, member);
                return f ? f->qualified_name : NULL;
            }
        }

        const CBMType *recv = go_member_base_type(go_eval_expr_type(ctx, operand));
        const char *receiver_qn = go_member_type_qn(recv);
        if (receiver_qn) {
            const CBMRegisteredType *rt = go_member_registered_type(ctx, &recv);
            if (!rt || rt->is_interface)
                return NULL;
            /* A direct method name is unique in a valid Go method set.
             * Promoted lookup through embedded types can be ambiguous; without
             * full selector-depth resolution, fail closed and retain USAGE. */
            const CBMRegisteredFunc *method =
                cbm_registry_lookup_method(ctx->registry, rt->qualified_name, member);
            return method && go_type_arguments_match(recv, method->type_param_names)
                       ? method->qualified_name : NULL;
        }
    }
    return NULL;
}

static void go_scope_bind_value(CBMScope *scope, const char *name, const CBMType *type,
                                const char *callable_qn) {
    if (callable_qn) {
        cbm_scope_bind_callable(scope, name, type, callable_qn);
    } else {
        cbm_scope_bind(scope, name, type);
    }
}

/* Ordinary blocks update an existing local. Guarded paths and closures keep
 * writes to captured values in an overlay that disappears at their boundary. */
static CBMScope *go_assignment_scope(GoLSPContext *ctx, const char *name) {
    CBMScope *floor = ctx->assignment_floor ? ctx->assignment_floor : ctx->current_scope;
    for (CBMScope *scope = ctx->current_scope; scope; scope = scope->parent) {
        if (cbm_scope_lookup_local(scope, name) || scope == floor)
            return scope;
    }
    return ctx->current_scope;
}

static void go_bind_assignment(GoLSPContext *ctx, const char *name, const CBMType *type,
                               const char *callable) {
    CBMScope *target = go_assignment_scope(ctx, name);
    const CBMVarBinding *previous = NULL;
    bool captured = false;
    for (const CBMScope *scope = ctx->current_scope; scope; scope = scope->parent) {
        if (scope == ctx->capture_parent)
            captured = true;
        previous = cbm_scope_lookup_local(scope, name);
        if (previous)
            break;
    }
    GoCallableBinding *entry = go_callable_binding(ctx, previous, true);
    GoCallableBinding *origin = entry ? entry->origin : NULL;
    if (captured && origin)
        origin->captured_write = true;
    go_scope_bind_value(target, name, type, callable);
    const CBMVarBinding *written = cbm_scope_lookup_local(target, name);
    if (!written) {
        ctx->callable_tracking_failed = true;
        return;
    }
    if (origin) {
        entry = go_callable_binding(ctx, written, true);
        if (entry)
            entry->origin = origin;
    }
}

static bool go_assigns_existing_value(TSNode node) {
    const char *kind = ts_node_type(node);
    if (strcmp(kind, "assignment_statement") == 0)
        return true;
    if (strcmp(kind, "range_clause") != 0 && strcmp(kind, "receive_statement") != 0)
        return false;
    for (uint32_t i = 0; i < ts_node_child_count(node); i++) {
        if (strcmp(ts_node_type(ts_node_child(node, i)), "=") == 0)
            return true;
    }
    return false;
}

// --- go_process_statement: bind variables from statements ---

typedef struct {
    const CBMType *type;
    const char *callable;
} GoBindingValue;

/* Evaluate every RHS before publishing any LHS, including swaps and shadows. */
static GoBindingValue *go_eval_binding_values(GoLSPContext *ctx, TSNode right, uint32_t count) {
    if (count == 0)
        return NULL;
    GoBindingValue *values = cbm_arena_alloc(ctx->arena, (size_t)count * sizeof(*values));
    if (!values)
        return NULL;
    for (uint32_t i = 0; i < count; i++)
        values[i] = (GoBindingValue){.type = cbm_type_unknown()};
    if (ts_node_is_null(right))
        return values;
    bool list = strcmp(ts_node_type(right), "expression_list") == 0;
    uint32_t rhs_count = list ? ts_node_named_child_count(right) : 1;
    if (rhs_count == count) {
        for (uint32_t i = 0; i < count; i++) {
            TSNode rhs = list ? ts_node_named_child(right, i) : right;
            values[i].type = go_eval_expr_type(ctx, rhs);
            values[i].callable = go_exact_callable_target(ctx, rhs);
        }
    } else if (rhs_count == 1) {
        TSNode rhs = list ? ts_node_named_child(right, 0) : right;
        const CBMType *type = go_eval_expr_type(ctx, rhs);
        if (type && type->kind == CBM_TYPE_TUPLE && type->data.tuple.count == (int)count) {
            for (uint32_t i = 0; i < count; i++)
                values[i].type = type->data.tuple.elems[i];
        } else {
            /* Comma-ok expressions retain their first value without callable proof. */
            values[0].type = type;
        }
    }
    return values;
}

void go_process_statement(GoLSPContext *ctx, TSNode node) {
    if (ts_node_is_null(node))
        return;
    const char *kind = ts_node_type(node);
    if ((strcmp(kind, "type_spec") == 0 || strcmp(kind, "type_alias") == 0) &&
        ctx->current_scope && ctx->current_scope->parent) {
        TSNode name_node = ts_node_child_by_field_name(node, "name", 4);
        char *name = ts_node_is_null(name_node) ? NULL : lsp_node_text(ctx, name_node);
        if (name && strcmp(name, "_") != 0)
            cbm_scope_bind_type(ctx->current_scope, name);
        return;
    }

    if (strcmp(kind, "short_var_declaration") == 0 ||
        strcmp(kind, "assignment_statement") == 0) {
        TSNode left = ts_node_child_by_field_name(node, "left", 4);
        TSNode right = ts_node_child_by_field_name(node, "right", 5);
        if (ts_node_is_null(left) || ts_node_is_null(right))
            return;

        bool list = strcmp(ts_node_type(left), "expression_list") == 0;
        bool assignment = go_assigns_existing_value(node);
        uint32_t lhs_count = list ? ts_node_named_child_count(left) : 1;
        GoBindingValue *values = go_eval_binding_values(ctx, right, lhs_count);
        for (uint32_t i = 0; i < lhs_count; i++) {
            TSNode lhs = list ? ts_node_named_child(left, i) : left;
            if (ts_node_is_null(lhs) || strcmp(ts_node_type(lhs), "identifier") != 0)
                continue;
            char *name = lsp_node_text(ctx, lhs);
            if (!name || strcmp(name, "_") == 0)
                continue;
            const CBMType *type = values ? values[i].type : cbm_type_unknown();
            const char *callable = values ? values[i].callable : NULL;
            if (assignment)
                go_bind_assignment(ctx, name, type, callable);
            else
                go_scope_bind_value(ctx->current_scope, name, type, callable);
        }
        return;
    }

    if (strcmp(kind, "var_spec") == 0 || strcmp(kind, "const_spec") == 0) {
        TSNode type_node = ts_node_child_by_field_name(node, "type", 4);
        TSNode value_node = ts_node_child_by_field_name(node, "value", 5);

        const CBMType *declared_type =
            ts_node_is_null(type_node) ? NULL : go_parse_type_node(ctx, type_node);
        uint32_t count = 0;
        uint32_t vnc = ts_node_child_count(node);
        for (uint32_t vi = 0; vi < vnc; vi++) {
            TSNode ch = ts_node_child(node, vi);
            if (!ts_node_is_null(ch) && strcmp(ts_node_type(ch), "identifier") == 0)
                count++;
        }
        GoBindingValue *values = go_eval_binding_values(ctx, value_node, count);
        uint32_t index = 0;
        for (uint32_t vi = 0; vi < vnc; vi++) {
            TSNode ch = ts_node_child(node, vi);
            if (ts_node_is_null(ch) || strcmp(ts_node_type(ch), "identifier") != 0)
                continue;
            const CBMType *type = declared_type ? declared_type
                                               : values ? values[index].type : cbm_type_unknown();
            const char *callable = values ? values[index].callable : NULL;
            /* Package variables can be reassigned by another function or file. */
            if (ctx->current_scope && !ctx->current_scope->parent)
                callable = NULL;
            index++;
            char *name = lsp_node_text(ctx, ch);
            if (name && strcmp(name, "_") != 0)
                go_scope_bind_value(ctx->current_scope, name, type, callable);
        }
        return;
    }

    // range_clause: for k, v := range container
    if (strcmp(kind, "range_clause") == 0) {
        TSNode left = ts_node_child_by_field_name(node, "left", 4);
        TSNode right = ts_node_child_by_field_name(node, "right", 5);
        if (ts_node_is_null(right))
            return;

        const CBMType *container_type = go_eval_expr_type(ctx, right);

        // Determine key and value types based on container type
        const CBMType *key_type = cbm_type_unknown();
        const CBMType *val_type = cbm_type_unknown();

        if (container_type) {
            switch (container_type->kind) {
            case CBM_TYPE_SLICE:
                key_type = cbm_type_builtin(ctx->arena, "int");
                val_type = container_type->data.slice.elem;
                break;
            case CBM_TYPE_MAP:
                key_type = container_type->data.map.key;
                val_type = container_type->data.map.value;
                break;
            case CBM_TYPE_CHANNEL:
                val_type = container_type->data.channel.elem;
                break;
            default:
                if (container_type->kind == CBM_TYPE_BUILTIN &&
                    strcmp(container_type->data.builtin.name, "string") == 0) {
                    key_type = cbm_type_builtin(ctx->arena, "int");
                    val_type = cbm_type_builtin(ctx->arena, "rune");
                }
                break;
            }
        }

        if (!ts_node_is_null(left) && strcmp(ts_node_type(left), "expression_list") == 0) {
            uint32_t lhs_count = ts_node_named_child_count(left);
            for (uint32_t i = 0; i < lhs_count; i++) {
                TSNode var_node = ts_node_named_child(left, i);
                if (strcmp(ts_node_type(var_node), "identifier") != 0)
                    continue;
                char *var_name = lsp_node_text(ctx, var_node);
                if (!var_name || strcmp(var_name, "_") == 0)
                    continue;
                if (go_assigns_existing_value(node))
                    go_bind_assignment(ctx, var_name, i == 0 ? key_type : val_type, NULL);
                else
                    cbm_scope_bind(ctx->current_scope, var_name,
                                   i == 0 ? key_type : val_type);
            }
        }
        return;
    }

    // type_switch_statement is handled in resolve_calls_in_node, not here
    // (needs per-case scope narrowing, not just variable binding)
}

// --- Emit a resolved call/reference ---

static void go_emit_resolved_kind(GoLSPContext *ctx, const char *callee_qn, const char *strategy,
                                  float confidence, const char *source_name, CBMResolvedKind kind,
                                  TSNode site) {
    if (!ctx->resolved_calls || !callee_qn || !ctx->enclosing_func_qn)
        return;

    CBMResolvedCall rc = {0};
    rc.caller_qn = ctx->enclosing_func_qn;
    rc.callee_qn = callee_qn;
    rc.strategy = strategy;
    rc.confidence = confidence;
    /* When a callable alias has a different textual leaf, retain that source
     * name for the exact-site join. */
    rc.reason = source_name;
    rc.kind = kind;
    if (!ts_node_is_null(site)) {
        rc.site_start_byte = ts_node_start_byte(site);
        rc.site_end_byte = ts_node_end_byte(site);
    }
    cbm_resolvedcall_push(ctx->resolved_calls, ctx->arena, rc);
}

static void emit_resolved_call(GoLSPContext *ctx, const char *callee_qn, const char *strategy,
                               float confidence, TSNode site) {
    go_emit_resolved_kind(ctx, callee_qn, strategy, confidence, NULL, CBM_RESOLVED_INVOCATION,
                          site);
}

static void emit_resolved_alias_call(GoLSPContext *ctx, const char *callee_qn,
                                     const char *source_name, TSNode site) {
    go_emit_resolved_kind(ctx, callee_qn, "lsp_callable_alias", 0.97f, source_name,
                          CBM_RESOLVED_INVOCATION, site);
}

static void emit_resolved_reference(GoLSPContext *ctx, const char *callee_qn,
                                    const char *source_name, TSNode site) {
    const char *leaf = strrchr(callee_qn, '.');
    leaf = leaf ? leaf + 1 : callee_qn;
    const char *join_name = source_name && strcmp(source_name, leaf) != 0 ? source_name : NULL;
    go_emit_resolved_kind(ctx, callee_qn, "lsp_callable_value_reference", 0.97f, join_name,
                          CBM_RESOLVED_CALL_REFERENCE, site);
}

static void emit_unresolved_reference(GoLSPContext *ctx, const char *source_name, TSNode site) {
    if (!ctx || !ctx->resolved_calls || !ctx->enclosing_func_qn || !source_name ||
        ts_node_is_null(site)) {
        return;
    }
    CBMResolvedCall rc = {0};
    rc.caller_qn = ctx->enclosing_func_qn;
    rc.callee_qn = source_name;
    rc.strategy = "lsp_unresolved";
    rc.confidence = 0.0f;
    rc.reason = "callable_value_not_in_registry";
    rc.kind = CBM_RESOLVED_CALL_REFERENCE;
    rc.site_start_byte = ts_node_start_byte(site);
    rc.site_end_byte = ts_node_end_byte(site);
    cbm_resolvedcall_push(ctx->resolved_calls, ctx->arena, rc);
}

// Emit a diagnostic for an unresolved call (confidence 0.0).
static void emit_unresolved_call(GoLSPContext *ctx, const char *expr_text, const char *reason,
                                 TSNode site) {
    if (!ctx->resolved_calls || !ctx->enclosing_func_qn)
        return;

    CBMResolvedCall rc = {0};
    rc.caller_qn = ctx->enclosing_func_qn;
    rc.callee_qn = expr_text ? expr_text : "?";
    rc.strategy = "lsp_unresolved";
    rc.confidence = 0.0f;
    rc.reason = reason;
    rc.kind = CBM_RESOLVED_INVOCATION;
    if (!ts_node_is_null(site)) {
        rc.site_start_byte = ts_node_start_byte(site);
        rc.site_end_byte = ts_node_end_byte(site);
    }
    cbm_resolvedcall_push(ctx->resolved_calls, ctx->arena, rc);
}

/* Only direct argument expressions are candidates. Descending into a
 * conditional/map/index expression would promote its constituent names even
 * though the runtime callable is not statically unique. */
static void go_resolve_value_references_at(GoLSPContext *ctx, TSNode call) {
    TSNode args = ts_node_child_by_field_name(call, "arguments", 9);
    if (ts_node_is_null(args))
        return;
    uint32_t count = ts_node_named_child_count(args);
    for (uint32_t i = 0; i < count; i++) {
        TSNode arg = ts_node_named_child(args, i);
        const char *kind = ts_node_type(arg);
        if (strcmp(kind, "identifier") != 0 && strcmp(kind, "selector_expression") != 0 &&
            strcmp(kind, "parenthesized_expression") != 0)
            continue;
        const char *target = go_exact_callable_target(ctx, arg);
        char *source_name = lsp_node_text(ctx, arg);
        if (target) {
            emit_resolved_reference(ctx, target, source_name, arg);
        } else if (strcmp(kind, "identifier") == 0 && source_name &&
                   !cbm_scope_contains(ctx->current_scope, source_name)) {
            /* The per-file registry cannot see an unqualified function from
             * another file in the same Go package. Preserve the exact source
             * occurrence for the metadata-only project pass. */
            emit_unresolved_reference(ctx, source_name, arg);
        }
    }
}

/* Any assignment that is guarded by a branch/loop makes the post-construct
 * callable identity a join of at least two paths. Clear the outer exact
 * identity before walking the construct; assignments inside its temporary
 * scope may still be exact locally, but cannot leak past the join. */
static void go_invalidate_control_flow_aliases(GoLSPContext *ctx, TSNode node, int depth) {
    if (!ctx || ts_node_is_null(node) || depth > 64)
        return;
    const char *kind = ts_node_type(node);
    if (strcmp(kind, "func_literal") == 0)
        return;
    if (go_assigns_existing_value(node)) {
        TSNode left = ts_node_child_by_field_name(node, "left", 4);
        if (!ts_node_is_null(left)) {
            uint32_t count = strcmp(ts_node_type(left), "expression_list") == 0
                                 ? ts_node_named_child_count(left)
                                 : 1;
            for (uint32_t i = 0; i < count; i++) {
                TSNode target = count == 1 && strcmp(ts_node_type(left), "expression_list") != 0
                                    ? left
                                    : ts_node_named_child(left, i);
                if (ts_node_is_null(target) || strcmp(ts_node_type(target), "identifier") != 0) {
                    continue;
                }
                char *name = lsp_node_text(ctx, target);
                /* Captures already fail closed; only scoped writes may taint their origins. */
                if (name && go_lexical_callable_target(ctx, name)) {
                    go_bind_assignment(ctx, name, cbm_scope_lookup(ctx->current_scope, name),
                                       NULL);
                }
            }
        }
        return;
    }
    uint32_t count = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < count; i++) {
        go_invalidate_control_flow_aliases(ctx, ts_node_named_child(node, i), depth + 1);
    }
}

static bool go_case_falls_through(TSNode node) {
    while (!ts_node_is_null(node)) {
        const char *kind = ts_node_type(node);
        if (strcmp(kind, "fallthrough_statement") == 0)
            return true;
        if (strcmp(kind, "expression_case") != 0 && strcmp(kind, "default_case") != 0 &&
            strcmp(kind, "statement_list") != 0)
            return false;
        TSNode last = {0};
        for (uint32_t i = ts_node_named_child_count(node); i > 0; i--) {
            TSNode child = ts_node_named_child(node, i - 1);
            if (strcmp(ts_node_type(child), "comment") != 0) {
                last = child;
                break;
            }
        }
        node = last;
    }
    return false;
}

static void go_bind_parameter_list(GoLSPContext *ctx, TSNode params) {
    if (ts_node_is_null(params))
        return;
    bool type_params = strcmp(ts_node_type(params), "type_parameter_list") == 0;
    if (!type_params && strcmp(ts_node_type(params), "parameter_list") != 0)
        return;
    uint32_t count = ts_node_named_child_count(params);
    for (uint32_t i = 0; i < count; i++) {
        TSNode param = ts_node_named_child(params, i);
        const char *kind = ts_node_type(param);
        bool variadic = strcmp(kind, "variadic_parameter_declaration") == 0;
        if (!variadic &&
            strcmp(kind, type_params ? "type_parameter_declaration" : "parameter_declaration") != 0)
            continue;
        TSNode type_node = ts_node_child_by_field_name(param, "type", 4);
        const CBMType *type = go_parse_type_node(ctx, type_node);
        if (variadic && type)
            type = cbm_type_slice(ctx->arena, type);
        uint32_t names = ts_node_named_child_count(param);
        for (uint32_t j = 0; j < names; j++) {
            TSNode name_node = ts_node_named_child(param, j);
            if (strcmp(ts_node_type(name_node), "identifier") != 0)
                continue;
            char *name = lsp_node_text(ctx, name_node);
            if (name && strcmp(name, "_") != 0) {
                if (type_params)
                    cbm_scope_bind_type(ctx->current_scope, name);
                else
                    cbm_scope_bind(ctx->current_scope, name, type);
            }
        }
    }
}

// --- Walk call expressions and resolve them ---

static void resolve_calls_in_node_inner(GoLSPContext *ctx, TSNode node) {
    if (ts_node_is_null(node))
        return;
    const char *kind = ts_node_type(node);

    /* A closure the walk reaches is walked with its parameters bound, not
     * as plain children in the enclosing scope. */
    if (strcmp(kind, "func_literal") == 0) {
        go_walk_func_literal(ctx, node);
        return;
    }
    /* A type declared in the function shadows the package's from here on. */
    if (ctx->in_function && strcmp(kind, "type_declaration") == 0) {
        go_shadow_declared_types(ctx, node);
    }

    bool bind_after_children = strcmp(kind, "short_var_declaration") == 0 ||
                               strcmp(kind, "assignment_statement") == 0 ||
                               strcmp(kind, "var_spec") == 0 ||
                               strcmp(kind, "const_spec") == 0 ||
                               strcmp(kind, "range_clause") == 0;
    if (!bind_after_children)
        go_process_statement(ctx, node);

    if (strcmp(kind, "if_statement") == 0 || strcmp(kind, "for_statement") == 0 ||
        strcmp(kind, "expression_switch_statement") == 0 ||
        strcmp(kind, "type_switch_statement") == 0 || strcmp(kind, "select_statement") == 0) {
        go_invalidate_control_flow_aliases(ctx, node, 0);
    }

    if (strcmp(kind, "type_conversion_expression") == 0) {
        TSNode type = ts_node_child_by_field_name(node, "type", 4);
        TSNode written_type = type;
        while (!ts_node_is_null(type) &&
               strcmp(ts_node_type(type), "parenthesized_type") == 0 &&
               ts_node_named_child_count(type) == 1)
            type = ts_node_named_child(type, 0);
        if (!ts_node_is_null(type) && strcmp(ts_node_type(type), "generic_type") == 0) {
            TSNode base = ts_node_child_by_field_name(type, "type", 4);
            const CBMRegisteredFunc *function = go_registered_callable(ctx, base);
            if (function && function->type_param_names)
                emit_resolved_call(ctx, function->qualified_name, "lsp_direct", 0.95f, node);
            else if (go_conversion_index_callable(ctx, type)->kind == CBM_TYPE_FUNC)
                emit_unresolved_call(ctx, lsp_node_text(ctx, written_type),
                                     "lexical_value_not_exact_callable", node);
        }
    }

    // Resolve call expressions
    if (strcmp(kind, "call_expression") == 0) {
        go_resolve_value_references_at(ctx, node);
        TSNode func_node = ts_node_child_by_field_name(node, "function", 8);
        if (!ts_node_is_null(func_node)) {
            const char *fk = ts_node_type(func_node);

            // selector_expression: obj.Method() or pkg.Func()
            if (strcmp(fk, "selector_expression") == 0) {
                TSNode operand = ts_node_child_by_field_name(func_node, "operand", 7);
                TSNode field = ts_node_child_by_field_name(func_node, "field", 5);
                if (!ts_node_is_null(operand) && !ts_node_is_null(field)) {
                    char *field_name = lsp_node_text(ctx, field);

                    // Check if operand is a package import
                    if (strcmp(ts_node_type(operand), "identifier") == 0) {
                        char *pkg_name = lsp_node_text(ctx, operand);
                        if (pkg_name) {
                            const char *pkg_qn = resolve_import(ctx, pkg_name);
                            if (ctx->has_cgo_import && !pkg_qn && field_name &&
                                strcmp(pkg_name, "C") == 0 && go_cgo_builtin(field_name) &&
                                !cbm_scope_contains(ctx->current_scope, pkg_name)) {
                                emit_unresolved_call(
                                    ctx, cbm_arena_sprintf(ctx->arena, "C.%s", field_name),
                                    "external_symbol_not_indexed", node);
                                goto recurse;
                            }
                            if (pkg_qn && field_name &&
                                !cbm_scope_contains(ctx->current_scope, pkg_name)) {
                                const CBMRegisteredFunc *f =
                                    go_lookup_callable(ctx->registry, pkg_qn, field_name);
                                if (f) {
                                    emit_resolved_call(ctx, f->qualified_name, "lsp_direct", 0.95f,
                                                       node);
                                    goto recurse;
                                }
                                const char *type_qn =
                                    cbm_arena_sprintf(ctx->arena, "%s.%s", pkg_qn, field_name);
                                if (!go_private_stdlib_name(pkg_qn, strlen(pkg_qn), field_name) &&
                                    cbm_registry_lookup_type(ctx->registry, type_qn)) {
                                    go_emit_resolved_kind(
                                        ctx, cbm_arena_sprintf(ctx->arena, "%s.%s", pkg_name,
                                                               field_name),
                                        "lsp_type_conversion", 0.0f, NULL,
                                        CBM_RESOLVED_INVOCATION, node);
                                    goto recurse;
                                }
                                bool external =
                                    go_is_stdlib_package(pkg_qn, strlen(pkg_qn));
                                emit_unresolved_call(
                                    ctx,
                                    cbm_arena_sprintf(ctx->arena, "%s.%s",
                                                      external ? pkg_qn : pkg_name, field_name),
                                    external ? "external_symbol_not_indexed"
                                             : "symbol_not_in_registry", node);
                                goto recurse;
                            }
                            if (field_name) {
                                bool conflict = false;
                                const char *target =
                                    go_package_variable_method(ctx, pkg_name, field_name, &conflict);
                                if (target) {
                                    emit_resolved_call(ctx, target, "lsp_type_dispatch", 0.95f,
                                                       node);
                                    goto recurse;
                                }
                                if (conflict) {
                                    emit_unresolved_call(ctx, lsp_node_text(ctx, func_node),
                                                         "symbol_not_in_registry", node);
                                    goto recurse;
                                }
                            }
                        }
                    }

                    // Type-based method dispatch
                    if (field_name) {
                        const CBMType *recv_type = go_eval_expr_type(ctx, operand);
                        const CBMType *base = go_member_base_type(recv_type);

                        if (base && (base->kind == CBM_TYPE_STRUCT ||
                                     go_member_type_qn(base))) {
                            GoMember member = go_lookup_member(ctx, base, field_name);
                            if (member.method) {
                                const char *strategy = "lsp_embed_dispatch";
                                const char *receiver_qn = go_member_type_qn(base);
                                if (receiver_qn &&
                                    !cbm_registry_lookup_type(ctx->registry, receiver_qn)) {
                                    const char *alt = go_requalify_via_imports(ctx, receiver_qn);
                                    if (alt && cbm_registry_lookup_type(ctx->registry, alt))
                                        receiver_qn = alt;
                                }
                                if (receiver_qn && member.method->receiver_type &&
                                    strcmp(member.method->receiver_type, receiver_qn) == 0)
                                    strategy = "lsp_type_dispatch";
                                emit_resolved_call(ctx, member.method->qualified_name,
                                                   strategy, 0.95f, node);
                                goto recurse;
                            }
                            if (member.field && member.field->kind == CBM_TYPE_FUNC) {
                                emit_unresolved_call(ctx, lsp_node_text(ctx, func_node),
                                                     "lexical_value_not_exact_callable", node);
                                goto recurse;
                            }
                        }

                        // Interface dispatch: NAMED type that is an interface, or bare INTERFACE
                        // type
                        if (base && field_name) {
                            bool is_iface = (base->kind == CBM_TYPE_INTERFACE);
                            const char *iface_qn = NULL;
                            if (!is_iface && go_member_type_qn(base)) {
                                const CBMType *iface_type = base;
                                const CBMRegisteredType *rt =
                                    go_member_registered_type(ctx, &iface_type);
                                if (rt && rt->is_interface) {
                                    is_iface = true;
                                    iface_qn = rt->qualified_name;
                                }
                            }
                            if (is_iface) {
                                /* A method set describes the interface contract, not
                                 * the runtime receiver, even with one indexed implementer. */
                                go_emit_resolved_kind(
                                    ctx,
                                    cbm_arena_sprintf(ctx->arena, "%s.%s",
                                                      iface_qn ? iface_qn : "interface",
                                                      field_name),
                                    "lsp_interface_dispatch", 0.0f,
                                    "dynamic_callable_target_unknown",
                                    CBM_RESOLVED_INVOCATION, node);
                                goto recurse;
                            }
                        }

                        // Type resolved to NAMED but neither method nor interface matched
                        const char *receiver_qn = go_member_type_qn(base);
                        if (receiver_qn) {
                            const CBMTypeRegistry *stdlib = go_stdlib_shared();
                            const char *type_qn = receiver_qn;
                            size_t package_len = strcspn(type_qn, ".");
                            bool external =
                                (stdlib && cbm_registry_lookup_type(stdlib, type_qn)) ||
                                (type_qn[package_len] == '.' &&
                                 go_is_stdlib_package(type_qn, package_len));
                            const char *reason = "method_not_found";
                            if (external)
                                reason = "external_symbol_not_indexed";
                            else if (go_imported_type_not_indexed(ctx, receiver_qn))
                                reason = "imported_type_not_indexed";
                            emit_unresolved_call(ctx,
                                                 cbm_arena_sprintf(ctx->arena, "%s.%s",
                                                                   receiver_qn,
                                                                   field_name),
                                                 reason, node);
                        } else {
                            char *operand_text = lsp_node_text(ctx, operand);
                            emit_unresolved_call(
                                ctx,
                                cbm_arena_sprintf(ctx->arena, "%s.%s",
                                                  operand_text ? operand_text : "?", field_name),
                                "unknown_receiver_type", node);
                        }
                    }
                }
            }

            // Direct function call: FuncName()
            if (strcmp(fk, "identifier") == 0) {
                char *name = lsp_node_text(ctx, func_node);
                if (name) {
                    const CBMVarBinding *binding =
                        cbm_scope_lookup_binding(ctx->current_scope, name);
                    if (binding) {
                        const char *callable = go_lexical_callable_target(ctx, name);
                        if (binding->is_type) {
                            go_emit_resolved_kind(ctx, name, "lsp_type_conversion", 0.0f, NULL,
                                                  CBM_RESOLVED_INVOCATION, node);
                        } else if (callable) {
                            emit_resolved_alias_call(ctx, callable, name, node);
                        } else {
                            emit_unresolved_call(ctx, name, "lexical_value_not_exact_callable",
                                                 node);
                        }
                        goto recurse;
                    }
                    // Package-local function
                    const CBMRegisteredFunc *f =
                        go_lookup_callable(ctx->registry, ctx->package_qn, name);
                    if (f) {
                        emit_resolved_call(ctx, f->qualified_name, "lsp_direct", 0.95f, node);
                    } else if (resolve_builtin_type(ctx, name) ||
                               cbm_registry_lookup_type(
                                   ctx->registry,
                                   cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->package_qn, name))) {
                        go_emit_resolved_kind(ctx, name, "lsp_type_conversion", 0.0f, NULL,
                                              CBM_RESOLVED_INVOCATION, node);
                    } else if (!cbm_go_is_builtin_func(name)) {
                        emit_unresolved_call(ctx, name, "function_not_in_registry", node);
                    }
                }
            } else if (strcmp(fk, "selector_expression") != 0) {
                TSNode value = func_node;
                while (strcmp(ts_node_type(value), "parenthesized_expression") == 0 &&
                       ts_node_named_child_count(value) == 1)
                    value = ts_node_named_child(value, 0);
                const char *target = go_exact_callable_target(ctx, value);
                if (target) {
                    emit_resolved_alias_call(ctx, target, lsp_node_text(ctx, func_node), node);
                    goto recurse;
                }
                const char *vk = ts_node_type(value);
                bool callable_value = strcmp(vk, "func_literal") == 0 ||
                                      strcmp(vk, "call_expression") == 0 ||
                                      strcmp(vk, "type_conversion_expression") == 0 ||
                                      strcmp(vk, "type_assertion_expression") == 0;
                if (strcmp(vk, "identifier") == 0) {
                    const CBMVarBinding *binding =
                        cbm_scope_lookup_binding(ctx->current_scope, lsp_node_text(ctx, value));
                    callable_value = binding && !binding->is_type;
                }
                if (strcmp(vk, "unary_expression") == 0) {
                    const char *op = ts_node_type(ts_node_child(value, 0));
                    TSNode operand = ts_node_child_by_field_name(value, "operand", 7);
                    while (!ts_node_is_null(operand) &&
                           strcmp(ts_node_type(operand), "parenthesized_expression") == 0 &&
                           ts_node_named_child_count(operand) == 1)
                        operand = ts_node_named_child(operand, 0);
                    if (strcmp(op, "<-") == 0) {
                        callable_value = true;
                    } else if (strcmp(op, "*") == 0 && !ts_node_is_null(operand)) {
                        /* A local type name also has a scope entry; only values
                         * prove that (*name)(arg) is not a conversion. */
                        const CBMVarBinding *binding =
                            strcmp(ts_node_type(operand), "identifier") == 0
                                ? cbm_scope_lookup_binding(ctx->current_scope,
                                                           lsp_node_text(ctx, operand))
                                : NULL;
                        const char *operand_kind = ts_node_type(operand);
                        callable_value = (binding && !binding->is_type) ||
                                         strcmp(operand_kind, "call_expression") == 0 ||
                                         strcmp(operand_kind, "type_assertion_expression") == 0;
                        if (!callable_value && !binding) {
                            const CBMType *pointer = go_eval_expr_type(ctx, operand);
                            callable_value = pointer && pointer->kind == CBM_TYPE_POINTER;
                        }
                    }
                } else if (!callable_value && strcmp(vk, "identifier") != 0) {
                    const CBMType *type = go_underlying_type(ctx, go_eval_expr_type(ctx, value));
                    callable_value = type && type->kind == CBM_TYPE_FUNC;
                }
                if (callable_value)
                    emit_unresolved_call(ctx, lsp_node_text(ctx, func_node),
                                         "lexical_value_not_exact_callable", node);
            }
        }
    }

recurse:;
    if (strcmp(kind, "expression_case") == 0 || strcmp(kind, "default_case") == 0) {
        TSNode previous = ts_node_prev_named_sibling(node);
        while (!ts_node_is_null(previous) && strcmp(ts_node_type(previous), "comment") == 0)
            previous = ts_node_prev_named_sibling(previous);
        if (go_case_falls_through(previous)) {
            /* The case can be entered directly or after its predecessor's
             * writes. Invalidate the switch frame before isolating this case. */
            go_invalidate_control_flow_aliases(ctx, previous, 0);
        }
    }
    // Push scope for blocks and statements that introduce variables
    bool push_scope =
        (strcmp(kind, "block") == 0 || strcmp(kind, "if_statement") == 0 ||
         strcmp(kind, "for_statement") == 0 || strcmp(kind, "expression_switch_statement") == 0 ||
         strcmp(kind, "expression_case") == 0 || strcmp(kind, "default_case") == 0);
    if (push_scope) {
        ctx->current_scope = cbm_scope_push(ctx->arena, ctx->current_scope);
        const char *parent_kind = ts_node_type(ts_node_parent(node));
        if (strcmp(kind, "block") != 0 || strcmp(parent_kind, "if_statement") == 0 ||
            strcmp(parent_kind, "for_statement") == 0)
            ctx->assignment_floor = ctx->current_scope;
    }

    // Type switch: switch a := expr.(type) { case *T: a.Method() }
    // Go tree-sitter structure: type_switch_statement has flat children:
    //   expression_list (contains var name "a")
    //   identifier (operand "animal")
    //   type_case (case clause, may repeat)
    if (strcmp(kind, "type_switch_statement") == 0) {
        const char *switch_var = NULL;
        // Pass 1: find switch variable and operand type
        uint32_t nc2 = ts_node_child_count(node);
        bool found_assign = false;
        for (uint32_t i = 0; i < nc2; i++) {
            TSNode child = ts_node_child(node, i);
            if (ts_node_is_null(child))
                continue;
            const char *ck = ts_node_type(child);

            // expression_list before := is the LHS (variable name)
            if (!found_assign && strcmp(ck, "expression_list") == 0) {
                TSNode var_node = ts_node_named_child(child, 0);
                if (!ts_node_is_null(var_node) && strcmp(ts_node_type(var_node), "identifier") == 0)
                    switch_var = lsp_node_text(ctx, var_node);
            }
            // := operator marks the assignment
            if (!ts_node_is_named(child)) {
                char *tok = lsp_node_text(ctx, child);
                if (tok && strcmp(tok, ":=") == 0)
                    found_assign = true;
            }
            // identifier after := is the operand being type-switched
            if (found_assign && strcmp(ck, "identifier") == 0) {
                (void)go_eval_expr_type(ctx, child);
            }
        }

        // Pass 2: process each type_case with narrowed scope
        for (uint32_t i = 0; i < nc2; i++) {
            TSNode child = ts_node_child(node, i);
            if (ts_node_is_null(child) || !ts_node_is_named(child))
                continue;
            if (strcmp(ts_node_type(child), "type_case") != 0)
                continue;

            CBMScope *saved = ctx->current_scope;
            CBMScope *saved_floor = ctx->assignment_floor;
            ctx->current_scope = cbm_scope_push(ctx->arena, ctx->current_scope);
            ctx->assignment_floor = ctx->current_scope;

            // Find case type and bind switch variable
            uint32_t cc_count = ts_node_child_count(child);
            for (uint32_t j = 0; j < cc_count; j++) {
                TSNode cc_child = ts_node_child(child, j);
                if (ts_node_is_null(cc_child) || !ts_node_is_named(cc_child))
                    continue;
                const char *cc_kind = ts_node_type(cc_child);
                if (strcmp(cc_kind, "type_identifier") == 0 ||
                    strcmp(cc_kind, "qualified_type") == 0 ||
                    strcmp(cc_kind, "pointer_type") == 0 || strcmp(cc_kind, "slice_type") == 0) {
                    if (switch_var) {
                        cbm_scope_bind(ctx->current_scope, switch_var,
                                       go_parse_type_node(ctx, cc_child));
                    }
                    break;
                }
            }

            // Recurse into case body statements
            for (uint32_t j = 0; j < cc_count; j++) {
                TSNode cc_child = ts_node_child(child, j);
                if (ts_node_is_null(cc_child) || !ts_node_is_named(cc_child))
                    continue;
                const char *cc_kind = ts_node_type(cc_child);
                // Skip type nodes, process everything else (expression_statement, etc.)
                if (strcmp(cc_kind, "type_identifier") == 0 ||
                    strcmp(cc_kind, "qualified_type") == 0 ||
                    strcmp(cc_kind, "pointer_type") == 0 || strcmp(cc_kind, "slice_type") == 0)
                    continue;
                resolve_calls_in_node(ctx, cc_child);
            }

            ctx->current_scope = saved;
            ctx->assignment_floor = saved_floor;
        }

        if (push_scope)
            ctx->current_scope = cbm_scope_pop(ctx->current_scope);
        return;
    }

    // Select statement: each communication_case gets its own scope
    // case msg := <-ch:  →  receive_statement has left (vars) + unary_expression (<-ch)
    if (strcmp(kind, "select_statement") == 0) {
        uint32_t nc3 = ts_node_child_count(node);
        for (uint32_t i = 0; i < nc3; i++) {
            TSNode child = ts_node_child(node, i);
            if (ts_node_is_null(child) || !ts_node_is_named(child))
                continue;
            const char *ck3 = ts_node_type(child);

            if (strcmp(ck3, "communication_case") == 0 || strcmp(ck3, "default_case") == 0) {
                CBMScope *saved = ctx->current_scope;
                CBMScope *saved_floor = ctx->assignment_floor;
                ctx->current_scope = cbm_scope_push(ctx->arena, ctx->current_scope);
                ctx->assignment_floor = ctx->current_scope;

                // Process children: receive_statement binds vars, then recurse body
                uint32_t cc_count = ts_node_child_count(child);
                for (uint32_t j = 0; j < cc_count; j++) {
                    TSNode cc_child = ts_node_child(child, j);
                    if (ts_node_is_null(cc_child) || !ts_node_is_named(cc_child))
                        continue;
                    const char *cc_kind = ts_node_type(cc_child);

                    if (strcmp(cc_kind, "receive_statement") == 0) {
                        // receive_statement: left := <-right
                        // tree-sitter Go: right field is the channel expression (after <-)
                        // The receive value type is the channel's element type
                        TSNode left = ts_node_child_by_field_name(cc_child, "left", 4);
                        TSNode right = ts_node_child_by_field_name(cc_child, "right", 5);
                        if (!ts_node_is_null(right)) {
                            const CBMType *right_type = go_eval_expr_type(ctx, right);
                            // right_type might be a channel (if right is the channel)
                            // or already the elem type (if right is a <-ch unary expr)
                            const CBMType *recv_type = right_type;
                            if (right_type && right_type->kind == CBM_TYPE_CHANNEL) {
                                recv_type = right_type->data.channel.elem;
                            }
                            if (!ts_node_is_null(left)) {
                                bool list = strcmp(ts_node_type(left), "expression_list") == 0;
                                bool assignment = go_assigns_existing_value(cc_child);
                                uint32_t lhs_count = list ? ts_node_named_child_count(left) : 1;
                                for (uint32_t k = 0; k < lhs_count; k++) {
                                    TSNode var_node = list ? ts_node_named_child(left, k) : left;
                                    if (strcmp(ts_node_type(var_node), "identifier") != 0)
                                        continue;
                                    char *var_name = lsp_node_text(ctx, var_node);
                                    if (!var_name || strcmp(var_name, "_") == 0)
                                        continue;
                                    const CBMType *type = k == 0
                                        ? recv_type : cbm_type_builtin(ctx->arena, "bool");
                                    if (assignment)
                                        go_bind_assignment(ctx, var_name, type, NULL);
                                    else
                                        cbm_scope_bind(ctx->current_scope, var_name, type);
                                }
                            }
                        }
                    } else {
                        // Body statements
                        resolve_calls_in_node(ctx, cc_child);
                    }
                }

                ctx->current_scope = saved;
                ctx->assignment_floor = saved_floor;
            }
        }
        if (push_scope)
            ctx->current_scope = cbm_scope_pop(ctx->current_scope);
        return;
    }

    // Recurse into children via a cursor (O(n)); ts_node_child(node,i) is O(i)
    // → O(n²) on a wide node.
    // The cursor is this depth's pooled one (cbm_cursor_acquire): the recursion
    // below runs one level deeper and never touches it.
    {
        cbm_cursor_lease_t lease;
        TSTreeCursor *cursor = cbm_cursor_acquire(&lease, ctx->walk_depth, node);
        if (ts_tree_cursor_goto_first_child(cursor)) {
            do {
                resolve_calls_in_node(ctx, ts_tree_cursor_current_node(cursor));
            } while (ts_tree_cursor_goto_next_sibling(cursor));
        }
        cbm_cursor_release(&lease);
    }

    /* RHS calls use the old scope; source-order traversal binds initializers once. */
    if (bind_after_children)
        go_process_statement(ctx, node);

    if (push_scope) {
        ctx->current_scope = cbm_scope_pop(ctx->current_scope);
    }
}

// --- Process a single function body ---

static void process_function(GoLSPContext *ctx, TSNode func_node) {
    // Set enclosing function QN
    TSNode name_node = ts_node_child_by_field_name(func_node, "name", 4);
    if (ts_node_is_null(name_node))
        return;

    char *func_name = lsp_node_text(ctx, name_node);
    if (!func_name || !func_name[0])
        return;

    // Enclosing-function QN must be EXACTLY the QN the textual call events
    // (extract_unified.c compute_func_qn) and the defs pass produce, or the
    // caller-QN join in cbm_pipeline_find_lsp_resolution breaks and the
    // LSP-resolved call silently falls back to the registry short-name
    // resolver. Since #1909 receiver-qualified Go method QNs, that shared
    // form is package_qn.ReceiverType.method for methods (the ONE-formula
    // contract: cbm_go_receiver_type_name) and package_qn.func for functions.
    // A package may hold any number of init() functions, so each one is
    // package_qn.init#<file>:<N> (#1910, cbm_go_init_qn — the same formula).
    ctx->enclosing_func_qn = cbm_arena_sprintf(ctx->arena, "%s.%s", ctx->package_qn, func_name);
    if (strcmp(ts_node_type(func_node), "method_declaration") == 0) {
        TSNode recv = ts_node_child_by_field_name(func_node, "receiver", 8);
        if (!ts_node_is_null(recv)) {
            char *recv_type = cbm_go_receiver_type_name(ctx->arena, recv, ctx->source);
            if (recv_type && recv_type[0]) {
                ctx->enclosing_func_qn = cbm_arena_sprintf(ctx->arena, "%s.%s.%s", ctx->package_qn,
                                                           recv_type, func_name);
            }
        }
    } else if (strcmp(func_name, "init") == 0) {
        ctx->enclosing_func_qn = cbm_go_init_qn(ctx->arena, ctx->enclosing_func_qn, ctx->rel_path,
                                                func_node, ctx->source);
    }

    // Push function scope
    CBMScope *saved_scope = ctx->current_scope;
    CBMScope *saved_floor = ctx->assignment_floor;
    ctx->current_scope = cbm_scope_push(ctx->arena, ctx->current_scope);
    ctx->assignment_floor = ctx->current_scope;

    // The function's type parameters (and its receiver's) shadow the
    // package's types of those names, in its signature and its body (bound in
    // the function scope just pushed).
    bool saved_in_function = ctx->in_function;
    ctx->in_function = true;
    go_shadow_type_params(ctx, ts_node_child_by_field_name(func_node, "type_parameters", 15));
    if (strcmp(ts_node_type(func_node), "method_declaration") == 0) {
        go_shadow_receiver_params(ctx, ts_node_child_by_field_name(func_node, "receiver", 8), false,
                                  0);
    }

    // Parameters and named results share the function's local scope.
    go_bind_parameter_list(ctx, ts_node_child_by_field_name(func_node, "type_parameters", 15));
    go_bind_parameter_list(ctx, ts_node_child_by_field_name(func_node, "parameters", 10));
    go_bind_parameter_list(ctx, ts_node_child_by_field_name(func_node, "result", 6));

    // Bind receiver for methods
    TSNode recv = ts_node_child_by_field_name(func_node, "receiver", 8);
    if (!ts_node_is_null(recv)) {
        // receiver is a parameter_list with one parameter_declaration
        uint32_t rnc = ts_node_child_count(recv);
        for (uint32_t i = 0; i < rnc; i++) {
            TSNode rp = ts_node_child(recv, i);
            if (ts_node_is_null(rp) || !ts_node_is_named(rp))
                continue;
            if (strcmp(ts_node_type(rp), "parameter_declaration") != 0)
                continue;

            TSNode rtype = ts_node_child_by_field_name(rp, "type", 4);
            if (ts_node_is_null(rtype))
                continue;
            TSNode receiver_type = rtype;
            while (!ts_node_is_null(receiver_type) &&
                   (strcmp(ts_node_type(receiver_type), "pointer_type") == 0 ||
                    strcmp(ts_node_type(receiver_type), "parenthesized_type") == 0) &&
                   ts_node_named_child_count(receiver_type) == 1)
                receiver_type = ts_node_named_child(receiver_type, 0);
            TSNode type_args = ts_node_child_by_field_name(receiver_type, "type_arguments", 14);
            for (uint32_t j = 0; !ts_node_is_null(type_args) &&
                                 j < ts_node_named_child_count(type_args); j++) {
                TSNode arg = ts_node_named_child(type_args, j);
                if (strcmp(ts_node_type(arg), "type_elem") == 0 &&
                    ts_node_named_child_count(arg) == 1)
                    arg = ts_node_named_child(arg, 0);
                if (strcmp(ts_node_type(arg), "type_identifier") == 0) {
                    const char *name = lsp_node_text(ctx, arg);
                    if (name && strcmp(name, "_") != 0)
                        cbm_scope_bind_type(ctx->current_scope, name);
                }
            }
            const CBMType *recv_type = go_parse_type_node(ctx, rtype);
            const CBMType *recv_base = cbm_type_deref(recv_type);
            if (recv_base && recv_base->kind == CBM_TYPE_TEMPLATE) {
                /* Receiver parameters declare unknown types, not concrete use-site arguments. */
                const CBMType *nominal =
                    cbm_type_named(ctx->arena, recv_base->data.template_type.template_name);
                recv_type = recv_type->kind == CBM_TYPE_POINTER
                                ? cbm_type_pointer(ctx->arena, nominal) : nominal;
            }

            // Find receiver name
            uint32_t rpnc = ts_node_child_count(rp);
            for (uint32_t j = 0; j < rpnc; j++) {
                TSNode rc = ts_node_child(rp, j);
                if (!ts_node_is_null(rc) && ts_node_is_named(rc) &&
                    strcmp(ts_node_type(rc), "identifier") == 0) {
                    char *rname = lsp_node_text(ctx, rc);
                    if (rname && strcmp(rname, "_") != 0) {
                        cbm_scope_bind(ctx->current_scope, rname, recv_type);
                    }
                    break;
                }
            }
        }
    }

    // Walk function body
    TSNode body = ts_node_child_by_field_name(func_node, "body", 4);
    if (!ts_node_is_null(body)) {
        resolve_calls_in_node(ctx, body);
    }

    // Restore scope
    ctx->current_scope = saved_scope;
    ctx->in_function = saved_in_function;
    ctx->assignment_floor = saved_floor;
}

// --- Process entire file ---

void go_lsp_process_file(GoLSPContext *ctx, TSNode root) {
    if (ts_node_is_null(root))
        return;
    ctx->callable_bindings = cbm_ht_create(0);
    ctx->callable_tracking_failed = !ctx->callable_bindings;

    // Collect top-level children once (O(n)); ts_node_child(root,i) is O(i) → O(n²).
    uint32_t kn = 0;
    TSNode *kids = cbm_lsp_collect_children(ctx->arena, root, &kn);

    if (!ts_node_has_error(root) && ctx->rel_path) {
        for (uint32_t i = 0; i < kn; i++) {
            if (strcmp(ts_node_type(kids[i]), "package_clause") == 0) {
                TSNode name = ts_node_named_child(kids[i], 0);
                if (!ts_node_is_null(name))
                    ctx->source_package = lsp_node_text(ctx, name);
                break;
            }
        }
    }

    // Pass 1: Bind package-level var/const declarations into root scope.
    // Must happen before processing functions so all globals are visible.
    for (uint32_t i = 0; i < kn; i++) {
        TSNode child = kids[i];
        const char *kind = ts_node_type(child);

        if (strcmp(kind, "var_declaration") == 0 || strcmp(kind, "const_declaration") == 0) {
            uint32_t vnc = ts_node_child_count(child);
            for (uint32_t j = 0; j < vnc; j++) {
                TSNode spec = ts_node_child(child, j);
                if (ts_node_is_null(spec) || !ts_node_is_named(spec))
                    continue;
                if (strcmp(ts_node_type(spec), "var_spec_list") == 0) {
                    uint32_t count = ts_node_named_child_count(spec);
                    for (uint32_t k = 0; k < count; k++)
                        go_process_statement(ctx, ts_node_named_child(spec, k));
                } else {
                    go_process_statement(ctx, spec);
                }
            }
        }
    }

    // Pass 2: Resolve bodies and package initializers after all globals are bound.
    for (uint32_t i = 0; i < kn; i++) {
        TSNode child = kids[i];
        const char *kind = ts_node_type(child);

        if (strcmp(kind, "function_declaration") == 0 || strcmp(kind, "method_declaration") == 0) {
            process_function(ctx, child);
        } else if (strcmp(kind, "var_declaration") == 0 ||
                   strcmp(kind, "const_declaration") == 0) {
            ctx->enclosing_func_qn = ctx->package_qn;
            resolve_calls_in_node(ctx, child);
        }
    }
    cbm_ht_free(ctx->callable_bindings);
    ctx->callable_bindings = NULL;
}

// --- Helper: parse Go return type text into CBMType ---

/* scope_ix: the defining def's resolved type identities (CBMLSPDef.type_scope,
 * indexed), NULL when it has none. A named type the scope knows is that
 * identity; any other named type keeps the module qualification. */
static const CBMType *go_parse_type_text_scoped(CBMArena *a, const char *text,
                                                const char *module_qn,
                                                const cbm_type_scope_index_t *scope_ix) {
    if (!text || !text[0])
        return cbm_type_unknown();
    if (strcmp(text, "error") == 0)
        return cbm_type_named(a, "builtin.error");

    // Pointer: *Foo
    if (text[0] == '*') {
        return cbm_type_pointer(a, go_parse_type_text_scoped(a, text + 1, module_qn, scope_ix));
    }

    // Slice: []Foo
    if (text[0] == '[' && text[1] == ']') {
        return cbm_type_slice(a, go_parse_type_text_scoped(a, text + 2, module_qn, scope_ix));
    }

    // Builtin types
    static const char *builtins[] = {"int",     "int8",    "int16",  "int32",   "int64",
                                     "uint",    "uint8",   "uint16", "uint32",  "uint64",
                                     "float32", "float64", "string", "bool",    "byte",
                                     "rune",    "error",   "any",    "uintptr", NULL};
    for (const char **b = builtins; *b; b++) {
        if (strcmp(text, *b) == 0)
            return cbm_type_builtin(a, text);
    }

    // Named type the defining file's scope resolved (`pkg.T` through its import).
    const char *scoped = cbm_type_scope_find(scope_ix, text, strlen(text));
    if (scoped) {
        return cbm_type_named(a, scoped);
    }

    // Named type: assume local to module
    return cbm_type_named(a, cbm_arena_sprintf(a, "%s.%s", module_qn, text));
}

const CBMType *cbm_parse_return_type_text(CBMArena *a, const char *text, const char *module_qn) {
    return go_parse_type_text_scoped(a, text, module_qn, NULL);
}

typedef struct {
    const char *module_qn;
    const cbm_type_scope_index_t *scope_ix; /* the def's resolved type identities, or NULL */
} CBMGoLSPSignatureParserContext;

static const CBMType *cbm_go_lsp_parse_signature_param_text(CBMArena *arena, const char *text,
                                                            void *parser_ctx) {
    const CBMGoLSPSignatureParserContext *ctx = (const CBMGoLSPSignatureParserContext *)parser_ctx;
    const char *module_qn = ctx && ctx->module_qn ? ctx->module_qn : "";
    return go_parse_type_text_scoped(arena, text, module_qn, ctx ? ctx->scope_ix : NULL);
}

// --- Shared Go stdlib registry ---

/* The Go stdlib declarations are registered ONCE per process into
 * a finalized, sealed registry that every per-file registry chains to as its
 * fallback -- the overlay contract of type_registry.h: lookups and the chain
 * iterators reach it, refinements copy into the head, nothing writes it.
 * Registered into each file's registry instead, it was 13.4 k re-registrations
 * on the Go corpus, 2.5 GB of copies, and every lookup of the unfinalized
 * per-file registry scanned the stdlib linearly (waste sanitizer, 2026-09-17).
 * Threads racing the first build each build a copy and the first to publish
 * wins; the others free theirs -- no thread waits. NULL on allocation
 * failure: the caller registers the stdlib into its own registry as before. */
typedef struct {
    CBMArena arena;
    CBMTypeRegistry reg;
} go_stdlib_holder_t;

static _Atomic(go_stdlib_holder_t *) g_go_stdlib_shared;

static const CBMTypeRegistry *go_stdlib_shared(void) {
    go_stdlib_holder_t *ready = atomic_load_explicit(&g_go_stdlib_shared, memory_order_acquire);
    if (ready)
        return &ready->reg;
    go_stdlib_holder_t *built = cbm_calloc(CBM_MEM_CLASS_OTHER, sizeof(*built));
    if (!built)
        return NULL;
    cbm_arena_init(&built->arena);
    if (built->arena.nblocks == 0) {
        cbm_free(CBM_MEM_CLASS_OTHER, built);
        return NULL;
    }
    cbm_registry_init(&built->reg, &built->arena);
    cbm_go_stdlib_register(&built->reg, &built->arena);
    cbm_registry_finalize(&built->reg);
    built->reg.read_only = true;
    go_stdlib_holder_t *expected = NULL;
    if (atomic_compare_exchange_strong_explicit(&g_go_stdlib_shared, &expected, built,
                                                memory_order_acq_rel, memory_order_acquire)) {
        return &built->reg;
    }
    cbm_arena_destroy(&built->arena);
    cbm_free(CBM_MEM_CLASS_OTHER, built);
    return &expected->reg;
}

/* A per-file registry sees the stdlib: chained to the shared copy, or
 * registered into it when the shared copy cannot be built. */
static void go_registry_with_stdlib(CBMTypeRegistry *reg, CBMArena *arena) {
    const CBMTypeRegistry *shared = go_stdlib_shared();
    if (shared) {
        reg->fallback = shared;
    } else {
        cbm_go_stdlib_register(reg, arena);
    }
}

/* The first row of each type QN in a filling registry, as a scan from the top
 * finds it. Registering and refining a file's types asked a scan of every type
 * per definition, and a generated file holds thousands. A row the memo cannot
 * take (no memory) sends every later question back to the scan. */
enum { GO_MEMO_ARENA_BLOCK = 4096 };

typedef struct {
    CBMIdxMemo first;
    CBMArena *arena;
    bool failed;
} GoTypeRows;

static void go_type_rows_note(GoTypeRows *rows, const CBMTypeRegistry *reg, int row) {
    const char *qn = reg->types[row].qualified_name;
    if (rows->failed || !qn)
        return;
    CBM_LSP_WORK(1);
    cbm_idxmemo_put_if_absent(&rows->first, rows->arena, qn, row);
    if (cbm_idxmemo_get(&rows->first, qn) < 0)
        rows->failed = true;
}

static int go_type_rows_first(const GoTypeRows *rows, const CBMTypeRegistry *reg, const char *qn) {
    CBM_LSP_WORK(1);
    if (!rows->failed)
        return cbm_idxmemo_get(&rows->first, qn);
    for (int ti = 0; ti < reg->type_count; ti++) {
        CBM_LSP_WORK(1);
        if (reg->types[ti].qualified_name && strcmp(reg->types[ti].qualified_name, qn) == 0)
            return ti;
    }
    return -1;
}

static void go_type_rows_add(CBMTypeRegistry *reg, GoTypeRows *rows, CBMRegisteredType type) {
    int row = go_type_rows_first(rows, reg, type.qualified_name);
    if (row >= 0) {
        reg->types[row] = type;
        return;
    }
    int before = reg->type_count;
    cbm_registry_add_type(reg, type);
    if (reg->type_count > before)
        go_type_rows_note(rows, reg, reg->type_count - 1);
}

/* The first registration of each function QN, listed when the first function
 * asks: each one scanned every registered function for its own. The functions
 * do not change while they are patched. */
typedef struct {
    CBMIdxMemo first;
    CBMArena arena;
    bool listed;
    bool failed; /* a row could not be remembered: scan instead */
} GoFuncRows;

static int go_func_rows_first(GoFuncRows *rows, const CBMTypeRegistry *reg, const char *qn) {
    for (int fi = 0; !rows->listed && !rows->failed && fi < reg->func_count; fi++) {
        const char *name = reg->funcs[fi].qualified_name;
        if (!name)
            continue;
        CBM_LSP_WORK(1);
        cbm_idxmemo_put_if_absent(&rows->first, &rows->arena, name, fi);
        if (cbm_idxmemo_get(&rows->first, name) < 0)
            rows->failed = true;
    }
    rows->listed = true;
    CBM_LSP_WORK(1);
    if (!rows->failed)
        return cbm_idxmemo_get(&rows->first, qn);
    for (int fi = 0; fi < reg->func_count; fi++) {
        CBM_LSP_WORK(1);
        if (reg->funcs[fi].qualified_name && strcmp(reg->funcs[fi].qualified_name, qn) == 0)
            return fi;
    }
    return -1;
}

static const CBMType *go_parse_def_type_text(CBMArena *arena, TSParser **parser,
                                            const CBMLSPDef *def, const char *module_qn,
                                            const char *text) {
    if (!text || !text[0])
        return NULL;
    static const char prefix[] = "package p\ntype T ";
    size_t len = strlen(text);
    if (len > INT32_MAX - sizeof(prefix) - 1)
        return cbm_type_unknown();
    size_t source_len = sizeof(prefix) - 1 + len + 1;
    char *source = cbm_alloc(CBM_MEM_CLASS_OTHER, source_len + 1);
    if (!source)
        return cbm_type_unknown();
    memcpy(source, prefix, sizeof(prefix) - 1);
    memcpy(source + sizeof(prefix) - 1, text, len);
    source[source_len - 1] = '\n';
    source[source_len] = '\0';
    if (!*parser) {
        *parser = ts_parser_new();
        if (*parser && !ts_parser_set_language(*parser, tree_sitter_go())) {
            ts_parser_delete(*parser);
            *parser = NULL;
        }
    }
    TSTree *tree = *parser ? cbm_parse_source(*parser, source, (uint32_t)source_len,
                                             (TSParseOptions){0}) : NULL;
    const CBMType *parsed = cbm_type_unknown();
    if (tree) {
        TSNode root = ts_tree_root_node(tree);
        TSNode declaration = ts_node_named_child(root, 1);
        TSNode spec = ts_node_is_null(declaration) ? (TSNode){0}
                                                   : ts_node_named_child(declaration, 0);
        TSNode type = ts_node_is_null(spec) ? (TSNode){0}
                                           : ts_node_child_by_field_name(spec, "type", 4);
        if (!ts_node_has_error(root) && ts_node_named_child_count(root) == 2 &&
            !ts_node_is_null(declaration) &&
            strcmp(ts_node_type(declaration), "type_declaration") == 0 &&
            ts_node_named_child_count(declaration) == 1 && !ts_node_is_null(spec) &&
            strcmp(ts_node_type(spec), "type_spec") == 0 && !ts_node_is_null(type) &&
            ts_node_start_byte(type) == sizeof(prefix) - 1 &&
            ts_node_end_byte(type) == sizeof(prefix) - 1 + len) {
            GoLSPContext ctx = {
                .arena = arena, .source = source, .source_len = (int)source_len,
                .package_qn = module_qn,
            };
            for (int i = 0; def->go_type_import_names && def->go_type_import_qns &&
                            def->go_type_import_names[i] && def->go_type_import_qns[i]; i++)
                go_lsp_add_import(&ctx, def->go_type_import_names[i], def->go_type_import_qns[i]);
            parsed = go_parse_type_node(&ctx, type);
        }
        ts_tree_delete(tree);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, source);
    return parsed;
}

static const char *go_invalid_type_params[] = {NULL};

static TSNode go_receiver_parameter(TSNode declaration) {
    TSNode receiver = ts_node_child_by_field_name(declaration, "receiver", 8);
    if (ts_node_is_null(receiver))
        return (TSNode){0};
    TSNode parameter = {0};
    for (uint32_t i = 0; i < ts_node_named_child_count(receiver); i++) {
        TSNode child = ts_node_named_child(receiver, i);
        if (ts_node_is_extra(child))
            continue;
        if (strcmp(ts_node_type(child), "parameter_declaration") != 0 ||
            cbm_go_lsp_signature_param_multiplicity(child) != 1 ||
            !ts_node_is_null(parameter))
            return (TSNode){0};
        parameter = child;
    }
    return parameter;
}

static TSNode go_generic_parameters(TSNode declaration) {
    if (ts_node_is_null(declaration))
        return (TSNode){0};
    if (strcmp(ts_node_type(declaration), "method_declaration") != 0)
        return ts_node_child_by_field_name(declaration, "type_parameters", 15);
    TSNode parameter = go_receiver_parameter(declaration);
    if (ts_node_is_null(parameter))
        return (TSNode){0};
    TSNode type = ts_node_child_by_field_name(parameter, "type", 4);
    while (!ts_node_is_null(type) &&
           (strcmp(ts_node_type(type), "pointer_type") == 0 ||
            strcmp(ts_node_type(type), "parenthesized_type") == 0)) {
        TSNode inner = {0};
        for (uint32_t i = 0; i < ts_node_named_child_count(type); i++) {
            TSNode child = ts_node_named_child(type, i);
            if (!ts_node_is_extra(child))
                inner = child;
        }
        type = inner;
    }
    return !ts_node_is_null(type) && strcmp(ts_node_type(type), "generic_type") == 0
               ? ts_node_child_by_field_name(type, "type_arguments", 14) : (TSNode){0};
}

static const char **go_generic_parameter_names(GoLSPContext *ctx, TSNode list) {
    if (ts_node_is_null(list))
        return NULL;
    const char *names[17];
    int count = 0;
    bool receiver = strcmp(ts_node_type(list), "type_arguments") == 0;
    for (uint32_t i = 0; i < ts_node_named_child_count(list); i++) {
        TSNode param = ts_node_named_child(list, i);
        if (ts_node_is_extra(param))
            continue;
        if (receiver) {
            if (strcmp(ts_node_type(param), "type_elem") == 0)
                param = ts_node_named_child(param, 0);
            if (strcmp(ts_node_type(param), "type_identifier") != 0 || count == 16)
                return NULL;
            names[count++] = lsp_node_text(ctx, param);
        } else {
            if (strcmp(ts_node_type(param), "type_parameter_declaration") != 0)
                continue;
            for (uint32_t j = 0; j < ts_node_child_count(param); j++) {
                const char *field = ts_node_field_name_for_child(param, j);
                if (!field || strcmp(field, "name") != 0)
                    continue;
                if (count == 16)
                    return NULL;
                names[count++] = lsp_node_text(ctx, ts_node_child(param, j));
            }
        }
    }
    if (!count)
        return NULL;
    for (int i = 0; i < count; i++) {
        if (!names[i] || !names[i][0])
            return NULL;
        for (int j = 0; j < i; j++)
            if (strcmp(names[i], "_") != 0 && strcmp(names[i], names[j]) == 0)
                return NULL;
    }
    const char **out = cbm_arena_alloc(ctx->arena, (count + 1) * sizeof(*out));
    if (!out)
        return NULL;
    memcpy(out, names, count * sizeof(*out));
    out[count] = NULL;
    return out;
}

static const CBMType *go_declaration_signature(GoLSPContext *ctx, TSNode declaration) {
    const CBMType **params = go_parse_signature_types(
        ctx, ts_node_child_by_field_name(declaration, "parameters", 10), false);
    if (!params)
        return cbm_type_unknown();
    TSNode result = ts_node_child_by_field_name(declaration, "result", 6);
    const CBMType *ret = go_parse_type_node(ctx, result);
    const CBMType *returns[] = {ret, NULL};
    const CBMType *empty_returns[] = {NULL};
    return cbm_type_func(ctx->arena, NULL, params, ts_node_is_null(result) ? empty_returns
                         : ret->kind == CBM_TYPE_TUPLE ? ret->data.tuple.elems : returns);
}

static void go_refine_generic_node(GoLSPContext ctx, TSNode declaration, CBMTypeRegistry *reg,
                                   CBMRegisteredType *rt, CBMRegisteredFunc *rf) {
    const char **params = go_generic_parameter_names(&ctx, go_generic_parameters(declaration));
    if (rf) {
        rf->signature = cbm_type_unknown();
        rf->type_param_names = go_invalid_type_params;
    }
    if (rt) {
        rt->go_identity = strcmp(ts_node_type(declaration), "type_alias") == 0
                              ? CBM_GO_IDENTITY_ALIAS : CBM_GO_IDENTITY_UNKNOWN;
        rt->type_param_names = go_invalid_type_params;
        rt->underlying_type = cbm_type_unknown();
        rt->field_names = NULL;
        rt->field_types = NULL;
        rt->embedded_types = NULL;
        rt->alias_of = NULL;
    }
    if (!params)
        return;
    ctx.signature_type_params = params;
    if (rf) {
        rf->signature = go_declaration_signature(&ctx, declaration);
        if (rf->signature && rf->signature->kind == CBM_TYPE_FUNC)
            rf->type_param_names = params;
        return;
    }
    TSNode type = ts_node_child_by_field_name(declaration, "type", 4);
    const CBMType *shape = go_parse_type_node(&ctx, type);
    rt->type_param_names = params;
    rt->underlying_type = shape;
    if (strcmp(ts_node_type(declaration), "type_alias") == 0)
        rt->alias_of = go_member_type_qn(shape);
    if (shape->kind == CBM_TYPE_STRUCT) {
        if (rt->go_identity != CBM_GO_IDENTITY_ALIAS)
            rt->go_identity = CBM_GO_IDENTITY_CONCRETE;
        rt->field_names = shape->data.struct_type.field_names;
        rt->field_types = shape->data.struct_type.field_types;
        const CBMType **embeds = shape->data.struct_type.embedded_types;
        int count = 0;
        while (embeds && embeds[count])
            count++;
        const char **qns = cbm_arena_calloc(ctx.arena, (count + 1) * sizeof(*qns));
        if (qns) {
            for (int i = 0; i < count; i++)
                qns[i] = go_member_type_qn(cbm_type_deref(embeds[i]));
            rt->embedded_types = qns;
        }
    }
    if (strcmp(ts_node_type(type), "interface_type") == 0) {
        rt->is_interface = true;
        if (rt->go_identity != CBM_GO_IDENTITY_ALIAS)
            rt->go_identity = CBM_GO_IDENTITY_INTERFACE;
        uint32_t count = ts_node_named_child_count(type);
        const char **names = cbm_arena_calloc(ctx.arena, (count + 1) * sizeof(*names));
        if (!names)
            return;
        int methods = 0;
        for (uint32_t i = 0; i < count; i++) {
            TSNode method = ts_node_named_child(type, i);
            const char *kind = ts_node_type(method);
            if (strcmp(kind, "method_spec") != 0 && strcmp(kind, "method_elem") != 0)
                continue;
            TSNode name_node = ts_node_child_by_field_name(method, "name", 4);
            if (ts_node_is_null(name_node))
                continue;
            const char *name = lsp_node_text(&ctx, name_node);
            if (!name || !name[0])
                continue;
            names[methods++] = name;
            cbm_registry_add_func(reg, (CBMRegisteredFunc){
                .qualified_name = cbm_arena_sprintf(ctx.arena, "%s.%s", rt->qualified_name, name),
                .short_name = name, .receiver_type = rt->qualified_name,
                .signature = go_declaration_signature(&ctx, method), .type_param_names = params,
            });
        }
        rt->method_names = names;
    }
}

/* Parse one body-free declaration in its defining package, before registry seal. */
static void go_refine_generic_text(CBMArena *arena, TSParser **parser, const CBMLSPDef *def,
                                   CBMTypeRegistry *reg, CBMRegisteredType *rt,
                                   CBMRegisteredFunc *rf) {
    const char *text = def->go_generic_declaration;
    if (!text)
        return;
    if (rt) {
        rt->type_param_names = go_invalid_type_params;
        rt->underlying_type = cbm_type_unknown();
        rt->field_names = NULL;
        rt->field_types = NULL;
        rt->embedded_types = NULL;
        rt->alias_of = NULL;
    }
    if (rf) {
        rf->signature = cbm_type_unknown();
        rf->type_param_names = go_invalid_type_params;
    }
    static const char prefix[] = "package p\n";
    size_t len = strlen(text);
    while (len && (text[len - 1] == ' ' || text[len - 1] == '\t' ||
                   text[len - 1] == '\r' || text[len - 1] == '\n'))
        len--;
    if (!len || len > INT32_MAX - sizeof(prefix))
        return;
    size_t source_len = sizeof(prefix) - 1 + len + 1;
    char *source = cbm_alloc(CBM_MEM_CLASS_OTHER, source_len + 1);
    if (!source)
        return;
    memcpy(source, prefix, sizeof(prefix) - 1);
    memcpy(source + sizeof(prefix) - 1, text, len);
    source[source_len - 1] = '\n';
    source[source_len] = '\0';
    if (!*parser) {
        *parser = ts_parser_new();
        if (*parser && !ts_parser_set_language(*parser, tree_sitter_go())) {
            ts_parser_delete(*parser);
            *parser = NULL;
        }
    }
    TSTree *tree = *parser ? cbm_parse_source(*parser, source, (uint32_t)source_len,
                                             (TSParseOptions){0}) : NULL;
    if (tree) {
        TSNode root = ts_tree_root_node(tree);
        if (ts_node_has_error(root))
            goto parsed_done;
        TSNode top = {0};
        int declarations = 0;
        for (uint32_t i = 0; i < ts_node_named_child_count(root); i++) {
            TSNode child = ts_node_named_child(root, i);
            if (ts_node_is_extra(child))
                continue;
            if (declarations++ == 1)
                top = child;
        }
        if (declarations != 2 || ts_node_is_null(top) ||
            ts_node_start_byte(top) != sizeof(prefix) - 1)
            goto parsed_done;
        size_t covered = ts_node_end_byte(top);
        size_t declaration_end = sizeof(prefix) - 1 + len;
        for (uint32_t i = 0; i < ts_node_named_child_count(root); i++) {
            TSNode child = ts_node_named_child(root, i);
            if (!ts_node_is_extra(child))
                continue;
            size_t start = ts_node_start_byte(child), end = ts_node_end_byte(child);
            if (start < covered || end > declaration_end ||
                strspn(source + covered, " \t\r\n") < start - covered)
                goto parsed_done;
            covered = end;
        }
        if (covered > declaration_end ||
            strspn(source + covered, " \t\r\n") < declaration_end - covered)
            goto parsed_done;
        TSNode declaration = top;
        if (rt && strcmp(ts_node_type(top), "type_declaration") == 0 &&
            ts_node_named_child_count(top) == 1)
            declaration = ts_node_named_child(top, 0);
        const char *kind = ts_node_type(declaration);
        bool valid_kind = rt ? strcmp(kind, "type_spec") == 0 || strcmp(kind, "type_alias") == 0
                            : strcmp(kind, def->receiver_type ? "method_declaration"
                                                             : "function_declaration") == 0;
        TSNode name_node = ts_node_child_by_field_name(declaration, "name", 4);
        if (!valid_kind || ts_node_is_null(name_node) ||
            ts_node_is_null(go_generic_parameters(declaration)) ||
            (rf && !ts_node_is_null(ts_node_child_by_field_name(declaration, "body", 4))))
            goto parsed_done;
        GoLSPContext ctx = {
            .arena = arena, .source = source, .source_len = (int)source_len,
            .registry = reg, .package_qn = def->def_module_qn ? def->def_module_qn : "",
        };
        for (int i = 0; def->go_type_import_names && def->go_type_import_qns &&
                        def->go_type_import_names[i] && def->go_type_import_qns[i]; i++)
            go_lsp_add_import(&ctx, def->go_type_import_names[i], def->go_type_import_qns[i]);
        const char *name = lsp_node_text(&ctx, name_node);
        const char *owner = ctx.package_qn;
        if (rf && def->receiver_type) {
            TSNode param = go_receiver_parameter(declaration);
            owner = go_member_type_qn(cbm_type_deref(go_parse_type_node(
                &ctx, ts_node_child_by_field_name(param, "type", 4))));
            valid_kind = valid_kind && owner && strcmp(owner, def->receiver_type) == 0;
        }
        const char *qn = owner && name
                             ? cbm_arena_sprintf(arena, "%s.%s", owner, name) : NULL;
        if (valid_kind &&
            name && strcmp(name, def->short_name) == 0 && qn &&
            strcmp(qn, def->qualified_name) == 0)
            go_refine_generic_node(ctx, declaration, reg, rt, rf);
parsed_done:
        ts_tree_delete(tree);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, source);
}

static void go_mark_lexical_call(CBMCall *call, const CBMResolvedCall *blocked) {
    if (blocked && call->source_origin == blocked->source_origin && call->callee_name &&
        call->enclosing_func_qn && blocked->caller_qn && blocked->callee_qn &&
        call->site_start_byte == blocked->site_start_byte &&
        call->site_end_byte == blocked->site_end_byte &&
        strcmp(blocked->caller_qn, call->enclosing_func_qn) == 0) {
        const char *source_name = blocked->callee_qn;
        const char *call_name = call->callee_name;
        bool dynamic_target = blocked->reason &&
                              strcmp(blocked->reason, "dynamic_callable_target_unknown") == 0;
        bool unindexed_target =
            blocked->reason &&
            (strcmp(blocked->reason, "external_symbol_not_indexed") == 0 ||
             strcmp(blocked->reason, "symbol_not_in_registry") == 0 ||
             strcmp(blocked->reason, "imported_type_not_indexed") == 0 ||
             strcmp(blocked->reason, "method_not_found") == 0 ||
             strcmp(blocked->reason, "unknown_receiver_type") == 0);
        if (blocked->confidence > 0.0f || unindexed_target || dynamic_target) {
            if (blocked->confidence > 0.0f && blocked->reason) {
                source_name = blocked->reason;
            } else {
                const char *dot = strrchr(source_name, '.');
                if (dot)
                    source_name = dot + 1;
                dot = strrchr(call_name, '.');
                if (dot)
                    call_name = dot + 1;
            }
        }
        if (strcmp(source_name, call_name) == 0) {
            bool lexical_value = blocked->reason &&
                                 strcmp(blocked->reason, "lexical_value_not_exact_callable") == 0;
            bool type_conversion = blocked->strategy &&
                                   strcmp(blocked->strategy, "lsp_type_conversion") == 0;
            if (dynamic_target || lexical_value || type_conversion)
                call->requires_lsp_resolution = true;
            else
                call->suppress_name_fallback = true;
        }
    }
}

static void go_mark_lexical_calls(CBMArena *arena, CBMFileResult *result) {
    CBMHashTable *blocked_sites = NULL;
    const CBMTypeRegistry *stdlib = go_stdlib_shared();
    for (int i = 0; i < result->resolved_calls.count; i++) {
        CBMResolvedCall *resolved = &result->resolved_calls.items[i];
        bool lexical_value = resolved->reason &&
                             (strcmp(resolved->reason, "lexical_value_not_exact_callable") == 0 ||
                              strcmp(resolved->reason, "dynamic_callable_target_unknown") == 0);
        bool type_conversion = resolved->strategy &&
                               strcmp(resolved->strategy, "lsp_type_conversion") == 0;
        bool unindexed_target =
            resolved->reason &&
            (strcmp(resolved->reason, "external_symbol_not_indexed") == 0 ||
             strcmp(resolved->reason, "symbol_not_in_registry") == 0 ||
             strcmp(resolved->reason, "imported_type_not_indexed") == 0 ||
             strcmp(resolved->reason, "method_not_found") == 0 ||
             strcmp(resolved->reason, "unknown_receiver_type") == 0);
        bool stdlib_target = stdlib && resolved->confidence > 0.0f && resolved->callee_qn &&
                             cbm_registry_lookup_func(stdlib, resolved->callee_qn);
        if (resolved->kind != CBM_RESOLVED_INVOCATION ||
            resolved->source_origin != CBM_SOURCE_ORIGIN_RAW ||
            (!lexical_value && !type_conversion && !stdlib_target && !unindexed_target) ||
            resolved->site_end_byte <= resolved->site_start_byte) {
            continue;
        }
        if (!blocked_sites)
            blocked_sites = cbm_ht_create(0);
        const char *key = cbm_arena_sprintf(arena, "%u:%u", resolved->site_start_byte,
                                           resolved->site_end_byte);
        cbm_ht_set(blocked_sites, key, resolved);
        if (!key || cbm_ht_get(blocked_sites, key) != resolved) {
            for (int c = 0; c < result->calls.count; c++)
                go_mark_lexical_call(&result->calls.items[c], resolved);
        }
    }
    if (!blocked_sites)
        return;

    for (int i = 0; i < result->calls.count; i++) {
        CBMCall *call = &result->calls.items[i];
        if (call->source_origin != CBM_SOURCE_ORIGIN_RAW || !call->callee_name ||
            !call->enclosing_func_qn)
            continue;
        char key[32];
        snprintf(key, sizeof(key), "%u:%u", call->site_start_byte, call->site_end_byte);
        go_mark_lexical_call(call, cbm_ht_get(blocked_sites, key));
    }
    cbm_ht_free(blocked_sites);
}

// --- Entry point: build registry from file defs + run LSP ---

void cbm_run_go_lsp(CBMArena *arena, CBMFileResult *result, const char *source, int source_len,
                    TSNode root, const char *rel_path) {

    CBMTypeRegistry reg;
    cbm_registry_init(&reg, arena);

    // Go stdlib types/functions: the shared sealed registry, chained
    go_registry_with_stdlib(&reg, arena);

    /* Rows of the file's own registry by QN, from whatever it holds already (the
     * stdlib, when it could not be shared) to the types registered below. */
    GoFuncRows own_funcs = {0};
    cbm_arena_init_lazy(&own_funcs.arena, GO_MEMO_ARENA_BLOCK);
    GoTypeRows own_types = {.arena = &own_funcs.arena};
    for (int ti = 0; ti < reg.type_count; ti++)
        go_type_rows_note(&own_types, &reg, ti);

    const char *module_qn = result->module_qn;

    // Phase 1: Register all types and functions from the file's own definitions
    for (int i = 0; i < result->defs.count; i++) {
        CBMDefinition *d = &result->defs.items[i];
        if (!d->qualified_name || !d->name)
            continue;

        // Register every type-like container (Class/Struct/Type/Interface/Enum/
        // Trait). Struct included so a Go `type T struct {...}` (now labelled
        // "Struct") is registered as a type and its methods/embedding resolve.
        if (cbm_label_is_type_like(d->label)) {
            CBMRegisteredType rt;
            memset(&rt, 0, sizeof(rt));
            rt.qualified_name = d->qualified_name;
            rt.short_name = d->name;
            rt.is_interface = d->label && strcmp(d->label, "Interface") == 0;
            rt.go_identity = d->alias_target ? CBM_GO_IDENTITY_ALIAS
                             : rt.is_interface ? CBM_GO_IDENTITY_INTERFACE
                             : strcmp(d->label, "Struct") == 0 ? CBM_GO_IDENTITY_CONCRETE
                                                               : CBM_GO_IDENTITY_UNKNOWN;

            // Populate embedded_types from base_classes (Go struct embedding)
            if (d->base_classes) {
                int bc_count = 0;
                while (d->base_classes[bc_count])
                    bc_count++;
                if (bc_count > 0) {
                    const char **embedded = (const char **)cbm_arena_alloc(
                        arena, (bc_count + 1) * sizeof(const char *));
                    for (int j = 0; j < bc_count; j++) {
                        const char *bc = d->base_classes[j];
                        // Strip pointer prefix for embedded *Type
                        while (bc[0] == '*')
                            bc++;
                        // Qualify the embedded type name
                        embedded[j] = cbm_arena_sprintf(arena, "%s.%s", module_qn, bc);
                    }
                    embedded[bc_count] = NULL;
                    rt.embedded_types = embedded;
                }
            }

            go_type_rows_add(&reg, &own_types, rt);
        }

        // Register Function/Method nodes
        if (d->label && (strcmp(d->label, "Function") == 0 || strcmp(d->label, "Method") == 0)) {
            CBMRegisteredFunc rf;
            memset(&rf, 0, sizeof(rf));
            rf.qualified_name = d->qualified_name;
            rf.short_name = d->name;

            // Build FUNC type from return_types
            const CBMType **ret_types = NULL;
            if (d->return_types) {
                int count = 0;
                while (d->return_types[count])
                    count++;
                if (count > 0) {
                    ret_types = (const CBMType **)cbm_arena_alloc(
                        arena, (count + 1) * sizeof(const CBMType *));
                    for (int j = 0; j < count; j++) {
                        ret_types[j] =
                            cbm_parse_return_type_text(arena, d->return_types[j], module_qn);
                    }
                    ret_types[count] = NULL;
                }
            } else if (d->return_type && d->return_type[0]) {
                // Fallback: single return_type string
                ret_types = (const CBMType **)cbm_arena_alloc(arena, 2 * sizeof(const CBMType *));
                ret_types[0] = cbm_parse_return_type_text(arena, d->return_type, module_qn);
                ret_types[1] = NULL;
            }

            /* The occurrence-preserving carrier is authoritative whenever it
             * is present, including a non-NULL carrier with an explicit zero
             * count. Its slots deliberately have no names because legacy name
             * extraction is not guaranteed to have the same multiplicity. */
            const CBMType **param_types_arr = NULL;
            const char **param_names_arr = NULL;
            bool has_ordered_params =
                d->signature_param_types != NULL || d->signature_param_count > 0;
            CBMGoLSPSignatureParserContext param_parser_ctx = {.module_qn = module_qn};
            if (has_ordered_params) {
                param_types_arr = cbm_type_materialize_signature_params(
                    arena, d->signature_param_types, d->signature_param_count,
                    cbm_go_lsp_parse_signature_param_text, &param_parser_ctx);
            } else if (d->param_types) {
                param_names_arr = d->param_names;
                int count = 0;
                while (d->param_types[count])
                    count++;
                if (count > 0) {
                    param_types_arr = (const CBMType **)cbm_arena_alloc(
                        arena, (count + 1) * sizeof(const CBMType *));
                    for (int j = 0; j < count; j++) {
                        param_types_arr[j] =
                            cbm_parse_return_type_text(arena, d->param_types[j], module_qn);
                    }
                    param_types_arr[count] = NULL;
                }
            } else {
                param_names_arr = d->param_names;
            }

            rf.signature = cbm_type_func(arena, param_names_arr, param_types_arr, ret_types);

            // Prefer the extractor's semantic receiver QN. Raw receiver text is
            // retained only as a compatibility fallback for hand-built defs;
            // reparsing it alone loses valid unnamed receivers such as `(Right)`.
            if (strcmp(d->label, "Method") == 0) {
                if (d->parent_class && d->parent_class[0]) {
                    rf.receiver_type = d->parent_class;
                } else if (d->receiver && d->receiver[0]) {
                    // Legacy named receiver formats: "(name *Type)" / "(name Type)".
                    const char *r = d->receiver;
                    while (*r == '(' || *r == ' ')
                        r++;
                    while (*r && *r != ' ' && *r != '*')
                        r++;
                    while (*r == ' ' || *r == '*')
                        r++;
                    const char *end = r;
                    while (*end && *end != ')' && *end != ' ')
                        end++;
                    if (end > r) {
                        char *type_name = cbm_arena_strndup(arena, r, (size_t)(end - r));
                        rf.receiver_type = cbm_arena_sprintf(arena, "%s.%s", module_qn, type_name);
                    }
                }

                /* reg's own types are all in own_types; the stdlib is behind. */
                if (rf.receiver_type &&
                    go_type_rows_first(&own_types, &reg, rf.receiver_type) < 0 &&
                    !cbm_registry_lookup_type(reg.fallback, rf.receiver_type)) {
                    const char *dot = strrchr(rf.receiver_type, '.');
                    CBMRegisteredType auto_type;
                    memset(&auto_type, 0, sizeof(auto_type));
                    auto_type.qualified_name = rf.receiver_type;
                    auto_type.short_name = dot ? dot + 1 : rf.receiver_type;
                    go_type_rows_add(&reg, &own_types, auto_type);
                }
            }

            cbm_registry_add_func(&reg, rf);
        }
    }

    // Phase 1b: Refine source return types and struct fields from the AST.
    {
        GoLSPContext field_ctx = {
            .arena = arena, .source = source, .source_len = (int)strlen(source),
            .registry = &reg, .package_qn = module_qn,
        };
        go_lsp_add_source_imports(&field_ctx, root);
        // Collect top-level children once (O(n)); ts_node_child(root,i) is O(i) → O(n²).
        uint32_t rkn = 0;
        TSNode *rkids = cbm_lsp_collect_children(arena, root, &rkn);
        for (uint32_t i = 0; i < rkn; i++) {
            TSNode top = rkids[i];
            const char *tk = ts_node_type(top);
            if (strcmp(tk, "function_declaration") == 0 ||
                strcmp(tk, "method_declaration") == 0) {
                TSNode result_node = ts_node_child_by_field_name(top, "result", 6);
                TSNode type_params = ts_node_child_by_field_name(top, "type_parameters", 15);
                if (ts_node_is_null(result_node) || !ts_node_is_null(type_params))
                    continue;
                char *name = cbm_node_text(
                    arena, ts_node_child_by_field_name(top, "name", 4), source);
                const char *owner = module_qn;
                if (strcmp(tk, "method_declaration") == 0) {
                    TSNode param = go_receiver_parameter(top);
                    if (ts_node_is_null(param))
                        continue;
                    const CBMType *recv = cbm_type_deref(go_parse_type_node(
                        &field_ctx, ts_node_child_by_field_name(param, "type", 4)));
                    if (!go_member_type_qn(recv))
                        continue;
                    owner = go_member_type_qn(recv);
                }
                if (!name)
                    continue;
                const char *qn = cbm_arena_sprintf(arena, "%s.%s", owner, name);
                int fi = go_func_rows_first(&own_funcs, &reg, qn);
                if (fi >= 0) {
                    /* Cleaned extractor names lose containers such as []T. */
                    const CBMType *ret = go_parse_type_node(&field_ctx, result_node);
                    if (!cbm_type_is_unknown(ret)) {
                        const CBMType *returns[] = {ret, NULL};
                        reg.funcs[fi].signature = cbm_type_func_replace_returns(
                            arena, reg.funcs[fi].signature,
                            ret->kind == CBM_TYPE_TUPLE ? ret->data.tuple.elems : returns);
                    }
                }
                continue;
            }
            // type_declaration contains type_spec children
            if (strcmp(tk, "type_declaration") != 0)
                continue;
            uint32_t td_nc = ts_node_child_count(top);
            for (uint32_t j = 0; j < td_nc; j++) {
                TSNode spec = ts_node_child(top, j);
                if (ts_node_is_null(spec) || !ts_node_is_named(spec))
                    continue;
                const char *spec_kind = ts_node_type(spec);

                // type_alias: type Foo = Bar
                if (strcmp(spec_kind, "type_alias") == 0) {
                    TSNode alias_name = ts_node_child_by_field_name(spec, "name", 4);
                    TSNode alias_type = ts_node_child_by_field_name(spec, "type", 4);
                    if (!ts_node_is_null(alias_name) && !ts_node_is_null(alias_type)) {
                        char *aname = cbm_node_text(arena, alias_name, source);
                        if (aname && aname[0]) {
                            const char *alias_type_qn =
                                cbm_arena_sprintf(arena, "%s.%s", module_qn, aname);
                            const CBMType *underlying =
                                ts_node_is_null(ts_node_child_by_field_name(
                                    spec, "type_parameters", 15))
                                    ? go_parse_type_node(&field_ctx, alias_type)
                                    : cbm_type_unknown();
                            const char *alias_target_qn = go_member_type_qn(underlying);
                            int alias_at = go_type_rows_first(&own_types, &reg, alias_type_qn);
                            if (alias_at >= 0) {
                                reg.types[alias_at].go_identity = CBM_GO_IDENTITY_ALIAS;
                                reg.types[alias_at].alias_of = alias_target_qn;
                                reg.types[alias_at].underlying_type = underlying;
                            } else {
                                CBMRegisteredType alias_rt;
                                memset(&alias_rt, 0, sizeof(alias_rt));
                                alias_rt.qualified_name = alias_type_qn;
                                alias_rt.short_name = aname;
                                alias_rt.go_identity = CBM_GO_IDENTITY_ALIAS;
                                alias_rt.alias_of = alias_target_qn;
                                alias_rt.underlying_type = underlying;
                                go_type_rows_add(&reg, &own_types, alias_rt);
                            }
                        }
                    }
                    continue;
                }

                if (strcmp(spec_kind, "type_spec") != 0)
                    continue;

                TSNode name_node = ts_node_child_by_field_name(spec, "name", 4);
                TSNode type_node = ts_node_child_by_field_name(spec, "type", 4);
                if (ts_node_is_null(name_node) || ts_node_is_null(type_node))
                    continue;

                char *type_name = cbm_node_text(arena, name_node, source);
                if (!type_name || !type_name[0])
                    continue;
                const char *type_qn = cbm_arena_sprintf(arena, "%s.%s", module_qn, type_name);
                int shape_at = go_type_rows_first(&own_types, &reg, type_qn);
                if (shape_at >= 0 &&
                    ts_node_is_null(ts_node_child_by_field_name(spec, "type_parameters", 15)) &&
                    strcmp(ts_node_type(type_node), "struct_type") != 0 &&
                    strcmp(ts_node_type(type_node), "interface_type") != 0)
                    reg.types[shape_at].underlying_type = go_parse_type_node(&field_ctx, type_node);

                // Interface type: extract method names for satisfaction checking
                if (strcmp(ts_node_type(type_node), "interface_type") == 0) {
                    const char *iface_methods[64];
                    int iface_method_count = 0;
                    uint32_t inl_nc = ts_node_named_child_count(type_node);
                    for (uint32_t k = 0; k < inl_nc && iface_method_count < 63; k++) {
                        TSNode child = ts_node_named_child(type_node, k);
                        if (ts_node_is_null(child))
                            continue;
                        const char *ck = ts_node_type(child);
                        // method_spec: MethodName(params) returns
                        if (strcmp(ck, "method_spec") == 0 || strcmp(ck, "method_elem") == 0) {
                            TSNode mname = ts_node_child_by_field_name(child, "name", 4);
                            if (!ts_node_is_null(mname)) {
                                char *mn = cbm_node_text(arena, mname, source);
                                if (mn && mn[0]) {
                                    iface_methods[iface_method_count++] = mn;
                                }
                            }
                        }
                    }
                    int iface_at =
                        iface_method_count > 0 ? go_type_rows_first(&own_types, &reg, type_qn) : -1;
                    if (iface_at >= 0) {
                        const char **names = (const char **)cbm_arena_alloc(
                            arena, (iface_method_count + 1) * sizeof(const char *));
                        for (int mi = 0; mi < iface_method_count; mi++) {
                            names[mi] = iface_methods[mi];
                        }
                        names[iface_method_count] = NULL;
                        reg.types[iface_at].method_names = names;
                    }
                    continue;
                }

                if (strcmp(ts_node_type(type_node), "struct_type") != 0)
                    continue;

                // Find field_declaration_list inside struct_type
                TSNode field_list = ts_node_child_by_field_name(type_node, "body", 4);
                if (ts_node_is_null(field_list)) {
                    // Some grammars use first named child
                    if (ts_node_named_child_count(type_node) > 0)
                        field_list = ts_node_named_child(type_node, 0);
                }
                if (ts_node_is_null(field_list))
                    continue;

                // Scan field_declarations for embeds and named fields: all of
                // them (no count decides what the registry holds). An embedded
                // type is also a field named by its unqualified type name.
                uint32_t fl_cap = ts_node_child_count(field_list) * 2 + 1;
                const char **embeds =
                    (const char **)cbm_arena_alloc(arena, fl_cap * sizeof(const char *));
                int embed_count = 0;
                const char **fld_names =
                    (const char **)cbm_arena_alloc(arena, fl_cap * sizeof(const char *));
                const CBMType **fld_types =
                    (const CBMType **)cbm_arena_alloc(arena, fl_cap * sizeof(const CBMType *));
                int fld_count = 0;
                if (!embeds || !fld_names || !fld_types)
                    continue;

                uint32_t fl_nc = ts_node_child_count(field_list);
                for (uint32_t k = 0; k < fl_nc; k++) {
                    TSNode field = ts_node_child(field_list, k);
                    if (ts_node_is_null(field) || !ts_node_is_named(field))
                        continue;
                    if (strcmp(ts_node_type(field), "field_declaration") != 0)
                        continue;

                    TSNode fname = ts_node_child_by_field_name(field, "name", 4);
                    TSNode ftype = ts_node_child_by_field_name(field, "type", 4);

                    if (ts_node_is_null(fname) && !ts_node_is_null(ftype)) {
                        // Embedded field: has type but no name
                        const CBMType *field_type = go_parse_type_node(&field_ctx, ftype);
                        const char *qn = go_member_type_qn(cbm_type_deref(field_type));
                        if (qn) {
                            embeds[embed_count++] = qn;
                            size_t length = 0;
                            const char *next = cbm_node_text(arena, ftype, source);
                            const char *spelling = next ? go_embedded_spelling(&next, &length) : NULL;
                            const char *name =
                                spelling ? go_embedded_field_name(arena, spelling, length) : NULL;
                            if (name) {
                                fld_names[fld_count] = name;
                                fld_types[fld_count++] = field_type;
                            }
                        }
                    } else if (!ts_node_is_null(fname) && !ts_node_is_null(ftype)) {
                        // Named field: name + type
                        char *fn = cbm_node_text(arena, fname, source);
                        if (fn && fn[0]) {
                            fld_names[fld_count] = fn;
                            fld_types[fld_count] = go_parse_type_node(&field_ctx, ftype);
                            fld_count++;
                        }
                    }
                }

                // Find the registered type and update it
                int ti = go_type_rows_first(&own_types, &reg, type_qn);
                if (ti >= 0) {
                    if (embed_count > 0) {
                        const char **arr = (const char **)cbm_arena_alloc(
                            arena, (embed_count + 1) * sizeof(const char *));
                        for (int ei = 0; ei < embed_count; ei++)
                            arr[ei] = embeds[ei];
                        arr[embed_count] = NULL;
                        reg.types[ti].embedded_types = arr;
                    }
                    if (fld_count > 0) {
                        const char **names = (const char **)cbm_arena_alloc(
                            arena, (fld_count + 1) * sizeof(const char *));
                        const CBMType **types = (const CBMType **)cbm_arena_alloc(
                            arena, (fld_count + 1) * sizeof(const CBMType *));
                        for (int fi = 0; fi < fld_count; fi++) {
                            names[fi] = fld_names[fi];
                            types[fi] = fld_types[fi];
                        }
                        names[fld_count] = NULL;
                        types[fld_count] = NULL;
                        reg.types[ti].field_names = names;
                        reg.types[ti].field_types = types;
                    }
                }
            }
        }
    }
    cbm_arena_destroy(&own_funcs.arena);

    // Phase 2: Build LSP context and run
    GoLSPContext lsp_ctx;
    go_lsp_init(&lsp_ctx, arena, source, source_len, &reg, module_qn, &result->resolved_calls);
    lsp_ctx.rel_path = rel_path;

    // Add imports
    for (int i = 0; i < result->imports.count; i++) {
        CBMImport *imp = &result->imports.items[i];
        if (imp->local_name && imp->module_path) {
            go_lsp_add_import(&lsp_ctx, imp->local_name, imp->module_path);
        }
    }
    go_lsp_add_source_imports(&lsp_ctx, root);
    extract_type_params_from_ast(&lsp_ctx, &reg, root);

    // Process the file
    go_lsp_process_file(&lsp_ctx, root);
    go_mark_lexical_calls(arena, result);
}

// --- Cross-file LSP: parse source, build registry from defs, run LSP ---

// Helper: split "|"-separated string into array of CBMType*.
static const CBMType **split_pipe_types(CBMArena *a, TSParser **parser, const CBMLSPDef *def,
                                       const char *module_qn,
                                       const cbm_type_scope_index_t *scope_ix) {
    const char *text = def->return_types;
    if (!text || !text[0])
        return NULL;

    // Count separators
    int count = 1;
    for (const char *p = text; *p; p++) {
        if (*p == '|')
            count++;
    }

    const CBMType **arr =
        (const CBMType **)cbm_arena_alloc(a, (count + 1) * sizeof(const CBMType *));
    if (!arr)
        return NULL;

    // Split and parse each type
    char *buf = cbm_arena_strdup(a, text);
    int idx = 0;
    char *start = buf;
    for (char *p = buf;; p++) {
        if (*p == '|' || *p == '\0') {
            char save = *p;
            *p = '\0';
            if (start[0]) {
                /* Older and direct definitions may carry just the declaring imports. */
                arr[idx++] = !scope_ix && def->go_type_import_names && strchr(start, '.')
                                 ? go_parse_def_type_text(a, parser, def, module_qn, start)
                                 : go_parse_type_text_scoped(a, start, module_qn, scope_ix);
            }
            if (save == '\0')
                break;
            start = p + 1;
        }
    }
    arr[idx] = NULL;
    return idx > 0 ? arr : NULL;
}

/* The mark of a QN in the value table below (go_value_qn_counts) whose
 * definitions give different answers; any other value is the QN's first
 * definition. */
static char g_go_qn_shared_mark;

static bool go_type_qn_shared(const CBMHashTable *shared, const char *qn) {
    return shared && qn && cbm_ht_get(shared, qn) == &g_go_qn_shared_mark;
}

static bool go_same_text(const char *a, const char *b) {
    return (!a || !a[0]) ? (!b || !b[0]) : (b && strcmp(a, b) == 0);
}

/* The QN a package-level value registers under: <package>.<name>, or NULL
 * for a def that is no typed value. */
static const char *go_value_qn(CBMArena *a, const CBMLSPDef *d, const char *def_mod) {
    if (!d->label || strcmp(d->label, "Variable") != 0 || !d->short_name || !d->return_types ||
        !d->return_types[0] || strchr(d->return_types, '|') || !def_mod || !def_mod[0]) {
        return NULL;
    }
    return cbm_arena_sprintf(a, "%s.%s", def_mod, d->short_name);
}

/* Every Go def QN and every value QN, marked shared when two defs that give
 * different answers have it. A directory holds both `package foo` and
 * `package foo_test`, and their package-level names live under one directory
 * QN: a value whose QN another definition also has (a value of another type
 * or identity, a function, a type of the other package) is registered for
 * neither, so no answer depends on file order. Two values of one QN that
 * spell the same type with the same identities (build variants of one
 * declaration) give one answer and stay. NULL on allocation failure (then no
 * value is registered). */
static CBMHashTable *go_value_qn_counts(CBMArena *a, const CBMLSPDef *defs, int def_count,
                                        const char *fallback_mod) {
    CBMHashTable *seen = cbm_ht_create((uint32_t)(def_count / 4 + 64));
    for (int i = 0; seen && i < def_count; i++) {
        const CBMLSPDef *d = &defs[i];
        if (!d->qualified_name || d->lang != CBM_LANG_GO) {
            continue;
        }
        const char *def_mod = d->def_module_qn ? d->def_module_qn : fallback_mod;
        const char *value_qn = go_value_qn(a, d, def_mod);
        const char *keys[2] = {d->qualified_name,
                               value_qn && strcmp(value_qn, d->qualified_name) != 0 ? value_qn
                                                                                    : NULL};
        for (int k = 0; k < 2; k++) {
            if (!keys[k]) {
                continue;
            }
            void *prev = cbm_ht_get(seen, keys[k]);
            if (!prev) {
                cbm_ht_set(seen, keys[k], (void *)d); /* the first definition */
                continue;
            }
            const CBMLSPDef *first = (const CBMLSPDef *)prev;
            bool same_value =
                prev != &g_go_qn_shared_mark && value_qn &&
                go_value_qn(a, first, first->def_module_qn ? first->def_module_qn : fallback_mod) &&
                go_same_text(first->return_types, d->return_types) &&
                go_same_text(first->type_scope, d->type_scope) &&
                go_same_text(first->go_source_package, d->go_source_package) &&
                go_same_text(first->go_source_path, d->go_source_path);
            if (!same_value) {
                cbm_ht_set(seen, keys[k], &g_go_qn_shared_mark);
            }
        }
    }
    return seen;
}

/* ── Language hook: promotion of embedded-struct members ─────────────
 *
 * Go promotes the methods and fields of an embedded type to the struct that
 * embeds it. A member lookup on the struct falls through to its embedded
 * types (go_lookup_promoted), which needs their QNs; a struct from another
 * file brings them as their source spelling ("logging.LogHolder", "*Base").
 * Resolve the identity using the declaring file's scope and imports.
 * A bare name belongs to the declaring package. */
/* One embedded spelling of a '|'-joined list, without its `*` and its type
 * arguments (a generic instance names its type): sets *len, returns its
 * start, or NULL at the end of the list. *next moves past it. */
static const char *go_embedded_spelling(const char **next, size_t *len) {
    const char *p = *next;
    if (!p || !*p) {
        return NULL;
    }
    const char *bar = strchr(p, '|');
    size_t n = bar ? (size_t)(bar - p) : strlen(p);
    *next = bar ? bar + 1 : p + n;
    while (n > 0 && *p == '*') {
        p++;
        n--;
    }
    const char *bracket = memchr(p, '[', n);
    *len = bracket ? (size_t)(bracket - p) : n;
    return p;
}

static const char *go_embedded_qn(CBMArena *a, const char *s, size_t len, const char *def_mod,
                                  const CBMLSPDef *def,
                                  const cbm_type_scope_index_t *scope_ix) {
    const char *qn = len ? cbm_type_scope_find(scope_ix, s, len) : NULL;
    if (qn || !len)
        return qn;
    const char *dot = memchr(s, '.', len);
    if (!dot)
        return def_mod && def_mod[0]
                   ? cbm_arena_sprintf(a, "%s.%.*s", def_mod, (int)len, s)
                   : NULL;
    size_t alias_len = (size_t)(dot - s);
    size_t type_len = len - alias_len - 1;
    if (alias_len && type_len && !memchr(dot + 1, '.', type_len)) {
        for (int i = 0; def->go_type_import_names && def->go_type_import_qns &&
                        def->go_type_import_names[i] && def->go_type_import_qns[i]; i++) {
            const char *alias = def->go_type_import_names[i];
            const char *pkg = def->go_type_import_qns[i];
            if (strlen(alias) == alias_len && memcmp(alias, s, alias_len) == 0)
                return pkg[0] ? cbm_arena_sprintf(a, "%s.%.*s", pkg, (int)type_len, dot + 1)
                              : NULL;
        }
    }
    /* A dotted module prefix distinguishes a legacy QN from Go's pkg.Type syntax. */
    size_t mod_len = def_mod ? strlen(def_mod) : 0;
    if (mod_len && len > mod_len + 1 && s[mod_len] == '.' &&
        memcmp(s, def_mod, mod_len) == 0 && memchr(def_mod, '.', mod_len))
        return cbm_arena_strndup(a, s, len);
    return NULL;
}

/* The field name an embedded spelling declares: Go's unqualified type name
 * (`pkg.T` -> `T`). NULL when it has none. */
static const char *go_embedded_field_name(CBMArena *a, const char *s, size_t len) {
    const char *name = s;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '.') {
            name = s + i + 1;
        }
    }
    size_t n = len - (size_t)(name - s);
    return n ? cbm_arena_strndup(a, name, n) : NULL;
}

static const char **go_embedded_qns(CBMArena *a, const CBMLSPDef *def, const char *def_mod,
                                    const cbm_type_scope_index_t *scope_ix) {
    const char *embedded = def->embedded_types;
    if (!embedded || !embedded[0]) {
        return NULL;
    }
    int count = 1;
    for (const char *p = embedded; *p; p++) {
        count += *p == '|';
    }
    const char **out = (const char **)cbm_arena_alloc(a, (size_t)(count + 1) * sizeof(*out));
    if (!out) {
        return NULL;
    }
    int n = 0;
    size_t len = 0;
    for (const char *next = embedded, *s; (s = go_embedded_spelling(&next, &len)) != NULL;) {
        const char *qn = go_embedded_qn(a, s, len, def_mod, def, scope_ix);
        if (qn) {
            out[n++] = qn;
        }
    }
    out[n] = NULL;
    return n > 0 ? out : NULL;
}

/* Append fields to rt (a name rt already declares keeps its entry). One hash
 * set of the names, so the cost is linear in the fields. */
static void go_append_fields(CBMArena *a, CBMRegisteredType *rt, const char *const *names,
                             const CBMType *const *types, int n) {
    if (n <= 0) {
        return;
    }
    int had = 0;
    while (rt->field_names && rt->field_names[had]) {
        had++;
    }
    const char **out_names =
        (const char **)cbm_arena_alloc(a, (size_t)(had + n + 1) * sizeof(char *));
    const CBMType **out_types =
        (const CBMType **)cbm_arena_alloc(a, (size_t)(had + n + 1) * sizeof(CBMType *));
    CBMHashTable *present = cbm_ht_create((uint32_t)(had + n + 8));
    if (!out_names || !out_types || !present) {
        cbm_ht_free(present);
        return;
    }
    int count = 0;
    for (int i = 0; i < had; i++) {
        out_names[count] = rt->field_names[i];
        out_types[count++] = rt->field_types ? rt->field_types[i] : NULL;
        cbm_ht_set(present, rt->field_names[i], (void *)1);
    }
    for (int i = 0; i < n; i++) {
        if (!names[i] || cbm_ht_get(present, names[i])) {
            continue;
        }
        cbm_ht_set(present, names[i], (void *)1);
        out_names[count] = names[i];
        out_types[count++] = types[i] ? types[i] : cbm_type_unknown();
    }
    cbm_ht_free(present);
    out_names[count] = NULL;
    out_types[count] = NULL;
    rt->field_names = out_names;
    rt->field_types = out_types;
}

/* Go's selector rule names an embedded field by its unqualified type name, at
 * the embedding type's depth: `s.Config` is the embedded Config even where an
 * embedded type has a field Config one level down, and a method of that name
 * one level down is shadowed by it. Each embedded spelling of `embedded`
 * becomes a field of rt: typed as the embedded type when `typed` and its QN is
 * known, else of unknown type (it shadows, and answers nothing). */
static void go_add_embedded_fields(CBMArena *a, CBMRegisteredType *rt, const CBMLSPDef *def,
                                   const char *def_mod, const cbm_type_scope_index_t *scope_ix,
                                   bool typed) {
    const char *embedded = def->embedded_types;
    if (!embedded || !embedded[0] || rt->is_interface) {
        return;
    }
    int count = 1;
    for (const char *p = embedded; *p; p++) {
        count += *p == '|';
    }
    const char **names = (const char **)cbm_arena_alloc(a, (size_t)count * sizeof(char *));
    const CBMType **types = (const CBMType **)cbm_arena_alloc(a, (size_t)count * sizeof(CBMType *));
    if (!names || !types) {
        return;
    }
    int n = 0;
    size_t len = 0;
    for (const char *next = embedded, *s; (s = go_embedded_spelling(&next, &len)) != NULL;) {
        const char *name = go_embedded_field_name(a, s, len);
        if (!name) {
            continue;
        }
        const char *qn = typed ? go_embedded_qn(a, s, len, def_mod, def, scope_ix) : NULL;
        names[n] = name;
        types[n++] = qn ? cbm_type_named(a, qn) : cbm_type_unknown();
    }
    go_append_fields(a, rt, names, types, n);
}

/* A package-level value (a Go `var`/`const` Variable def whose declaration or
 * initializer spells its type): registered under <package>.<name> with
 * CBM_FUNC_FLAG_VALUE and that type as the signature's single result, so
 * `pkg.V.Method()` and a bare `V.Method()` of another file are typed. A
 * value is never a call target (go_lookup_callable, go_lookup_func_callable),
 * and a QN another definition shares registers no value (go_value_qn_counts). */
static void go_register_value(CBMTypeRegistry *reg, CBMArena *a, TSParser **parser, const CBMLSPDef *d,
                              const char *def_mod, const cbm_type_scope_index_t *scope_ix,
                              const CBMHashTable *value_qns) {
    const char *qn = go_value_qn(a, d, def_mod);
    if (!qn || !value_qns || go_type_qn_shared(value_qns, qn)) {
        return;
    }
    const CBMType **ret = split_pipe_types(a, parser, d, def_mod, scope_ix);
    if (!ret || !ret[0] || cbm_type_is_unknown(ret[0])) {
        return;
    }
    CBMRegisteredFunc rf;
    memset(&rf, 0, sizeof(rf));
    rf.qualified_name = qn;
    rf.short_name = d->short_name;
    rf.signature = cbm_type_func(a, NULL, NULL, ret);
    rf.flags = CBM_FUNC_FLAG_VALUE;
    cbm_registry_add_func(reg, rf);
}

// Helper: split "|"-separated string into array of const char*.
static const char **split_pipe_strings(CBMArena *a, const char *text) {
    if (!text || !text[0])
        return NULL;

    int count = 1;
    for (const char *p = text; *p; p++) {
        if (*p == '|')
            count++;
    }

    const char **arr = (const char **)cbm_arena_alloc(a, (count + 1) * sizeof(const char *));
    if (!arr)
        return NULL;

    char *buf = cbm_arena_strdup(a, text);
    int idx = 0;
    char *start = buf;
    for (char *p = buf;; p++) {
        if (*p == '|' || *p == '\0') {
            char save = *p;
            *p = '\0';
            if (start[0]) {
                arr[idx++] = cbm_arena_strdup(a, start);
            }
            if (save == '\0')
                break;
            start = p + 1;
        }
    }
    arr[idx] = NULL;
    return idx > 0 ? arr : NULL;
}

/* QN of the type an identity alias `type A = B` names, for the def-driven
 * cross-file registries (#2033). The per-file AST scan sets alias_of only for
 * the file it walks, so an alias declared in another file of the package
 * reaches a call only through here. Only a bare identifier is qualified (B
 * declared in A's package); a qualified, pointer, composite or generic target
 * stays NULL rather than guessed. */
static const char *go_alias_target_qn(CBMArena *arena, const char *target,
                                      const char *def_module_qn) {
    if (!target || !target[0] || !def_module_qn || !def_module_qn[0]) {
        return NULL;
    }
    for (const unsigned char *p = (const unsigned char *)target; *p; p++) {
        bool ident = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                     (*p >= '0' && *p <= '9') || *p == '_' || *p >= 0x80;
        if (!ident) {
            return NULL;
        }
    }
    return cbm_arena_sprintf(arena, "%s.%s", def_module_qn, target);
}

// Helper: parse "|"-separated "name:type" field definitions and populate a registered type.
// Format: "Binder:Binder|Name:string|Count:int"
// type_text is resolved relative to def_module_qn.
/* Parse "name:type|name:type" into NULL-terminated name/type arrays. False when
 * nothing parsed (or on allocation failure): the type keeps no field info. */
static const char *go_field_type_identity(const cbm_type_scope_index_t *ix, const char *text);

static bool parse_field_defs(CBMArena *arena, TSParser **parser, const CBMLSPDef *def,
                             const char *field_defs, const char *module_qn,
                             const cbm_type_scope_index_t *scope_ix, const char ***names_out,
                             const CBMType ***types_out) {

    // Count fields: all of them (no count decides which fields a struct has)
    int count = 1;
    for (const char *p = field_defs; *p; p++) {
        if (*p == '|')
            count++;
    }

    const char **names = (const char **)cbm_arena_alloc(arena, (count + 1) * sizeof(const char *));
    const CBMType **types =
        (const CBMType **)cbm_arena_alloc(arena, (count + 1) * sizeof(const CBMType *));
    if (!names || !types)
        return false;

    char *buf = cbm_arena_strdup(arena, field_defs);
    int idx = 0;
    char *start = buf;
    for (char *p = buf;; p++) {
        if (*p == '|' || *p == '\0') {
            char save = *p;
            *p = '\0';
            // Parse "name:type"
            char *colon = NULL;
            for (char *q = start; *q; q++) {
                if (*q == ':') {
                    colon = q;
                    break;
                }
            }
            if (colon && idx < count) {
                *colon = '\0';
                names[idx] = cbm_arena_strdup(arena, start);
                const char *type = colon + 1;
                types[idx] = def && def->go_type_import_names && strchr(type, '.') &&
                             !go_field_type_identity(scope_ix, type)
                                 ? go_parse_def_type_text(arena, parser, def, module_qn, type)
                                 : go_parse_type_text_scoped(arena, type, module_qn, scope_ix);
                idx++;
            }
            if (save == '\0')
                break;
            start = p + 1;
        }
    }
    names[idx] = NULL;
    types[idx] = NULL;
    *names_out = names;
    *types_out = types;
    return idx > 0;
}

/* Go module QNs are directories, so a package and its external test package
 * (`foo` and `foo_test`), or build-tagged variants, can declare two types of
 * one QN. A type lookup answers with one entry of a name, which one depends on
 * file order, so what is keyed by such a QN is registered only where every
 * definition of the QN gives the same answer:
 *   - a field when every definition declares it with the same type text whose
 *     name means the same type (its identity, or the package's own type);
 *   - the embedded types when every definition embeds the same types.
 * Build variants of one struct keep what they share; `foo` and `foo_test`
 * declaring different structs of one name keep only what agrees. A name any
 * definition declares as a field (named or embedded) is still a field of the
 * QN at its depth, of unknown type where they do not agree, so no deeper
 * member of that name is selected (go_type_qn_shadow). */
typedef struct {
    const CBMLSPDef *first;
    int count;                /* definitions of the QN */
    const char *first_embeds; /* the first definition's embedded QNs, '|'-joined */
    bool embeds_differ;
    bool fields_done;
    const char *fields;    /* count > 1: the fields every definition agrees on, or NULL */
    const CBMLSPDef **all; /* count > 1: every definition of the QN */
    int all_cap;
    bool shadow_done;
    const char **shadow_names; /* every field name some definition declares */
    int shadow_count;
} go_type_qn_t;

/* What a field type text means in one definition: the part the parser looks
 * up after `*` and `[]`, resolved through the def's identities, or NULL for
 * the package's own name (the same in every definition of one directory). */
static const char *go_field_type_identity(const cbm_type_scope_index_t *ix, const char *text) {
    while (text && (*text == '*' || (text[0] == '[' && text[1] == ']'))) {
        text += *text == '*' ? 1 : 2;
    }
    return text ? cbm_type_scope_find(ix, text, strlen(text)) : NULL;
}

static const char *go_join_embeds(CBMArena *a, const CBMLSPDef *d) {
    const char *mod = d->def_module_qn ? d->def_module_qn : "";
    const char **qns =
        go_embedded_qns(a, d, mod, cbm_type_scope_index(a, d->type_scope));
    size_t total = 1;
    for (int i = 0; qns && qns[i]; i++) {
        total += strlen(qns[i]) + 1;
    }
    char *out = (char *)cbm_arena_alloc(a, total);
    if (!out) {
        return "";
    }
    size_t at = 0;
    for (int i = 0; qns && qns[i]; i++) {
        if (i) {
            out[at++] = '|';
        }
        size_t n = strlen(qns[i]);
        memcpy(out + at, qns[i], n);
        at += n;
    }
    out[at] = '\0';
    return out;
}

/* Keep the fields of `agreed` ("name:type|...") that `d` declares alike. */
static const char *go_agreed_fields(CBMArena *a, const char *agreed, const CBMLSPDef *agreed_def,
                                    const CBMLSPDef *d) {
    if (!agreed || !agreed[0] || !d->field_defs || !d->field_defs[0]) {
        return NULL;
    }
    const cbm_type_scope_index_t *agreed_ix = cbm_type_scope_index(a, agreed_def->type_scope);
    const cbm_type_scope_index_t *d_ix = cbm_type_scope_index(a, d->type_scope);
    CBMHashTable *mine = cbm_ht_create(16);
    char *copy = cbm_arena_strdup(a, d->field_defs);
    for (char *p = copy; mine && p && *p;) {
        char *bar = strchr(p, '|');
        if (bar) {
            *bar = '\0';
        }
        char *colon = strchr(p, ':');
        if (colon) {
            *colon = '\0';
            cbm_ht_set(mine, p, colon + 1); /* name -> type text */
        }
        p = bar ? bar + 1 : NULL;
    }
    /* The kept fields are a subset of `agreed`: one buffer of its size. */
    char *out = (char *)cbm_arena_alloc(a, strlen(agreed) + 1);
    size_t at = 0;
    char *keep = cbm_arena_strdup(a, agreed);
    for (char *p = keep; mine && out && p && *p;) {
        char *bar = strchr(p, '|');
        if (bar) {
            *bar = '\0';
        }
        char *colon = strchr(p, ':');
        const char *theirs =
            colon ? (const char *)cbm_ht_get(mine, cbm_arena_strndup(a, p, (size_t)(colon - p)))
                  : NULL;
        if (theirs && strcmp(theirs, colon + 1) == 0 &&
            go_same_text(go_field_type_identity(agreed_ix, colon + 1),
                         go_field_type_identity(d_ix, theirs))) {
            size_t n = strlen(p);
            if (at) {
                out[at++] = '|';
            }
            memcpy(out + at, p, n);
            at += n;
        }
        p = bar ? bar + 1 : NULL;
    }
    cbm_ht_free(mine);
    if (!out || at == 0) {
        return NULL;
    }
    out[at] = '\0';
    return out;
}

/* QN -> go_type_qn_t for every Go type definition (keys borrowed from defs;
 * free with cbm_ht_free, entries live in `a`), or NULL on allocation failure
 * (then a QN of two definitions keeps nothing). */
static CBMHashTable *go_type_qn_table(CBMArena *a, const CBMLSPDef *defs, int def_count) {
    CBMHashTable *table = cbm_ht_create((uint32_t)(def_count / 4 + 64));
    for (int i = 0; table && i < def_count; i++) {
        const CBMLSPDef *d = &defs[i];
        if (!d->qualified_name || !d->label || d->lang != CBM_LANG_GO ||
            !cbm_label_is_type_like(d->label)) {
            continue;
        }
        go_type_qn_t *e = (go_type_qn_t *)cbm_ht_get(table, d->qualified_name);
        if (!e) {
            e = (go_type_qn_t *)cbm_arena_alloc(a, sizeof(*e));
            if (!e) {
                cbm_ht_free(table);
                return NULL;
            }
            memset(e, 0, sizeof(*e));
            e->first = d;
            cbm_ht_set(table, d->qualified_name, e);
        }
        e->count++;
        if (e->count == 2) {
            e->first_embeds = go_join_embeds(a, e->first);
            e->fields = e->first->field_defs;
        }
        if (e->count >= 2) {
            e->embeds_differ =
                e->embeds_differ || !go_same_text(e->first_embeds, go_join_embeds(a, d));
            e->fields = go_agreed_fields(a, e->fields, e->first, d);
            if (e->count > e->all_cap) {
                int cap = e->all_cap ? e->all_cap * 2 : 4;
                const CBMLSPDef **grown =
                    (const CBMLSPDef **)cbm_arena_alloc(a, (size_t)cap * sizeof(*grown));
                if (!grown) {
                    cbm_ht_free(table);
                    return NULL;
                }
                if (e->all_cap) {
                    memcpy(grown, e->all, (size_t)(e->count - 1) * sizeof(*grown));
                } else {
                    grown[0] = e->first;
                }
                e->all = grown;
                e->all_cap = cap;
            }
            e->all[e->count - 1] = d;
        }
    }
    return table;
}

/* The field names some definition of a QN of several declares (named fields
 * and embedded types), each once; computed on the first call. */
static int go_pipe_pieces(const char *s) {
    int n = s && *s ? 1 : 0;
    for (; s && *s; s++) {
        n += *s == '|';
    }
    return n;
}

static void go_shadow_note(go_type_qn_t *e, CBMHashTable *seen, const char *name) {
    if (name && !cbm_ht_get(seen, name)) {
        cbm_ht_set(seen, name, (void *)name);
        e->shadow_names[e->shadow_count++] = name;
    }
}

static void go_type_qn_shadow(CBMArena *a, go_type_qn_t *e) {
    if (e->shadow_done) {
        return;
    }
    e->shadow_done = true;
    int bound = 0;
    for (int i = 0; i < e->count; i++) {
        bound += go_pipe_pieces(e->all[i]->field_defs) + go_pipe_pieces(e->all[i]->embedded_types);
    }
    CBMHashTable *seen = bound ? cbm_ht_create((uint32_t)(bound + 8)) : NULL;
    e->shadow_names =
        seen ? (const char **)cbm_arena_alloc(a, (size_t)(bound + 1) * sizeof(char *)) : NULL;
    if (!e->shadow_names) {
        cbm_ht_free(seen);
        return;
    }
    /* In definition order, then declaration order: a fixed order. */
    for (int i = 0; i < e->count; i++) {
        const CBMLSPDef *d = e->all[i];
        for (const char *p = d->field_defs; p && *p;) {
            const char *colon = strchr(p, ':');
            const char *bar = strchr(p, '|');
            if (colon && (!bar || colon < bar) && colon > p) {
                go_shadow_note(e, seen, cbm_arena_strndup(a, p, (size_t)(colon - p)));
            }
            p = bar ? bar + 1 : NULL;
        }
        size_t len = 0;
        for (const char *next = d->embedded_types, *s;
             (s = go_embedded_spelling(&next, &len)) != NULL;) {
            go_shadow_note(e, seen, go_embedded_field_name(a, s, len));
        }
    }
    e->shadow_names[e->shadow_count] = NULL;
    cbm_ht_free(seen);
}

/* A type QN of several definitions: every field name some definition
 * declares that rt does not register with a type becomes a field of unknown
 * type (it shadows deeper members and answers nothing). */
static void go_add_shadow_fields(CBMArena *a, CBMRegisteredType *rt, const CBMHashTable *table,
                                 const CBMLSPDef *d) {
    go_type_qn_t *e = table ? (go_type_qn_t *)cbm_ht_get(table, d->qualified_name) : NULL;
    if (!e || e->count < 2 || rt->is_interface) {
        return;
    }
    go_type_qn_shadow(a, e);
    if (e->shadow_count == 0) {
        return;
    }
    const CBMType **types =
        (const CBMType **)cbm_arena_alloc(a, (size_t)e->shadow_count * sizeof(CBMType *));
    if (!types) {
        return;
    }
    for (int i = 0; i < e->shadow_count; i++) {
        types[i] = cbm_type_unknown();
    }
    go_append_fields(a, rt, e->shadow_names, types, e->shadow_count);
}

/* The fields to register for `d`: its own when it is its QN's only definition,
 * else those every definition of the QN agrees on (NULL: none). Without a
 * table (allocation failure) every def keeps its own, as before the table. */
static const char *go_type_qn_fields(const CBMHashTable *table, const CBMLSPDef *d) {
    const go_type_qn_t *e =
        table ? (const go_type_qn_t *)cbm_ht_get(table, d->qualified_name) : NULL;
    return !e || e->count < 2 ? d->field_defs : e->fields;
}

static const CBMLSPDef *go_unique_type_def(const CBMHashTable *table, const CBMLSPDef *d) {
    const go_type_qn_t *group = table ? cbm_ht_get(table, d->qualified_name) : NULL;
    return !table || (group && group->count > 1) ? NULL : d;
}

/* Whether `d`'s embedded types are the same in every definition of its QN. */
static bool go_type_qn_embeds(const CBMHashTable *table, const CBMLSPDef *d) {
    const go_type_qn_t *e =
        table ? (const go_type_qn_t *)cbm_ht_get(table, d->qualified_name) : NULL;
    return !e || e->count < 2 || !e->embeds_differ;
}

// --- Phase 1c: Refine generic declarations ---

/* Go permits one AST parameter declaration to introduce several call
 * positions: `first, second T`. Count direct names without exposing or
 * rewriting the legacy public param_names projection. */
static int cbm_go_lsp_signature_param_multiplicity(TSNode param) {
    const char *kind = ts_node_type(param);
    if (strcmp(kind, "parameter_declaration") != 0 &&
        strcmp(kind, "variadic_parameter_declaration") != 0) {
        return 0;
    }

    int field_names = 0;
    int identifier_names = 0;
    uint32_t child_count = ts_node_child_count(param);
    for (uint32_t i = 0; i < child_count; i++) {
        TSNode child = ts_node_child(param, i);
        if (ts_node_is_null(child) || !ts_node_is_named(child))
            continue;
        const char *field = ts_node_field_name_for_child(param, i);
        if (field && strcmp(field, "name") == 0)
            field_names++;
        if (strcmp(ts_node_type(child), "identifier") == 0)
            identifier_names++;
    }

    int names = field_names > 0 ? field_names : identifier_names;
    return names > 0 ? names : 1;
}

/* Declaration signatures must follow the extractor's ordinary interface-method rows. */
static void go_refine_generic_defs(CBMTypeRegistry *reg, TSParser **parser,
                                   CBMLSPDef *defs, int count, const char *module_qn,
                                   const CBMHashTable *type_qns) {
    GoFuncRows funcs = {0};
    cbm_arena_init_lazy(&funcs.arena, GO_MEMO_ARENA_BLOCK);
    GoTypeRows types = {.arena = &funcs.arena};
    bool listed_types = false;
    for (int i = 0; i < count; i++) {
        CBMLSPDef def = defs[i];
        if (def.lang != CBM_LANG_GO || !def.go_generic_declaration || !def.qualified_name ||
            !def.short_name || !def.label)
            continue;
        if (!def.def_module_qn)
            def.def_module_qn = module_qn;
        if (cbm_label_is_type_like(def.label)) {
            const go_type_qn_t *group = type_qns ? cbm_ht_get(type_qns, def.qualified_name) : NULL;
            if (!type_qns || (group && group->count > 1))
                continue;
            if (!listed_types) {
                /* The finalized registry uses the last row, after any receiver placeholder. */
                for (int ti = reg->type_count - 1; ti >= 0; ti--)
                    go_type_rows_note(&types, reg, ti);
                listed_types = true;
            }
            int ti = types.failed ? -1 : go_type_rows_first(&types, reg, def.qualified_name);
            if (ti >= 0)
                go_refine_generic_text(reg->arena, parser, &def, reg, &reg->types[ti], NULL);
        } else if (strcmp(def.label, "Function") == 0 || strcmp(def.label, "Method") == 0) {
            int fi = go_func_rows_first(&funcs, reg, def.qualified_name);
            if (fi >= 0)
                go_refine_generic_text(reg->arena, parser, &def, reg, NULL, &reg->funcs[fi]);
        }
    }
    cbm_arena_destroy(&funcs.arena);
}

// Refine generic signatures with the same imports and type parser as their uses.
static void extract_type_params_from_ast(GoLSPContext *ctx, CBMTypeRegistry *reg, TSNode root) {
    CBMArena *arena = ctx->arena;
    GoFuncRows func_rows;
    memset(&func_rows, 0, sizeof(func_rows));
    cbm_arena_init_lazy(&func_rows.arena, GO_MEMO_ARENA_BLOCK);
    GoTypeRows type_rows = {.arena = &func_rows.arena};
    for (int ti = 0; ti < reg->type_count; ti++)
        go_type_rows_note(&type_rows, reg, ti);

    uint32_t rkn = 0;
    TSNode *rkids = cbm_lsp_collect_children(arena, root, &rkn);
    for (uint32_t i = 0; i < rkn; i++) {
        TSNode top = rkids[i];
        const char *kind = ts_node_type(top);
        if (strcmp(kind, "type_declaration") == 0) {
            for (uint32_t j = 0; j < ts_node_named_child_count(top); j++) {
                TSNode spec = ts_node_named_child(top, j);
                if (ts_node_is_null(go_generic_parameters(spec)))
                    continue;
                const char *name = lsp_node_text(
                    ctx, ts_node_child_by_field_name(spec, "name", 4));
                const char *qn = name
                    ? cbm_arena_sprintf(arena, "%s.%s", ctx->package_qn, name) : NULL;
                int ti = qn ? go_type_rows_first(&type_rows, reg, qn) : -1;
                if (ti >= 0)
                    go_refine_generic_node(*ctx, spec, reg, &reg->types[ti], NULL);
            }
            continue;
        }
        if ((strcmp(kind, "function_declaration") != 0 &&
             strcmp(kind, "method_declaration") != 0) ||
            ts_node_is_null(go_generic_parameters(top)))
            continue;
        const char *name = lsp_node_text(ctx, ts_node_child_by_field_name(top, "name", 4));
        const char *owner = ctx->package_qn;
        if (strcmp(kind, "method_declaration") == 0) {
            TSNode param = go_receiver_parameter(top);
            owner = go_member_type_qn(cbm_type_deref(go_parse_type_node(
                ctx, ts_node_child_by_field_name(param, "type", 4))));
        }
        const char *qn = name && owner
            ? cbm_arena_sprintf(arena, "%s.%s", owner, name) : NULL;
        int fi = qn ? go_func_rows_first(&func_rows, reg, qn) : -1;
        if (fi >= 0)
            go_refine_generic_node(*ctx, top, reg, NULL, &reg->funcs[fi]);
    }
    cbm_arena_destroy(&func_rows.arena);
}

// Forward: tree-sitter Go language (from lang_specs.c)
void cbm_run_go_lsp_cross(CBMArena *arena, const char *source, int source_len,
                          const char *module_qn, const char *rel_path, CBMLSPDef *defs,
                          int def_count, const char **import_names, const char **import_qns,
                          int import_count, TSTree *cached_tree, CBMResolvedCallArray *out) {
    if (!source || source_len <= 0)
        return;

    // 1. Use cached tree if available, otherwise parse fresh
    TSParser *parser = NULL;
    TSTree *tree = cached_tree;
    bool owns_tree = false;
    if (!tree) {
        parser = ts_parser_new();
        if (!parser)
            return;
        ts_parser_set_language(parser, tree_sitter_go());
        tree = cbm_parse_source(parser, source, (uint32_t)source_len, (TSParseOptions){0});
        owns_tree = true;
        if (!tree) {
            ts_parser_delete(parser);
            return;
        }
    }
    TSNode root = ts_tree_root_node(tree);

    // 2. Build registry (the stdlib is the shared sealed registry, chained)
    CBMTypeRegistry reg;
    cbm_registry_init(&reg, arena);
    go_registry_with_stdlib(&reg, arena);
    TSParser *type_parser = NULL;

    // Register all defs (file-local + cross-file).
    // Perf: borrow strings from defs[] directly — they live in the
    // caller's arena which outlives this call, so cbm_arena_strdup is
    // wasted work. On kubernetes (~110k defs × 11k files × 5 strdups
    // ~= 6B mallocs) this alone saves ~90s of resolve wall time.
    CBMHashTable *type_qns = go_type_qn_table(arena, defs, def_count);
    CBMHashTable *value_qns = go_value_qn_counts(arena, defs, def_count, module_qn);
    for (int i = 0; i < def_count; i++) {
        CBMLSPDef *d = &defs[i];
        if (!d->qualified_name || !d->short_name || !d->label)
            continue;

        const char *def_mod = d->def_module_qn ? d->def_module_qn : module_qn;
        /* The def's declared-type identities, indexed once for its texts. */
        const cbm_type_scope_index_t *scope_ix = cbm_type_scope_index(arena, d->type_scope);

        // Every type-like container (Type/Class/Struct/Interface/Enum/Trait).
        // Struct included so Go structs (now labelled "Struct") register as types.
        if (cbm_label_is_type_like(d->label)) {
            CBMRegisteredType rt;
            memset(&rt, 0, sizeof(rt));
            rt.qualified_name = d->qualified_name; // borrowed
            rt.short_name = d->short_name;         // borrowed
            rt.is_interface = d->is_interface || strcmp(d->label, "Interface") == 0;
            rt.go_identity = d->alias_target ? CBM_GO_IDENTITY_ALIAS
                             : rt.is_interface ? CBM_GO_IDENTITY_INTERFACE
                             : strcmp(d->label, "Struct") == 0 ? CBM_GO_IDENTITY_CONCRETE
                                                               : CBM_GO_IDENTITY_UNKNOWN;
            /* Embedded types other definitions of the QN differ in promote
             * nothing (go_type_qn_table). */
            rt.embedded_types = go_type_qn_embeds(type_qns, d)
                                    ? go_embedded_qns(arena, d, def_mod, scope_ix)
                                    : NULL;

            // Set method_names for interfaces from "|"-separated string
            if (rt.is_interface && d->method_names_str && d->method_names_str[0]) {
                rt.method_names = split_pipe_strings(arena, d->method_names_str);
            }
            rt.alias_of = go_alias_target_qn(arena, d->alias_target, def_mod);
            rt.underlying_type = go_parse_def_type_text(arena, &type_parser, d, def_mod,
                                                        d->go_underlying_type);

            // Struct field types from field_defs, on this def's own entry: a
            // type lookup answers with the last entry of a name, so fields on
            // an earlier receiver placeholder were never seen. A QN of several
            // definitions keeps the fields they agree on (go_type_qn_table).
            const char *fields = go_type_qn_fields(type_qns, d);
            if (fields && fields[0]) {
                (void)parse_field_defs(arena, &type_parser, go_unique_type_def(type_qns, d),
                                       fields, def_mod, scope_ix, &rt.field_names, &rt.field_types);
            }
            /* Embedded types are fields too (Go's selector rule), and a QN of
             * several definitions shadows every field name one declares. */
            go_add_embedded_fields(arena, &rt, d, def_mod, scope_ix,
                                   go_type_qn_embeds(type_qns, d));
            go_add_shadow_fields(arena, &rt, type_qns, d);

            cbm_registry_add_type(&reg, rt);
        }

        // Function/Method
        if (strcmp(d->label, "Function") == 0 || strcmp(d->label, "Method") == 0) {
            CBMRegisteredFunc rf;
            memset(&rf, 0, sizeof(rf));
            rf.qualified_name = d->qualified_name; // borrowed
            rf.short_name = d->short_name;         // borrowed

            // Build FUNC type from return_types text
            const CBMType **ret_types = split_pipe_types(arena, &type_parser, d, def_mod, scope_ix);
            CBMGoLSPSignatureParserContext param_parser_ctx = {def_mod, scope_ix};
            const CBMType **param_types = cbm_type_materialize_signature_params(
                arena, d->signature_param_types, d->signature_param_count,
                cbm_go_lsp_parse_signature_param_text, &param_parser_ctx);
            rf.signature = cbm_type_func(arena, NULL, param_types, ret_types);

            // Method receiver
            if (strcmp(d->label, "Method") == 0 && d->receiver_type && d->receiver_type[0]) {
                rf.receiver_type = d->receiver_type; // borrowed
                // Auto-create type entry if not exists
                if (!cbm_registry_lookup_type(&reg, rf.receiver_type)) {
                    CBMRegisteredType auto_type;
                    memset(&auto_type, 0, sizeof(auto_type));
                    auto_type.qualified_name = rf.receiver_type;
                    const char *dot = strrchr(d->receiver_type, '.');
                    auto_type.short_name = dot ? dot + 1 : rf.receiver_type; // borrowed substring
                    cbm_registry_add_type(&reg, auto_type);
                }
            }

            cbm_registry_add_func(&reg, rf);
        }
        go_register_value(&reg, arena, &type_parser, d, def_mod, scope_ix, value_qns);
    }
    cbm_ht_free(value_qns);

    // 3. Phase 1b: refine shapes from the walked file when definitions lack them.
    {
        GoLSPContext field_ctx = {
            .arena = arena, .source = source, .source_len = source_len,
            .registry = &reg, .package_qn = module_qn,
        };
        for (int i = 0; i < import_count; i++) {
            if (import_names[i] && import_qns[i])
                go_lsp_add_import(&field_ctx, import_names[i], import_qns[i]);
        }
        go_lsp_add_source_imports(&field_ctx, root);
        // Collect top-level children once (O(n)); ts_node_child(root,i) is O(i) → O(n²).
        uint32_t rkn = 0;
        TSNode *rkids = cbm_lsp_collect_children(arena, root, &rkn);
        for (uint32_t i = 0; i < rkn; i++) {
            TSNode top = rkids[i];
            if (strcmp(ts_node_type(top), "type_declaration") != 0)
                continue;
            uint32_t td_nc = ts_node_child_count(top);
            for (uint32_t j = 0; j < td_nc; j++) {
                TSNode spec = ts_node_child(top, j);
                if (ts_node_is_null(spec) || !ts_node_is_named(spec))
                    continue;
                const char *spec_kind2 = ts_node_type(spec);

                // type_alias: type Foo = Bar
                if (strcmp(spec_kind2, "type_alias") == 0) {
                    TSNode alias_name = ts_node_child_by_field_name(spec, "name", 4);
                    TSNode alias_type = ts_node_child_by_field_name(spec, "type", 4);
                    if (!ts_node_is_null(alias_name) && !ts_node_is_null(alias_type)) {
                        char *aname = cbm_node_text(arena, alias_name, source);
                        if (aname && aname[0]) {
                            const char *alias_type_qn =
                                cbm_arena_sprintf(arena, "%s.%s", module_qn, aname);
                            const CBMType *underlying =
                                ts_node_is_null(ts_node_child_by_field_name(
                                    spec, "type_parameters", 15))
                                    ? go_parse_type_node(&field_ctx, alias_type)
                                    : cbm_type_unknown();
                            const char *alias_target_qn = go_member_type_qn(underlying);
                            bool found_a = false;
                            for (int ti = 0; ti < reg.type_count; ti++) {
                                if (reg.types[ti].qualified_name &&
                                    strcmp(reg.types[ti].qualified_name, alias_type_qn) == 0) {
                                    reg.types[ti].alias_of = alias_target_qn;
                                    reg.types[ti].go_identity = CBM_GO_IDENTITY_ALIAS;
                                    reg.types[ti].underlying_type = underlying;
                                    found_a = true;
                                    break;
                                }
                            }
                            if (!found_a) {
                                CBMRegisteredType alias_rt;
                                memset(&alias_rt, 0, sizeof(alias_rt));
                                alias_rt.qualified_name = alias_type_qn;
                                alias_rt.short_name = aname;
                                alias_rt.go_identity = CBM_GO_IDENTITY_ALIAS;
                                alias_rt.alias_of = alias_target_qn;
                                alias_rt.underlying_type = underlying;
                                cbm_registry_add_type(&reg, alias_rt);
                            }
                        }
                    }
                    continue;
                }
                if (strcmp(spec_kind2, "type_spec") != 0 ||
                    !ts_node_is_null(ts_node_child_by_field_name(spec, "type_parameters", 15)))
                    continue;
                TSNode name_node = ts_node_child_by_field_name(spec, "name", 4);
                TSNode type_node = ts_node_child_by_field_name(spec, "type", 4);
                if (ts_node_is_null(name_node) || ts_node_is_null(type_node) ||
                    strcmp(ts_node_type(type_node), "interface_type") == 0)
                    continue;
                const char *name = cbm_node_text(arena, name_node, source);
                if (!name || !name[0])
                    continue;
                const char *qn = cbm_arena_sprintf(arena, "%s.%s", module_qn, name);
                const go_type_qn_t *group = type_qns ? cbm_ht_get(type_qns, qn) : NULL;
                if (!type_qns || (group && group->count > 1))
                    continue;
                for (int ti = reg.type_count - 1; ti >= 0; ti--) {
                    CBMRegisteredType *type = &reg.types[ti];
                    if (!type->qualified_name || strcmp(type->qualified_name, qn) != 0)
                        continue;
                    if (strcmp(ts_node_type(type_node), "struct_type") != 0) {
                        if (!type->underlying_type)
                            type->underlying_type = go_parse_type_node(&field_ctx, type_node);
                    } else if (!type->field_names && !type->embedded_types) {
                        const CBMType *shape = go_parse_type_node(&field_ctx, type_node);
                        if (shape && shape->kind == CBM_TYPE_STRUCT) {
                            const CBMType **embedded = shape->data.struct_type.embedded_types;
                            size_t count = 0;
                            while (embedded && embedded[count])
                                count++;
                            const char **qns = count ? cbm_arena_alloc(
                                arena, (count + 1) * sizeof(*qns)) : NULL;
                            if (qns) {
                                for (size_t k = 0; k < count; k++)
                                    qns[k] = go_member_type_qn(cbm_type_deref(embedded[k]));
                                qns[count] = NULL;
                            }
                            type->embedded_types = qns;
                            type->field_names = shape->data.struct_type.field_names;
                            type->field_types = shape->data.struct_type.field_types;
                        }
                    }
                    break;
                }
            }
        }
    }
    // 4. Build LSP context and run
    GoLSPContext ctx;
    go_lsp_init(&ctx, arena, source, source_len, &reg, module_qn, out);
    ctx.rel_path = rel_path;

    for (int i = 0; i < import_count; i++) {
        if (import_names[i] && import_qns[i]) {
            go_lsp_add_import(&ctx, import_names[i], import_qns[i]);
        }
    }

    go_lsp_add_source_imports(&ctx, root);
    extract_type_params_from_ast(&ctx, &reg, root);
    go_refine_generic_defs(&reg, &type_parser, defs, def_count, module_qn, type_qns);
    cbm_ht_free(type_qns);
    go_index_source_defs(&reg, defs, def_count);
    if (type_parser)
        ts_parser_delete(type_parser);
    cbm_registry_finalize(&reg);
    go_lsp_process_file(&ctx, root);

    // 5. Cleanup — only free if we allocated
    if (owns_tree) {
        ts_tree_delete(tree);
        if (parser)
            ts_parser_delete(parser);
    }
}

/* ── Tier 2: pre-built per-language registry (gopls package summary pattern) ──
 *
 * cbm_go_build_cross_registry runs the registry build ONCE per project (in
 * pipeline.c, before the parallel resolve workers fire). The returned
 * registry is finalized (O(1) lookups) and shared READ-ONLY across all
 * workers in the resolve phase.
 *
 * cbm_run_go_lsp_cross_with_registry is the per-file entrypoint used by
 * the resolve worker. It SKIPS the registry build (uses the pre-built reg)
 * AND skips Phase 1b/1c AST scans (those mutate the registry, which would
 * race with other workers reading the shared reg). Accuracy trade-off:
 * file-local type aliases and struct embeddings discovered ONLY by Phase
 * 1b (and not already in defs[] embedded_types/field_defs strings) are
 * missed. In practice the per-file LSP during extract already captures
 * those via the def strings. */
CBMTypeRegistry *cbm_go_build_cross_registry(CBMArena *arena, CBMLSPDef *defs, int def_count) {
    if (!arena)
        return NULL;
    CBMTypeRegistry *reg = (CBMTypeRegistry *)cbm_arena_alloc(arena, sizeof(*reg));
    if (!reg)
        return NULL;
    cbm_registry_init(reg, arena);
    cbm_go_stdlib_register(reg, arena);

    /* Qualified name -> FIRST type index while the registry is built: it is
     * not finalized until the end, so its own lookup scans every type, and the
     * receiver check below plus the field-definition lookup made the build
     * O(types x (methods + structs)) -- 4.4 s single-threaded on the Go corpus,
     * the scaling lane's field-definition lookup x2.9 (waste sanitizer,
     * 2026-09-17). A receiver's placeholder type added before its struct
     * receives the struct's fields as well as the struct's own entry.
     * NULL on allocation failure: the receiver check scans the registry. */
    CBMHashTable *first_type = cbm_ht_create((uint32_t)(def_count / 4 + 1024));
    CBMHashTable *type_qns = go_type_qn_table(arena, defs, def_count);
    CBMHashTable *value_qns = go_value_qn_counts(arena, defs, def_count, "");
    int noted_types = 0;
#define GO_NOTE_NEW_TYPES()                                                        \
    do {                                                                           \
        for (; first_type && noted_types < reg->type_count; noted_types++) {       \
            const char *tqn = reg->types[noted_types].qualified_name;              \
            if (tqn && !cbm_ht_has(first_type, tqn)) {                             \
                cbm_ht_set(first_type, tqn, (void *)(uintptr_t)(noted_types + 1)); \
            }                                                                      \
        }                                                                          \
    } while (0)
    GO_NOTE_NEW_TYPES();

    TSParser *type_parser = NULL;
    for (int i = 0; i < def_count; i++) {
        CBMLSPDef *d = &defs[i];
        if (!d->qualified_name || !d->short_name || !d->label)
            continue;
        /* Filter to Go defs only — the all_defs[] array is mixed-language. */
        if (d->lang != CBM_LANG_GO)
            continue;
        /* In the pre-built path every def carries its own def_module_qn
         * (set by cbm_pxc_collect_all_defs). There is no caller module to
         * fall back to — this registry is project-wide, not per-file. */
        const char *def_mod = d->def_module_qn ? d->def_module_qn : "";
        /* The def's declared-type identities, indexed once for its texts. */
        const cbm_type_scope_index_t *scope_ix = cbm_type_scope_index(arena, d->type_scope);

        // Every type-like container (Type/Class/Struct/Interface/Enum/Trait).
        // Struct included so Go structs (now labelled "Struct") register as types.
        if (cbm_label_is_type_like(d->label)) {
            CBMRegisteredType rt;
            memset(&rt, 0, sizeof(rt));
            rt.qualified_name = d->qualified_name; /* borrowed */
            rt.short_name = d->short_name;
            rt.is_interface = d->is_interface || strcmp(d->label, "Interface") == 0;
            rt.go_identity = d->alias_target ? CBM_GO_IDENTITY_ALIAS
                             : rt.is_interface ? CBM_GO_IDENTITY_INTERFACE
                             : strcmp(d->label, "Struct") == 0 ? CBM_GO_IDENTITY_CONCRETE
                                                               : CBM_GO_IDENTITY_UNKNOWN;
            /* Embedded types other definitions of the QN differ in promote
             * nothing (go_type_qn_table). */
            rt.embedded_types = go_type_qn_embeds(type_qns, d)
                                    ? go_embedded_qns(arena, d, def_mod, scope_ix)
                                    : NULL;
            if (rt.is_interface && d->method_names_str && d->method_names_str[0]) {
                rt.method_names = split_pipe_strings(arena, d->method_names_str);
            }
            rt.alias_of = go_alias_target_qn(arena, d->alias_target, def_mod);
            /* Fields on this def's own entry, which a lookup after finalize
             * answers with (the last entry of a name). The first entry -- a
             * receiver placeholder when a method came earlier -- keeps them
             * too, for the first-registered readers. A QN of several
             * definitions keeps the fields they agree on (go_type_qn_table). */
            const char *fields = go_type_qn_fields(type_qns, d);
            if (fields && fields[0]) {
                (void)parse_field_defs(arena, &type_parser, go_unique_type_def(type_qns, d),
                                       fields, def_mod, scope_ix, &rt.field_names, &rt.field_types);
            }
            /* Embedded types are fields too (Go's selector rule), and a QN of
             * several definitions shadows every field name one declares. */
            go_add_embedded_fields(arena, &rt, d, def_mod, scope_ix,
                                   go_type_qn_embeds(type_qns, d));
            go_add_shadow_fields(arena, &rt, type_qns, d);
            rt.underlying_type = go_parse_def_type_text(arena, &type_parser, d, def_mod,
                                                        d->go_underlying_type);
            cbm_registry_add_type(reg, rt);
            GO_NOTE_NEW_TYPES();
            uintptr_t at = first_type ? (uintptr_t)cbm_ht_get(first_type, rt.qualified_name) : 0;
            if (rt.field_names && at && (int)at - 1 != reg->type_count - 1) {
                reg->types[at - 1].field_names = rt.field_names;
                reg->types[at - 1].field_types = rt.field_types;
            }
        }

        if (strcmp(d->label, "Function") == 0 || strcmp(d->label, "Method") == 0) {
            CBMRegisteredFunc rf;
            memset(&rf, 0, sizeof(rf));
            rf.qualified_name = d->qualified_name; /* borrowed */
            rf.short_name = d->short_name;
            const CBMType **ret_types = split_pipe_types(arena, &type_parser, d, def_mod, scope_ix);
            CBMGoLSPSignatureParserContext param_parser_ctx = {def_mod, scope_ix};
            const CBMType **param_types = cbm_type_materialize_signature_params(
                arena, d->signature_param_types, d->signature_param_count,
                cbm_go_lsp_parse_signature_param_text, &param_parser_ctx);
            rf.signature = cbm_type_func(arena, NULL, param_types, ret_types);
            if (strcmp(d->label, "Method") == 0 && d->receiver_type && d->receiver_type[0]) {
                rf.receiver_type = d->receiver_type;
                bool known = first_type ? cbm_ht_has(first_type, rf.receiver_type)
                                        : cbm_registry_lookup_type(reg, rf.receiver_type) != NULL;
                if (!known) {
                    CBMRegisteredType auto_type;
                    memset(&auto_type, 0, sizeof(auto_type));
                    auto_type.qualified_name = rf.receiver_type;
                    const char *dot = strrchr(d->receiver_type, '.');
                    auto_type.short_name = dot ? dot + 1 : rf.receiver_type;
                    cbm_registry_add_type(reg, auto_type);
                    GO_NOTE_NEW_TYPES();
                }
            }
            cbm_registry_add_func(reg, rf);
        }
        go_register_value(reg, arena, &type_parser, d, def_mod, scope_ix, value_qns);
    }
    go_refine_generic_defs(reg, &type_parser, defs, def_count, "", type_qns);
    go_index_source_defs(reg, defs, def_count);
    if (type_parser)
        ts_parser_delete(type_parser);
#undef GO_NOTE_NEW_TYPES
    cbm_ht_free(first_type);
    cbm_ht_free(type_qns); /* NULL-safe */
    cbm_ht_free(value_qns);

    cbm_registry_finalize(reg);
    reg->read_only = true; /* seal: shared Tier-2 registry is read-only during resolve */
    return reg;
}

void cbm_run_go_lsp_cross_with_registry(CBMArena *arena, const char *source, int source_len,
                                        const char *module_qn, const char *rel_path,
                                        CBMTypeRegistry *reg, const char **import_names,
                                        const char **import_qns, int import_count,
                                        TSTree *cached_tree, CBMResolvedCallArray *out) {
    if (!source || source_len <= 0 || !reg)
        return;

    TSParser *parser = NULL;
    TSTree *tree = cached_tree;
    bool owns_tree = false;
    if (!tree) {
        parser = ts_parser_new();
        if (!parser)
            return;
        ts_parser_set_language(parser, tree_sitter_go());
        tree = cbm_parse_source(parser, source, (uint32_t)source_len, (TSParseOptions){0});
        owns_tree = true;
        if (!tree) {
            ts_parser_delete(parser);
            return;
        }
    }
    TSNode root = ts_tree_root_node(tree);

    /* Phase 1b/1c (per-file AST mutations on registry) DELIBERATELY SKIPPED —
     * shared registry must stay immutable across parallel workers. */

    GoLSPContext ctx;
    go_lsp_init(&ctx, arena, source, source_len, reg, module_qn, out);
    ctx.rel_path = rel_path;
    for (int i = 0; i < import_count; i++) {
        if (import_names[i] && import_qns[i]) {
            go_lsp_add_import(&ctx, import_names[i], import_qns[i]);
        }
    }
    go_lsp_add_source_imports(&ctx, root);
    go_lsp_process_file(&ctx, root);

    if (owns_tree) {
        ts_tree_delete(tree);
        if (parser)
            ts_parser_delete(parser);
    }
}

/* ── Tier 3: AST-walk-free metadata-driven cross-file resolver ────
 *
 * KEY INSIGHT: the per-file LSP during extract ALREADY emits one
 * CBMResolvedCall per call site, with strategy="lsp_unresolved" for
 * calls it couldn't resolve. For those unresolved entries:
 *
 *   * "symbol_not_in_registry" (go_lsp.c:1142) → callee_qn is
 *     "pkg_name.field_name" (literal local import alias)
 *   * "method_not_found" (go_lsp.c:1242) → callee_qn is
 *     "<FullyQualifiedReceiverTypeQN>.<MethodName>" — receiver type
 *     was ALREADY inferred by per-file LSP, just the method wasn't
 *     in the per-file registry (cross-file)
 *   * "function_not_in_registry" (go_lsp.c:1266) → callee_qn is
 *     the bare function name (likely a same-package symbol we
 *     missed, or a cross-file package function used unqualified)
 *   * "unknown_receiver_type" (go_lsp.c:1248) → per-file LSP
 *     couldn't infer the receiver type. Cross-LSP can't either
 *     without re-walking — leave unresolved.
 *
 * So cross-LSP work reduces to:
 *   for each unresolved entry → look up callee_qn (or pkg.x via
 *   import map) in the global registry → emit resolved version
 *   on top. NO TREE-SITTER PARSE. NO AST WALK. Just hash lookups.
 *
 * This is what the user meant: walk the AST ONCE (during extract),
 * capture everything cross-LSP needs as metadata, and let cross-LSP
 * be a pure lookup pass. */
int cbm_go_fast_resolve_qualified_calls(CBMFileResult *result, CBMTypeRegistry *reg,
                                        const char **import_names, const char **import_qns,
                                        int import_count) {
    if (!result || !reg)
        return 0;
    /* Snapshot the count: we append to resolved_calls inside the loop,
     * but only want to scan the original unresolved entries. */
    int initial_count = result->resolved_calls.count;
    int newly_resolved = 0;

    for (int i = 0; i < initial_count; i++) {
        const CBMResolvedCall *uc = &result->resolved_calls.items[i];
        if (!uc->strategy || !uc->callee_qn || !uc->caller_qn)
            continue;
        if (strcmp(uc->strategy, "lsp_unresolved") != 0)
            continue;
        if (uc->reason && strcmp(uc->reason, "lexical_value_not_exact_callable") == 0)
            continue;

        /* Case 1: callee_qn is already a fully-qualified type/pkg
         * symbol that per-file LSP couldn't find in its local registry
         * but the global registry has. (method_not_found with NAMED
         * receiver, or any other case where callee_qn looks like a
         * full QN). Direct lookup. */
        const CBMRegisteredFunc *f = go_lookup_func_callable(reg, uc->callee_qn);

        /* Case 2: callee_qn is "local_pkg_alias.suffix" — the alias
         * needs translating through the file's import map to get the
         * real module QN. */
        if (!f) {
            const char *dot = strchr(uc->callee_qn, '.');
            if (dot) {
                size_t prefix_len = (size_t)(dot - uc->callee_qn);
                if (prefix_len > 0 && prefix_len < 256) {
                    char prefix[256];
                    memcpy(prefix, uc->callee_qn, prefix_len);
                    prefix[prefix_len] = '\0';
                    const char *suffix = dot + 1;
                    for (int j = 0; j < import_count; j++) {
                        if (import_names[j] && import_qns[j] &&
                            strcmp(prefix, import_names[j]) == 0) {
                            char fq[1024];
                            int n = snprintf(fq, sizeof(fq), "%s.%s", import_qns[j], suffix);
                            if (n > 0 && n < (int)sizeof(fq)) {
                                f = go_lookup_func_callable(reg, fq);
                            }
                            break;
                        }
                    }
                }
            }
        }

        /* Case 3: an unqualified function value from another source file in
         * the same Go package. Go module QNs are directory-based, so this is
         * an exact package-local lookup rather than a project-wide short-name
         * guess. */
        if (!f && !strchr(uc->callee_qn, '.') && result->module_qn) {
            f = go_lookup_callable(reg, result->module_qn, uc->callee_qn);
        }

        if (!f)
            continue;

        /* Cross-file interface signatures describe a contract, not a concrete
         * runtime receiver. Leave these sites for the AST dispatch diagnostic. */
        if (f->receiver_type) {
            const CBMRegisteredType *receiver =
                cbm_registry_resolve_alias(reg, f->receiver_type);
            if (receiver && receiver->is_interface)
                continue;
        }

        /* Emit a resolved entry. cbm_pipeline_find_lsp_resolution
         * picks the highest-confidence match, so the unresolved entry
         * stays (harmless duplicate) but our resolved entry wins. */
        CBMResolvedCall rc = {0};
        rc.caller_qn = uc->caller_qn;
        rc.callee_qn = f->qualified_name; /* borrowed from pipeline arena */
        rc.strategy = "lsp_strategy_cross_file";
        rc.confidence = 0.92f;
        rc.reason = NULL;
        rc.kind = uc->kind;
        rc.site_start_byte = uc->site_start_byte;
        rc.site_end_byte = uc->site_end_byte;
        cbm_resolvedcall_push(&result->resolved_calls, &result->arena, rc);
        newly_resolved++;
    }

    /* Return value mirrors the old contract (count of items still
     * needing the slow path) but is always 0 now — caller should
     * unconditionally skip the slow path for Go. */
    (void)newly_resolved;
    return 0;
}

// --- Batch cross-file LSP ---

void cbm_batch_go_lsp_cross(CBMArena *arena, CBMBatchGoLSPFile *files, int file_count,
                            CBMResolvedCallArray *out) {
    if (!files || file_count <= 0 || !out)
        return;

    for (int f = 0; f < file_count; f++) {
        CBMBatchGoLSPFile *file = &files[f];
        memset(&out[f], 0, sizeof(CBMResolvedCallArray));

        if (!file->source || file->source_len <= 0 || file->def_count <= 0)
            continue;

        // Per-file arena: registry + temp data freed after each file
        CBMArena file_arena;
        cbm_arena_init(&file_arena);

        CBMResolvedCallArray file_out;
        memset(&file_out, 0, sizeof(file_out));

        // Delegate to existing per-file function
        cbm_run_go_lsp_cross(&file_arena, file->source, file->source_len, file->module_qn,
                             file->rel_path, file->defs, file->def_count, file->import_names,
                             file->import_qns, file->import_count, file->cached_tree, &file_out);

        // Copy results to output arena (must outlive per-file arena)
        if (file_out.count > 0) {
            out[f].count = file_out.count;
            out[f].items =
                (CBMResolvedCall *)cbm_arena_alloc(arena, file_out.count * sizeof(CBMResolvedCall));
            for (int j = 0; j < file_out.count; j++) {
                CBMResolvedCall *src = &file_out.items[j];
                CBMResolvedCall *dst = &out[f].items[j];
                memset(dst, 0, sizeof(*dst));
                dst->caller_qn = src->caller_qn ? cbm_arena_strdup(arena, src->caller_qn) : NULL;
                dst->callee_qn = src->callee_qn ? cbm_arena_strdup(arena, src->callee_qn) : NULL;
                dst->strategy = src->strategy ? cbm_arena_strdup(arena, src->strategy) : NULL;
                dst->confidence = src->confidence;
                dst->reason = src->reason ? cbm_arena_strdup(arena, src->reason) : NULL;
                dst->kind = src->kind;
                dst->site_start_byte = src->site_start_byte;
                dst->site_end_byte = src->site_end_byte;
            }
        }

        cbm_arena_destroy(&file_arena);
    }
}
