#ifndef CBM_LSP_TS_LSP_H
#define CBM_LSP_TS_LSP_H

#include "lsp_name_rows.h"
#include "type_rep.h"
#include "scope.h"
#include "type_registry.h"
#include "../cbm.h"
#include "../helpers.h"
#include "go_lsp.h" // for CBMLSPDef, CBMResolvedCallArray (shared cross-language)

struct CBMCompilerFacts;

// TSLSPContext holds state for TypeScript / JavaScript / JSX / TSX expression type
// evaluation within a single file. One context per cbm_run_ts_lsp invocation.
//
// Mode flags choose dialect behaviour:
//   - js_mode:  .js / .jsx — JSDoc inference is the primary type source; missing annotations
//               default to UNKNOWN rather than failing.
//   - jsx_mode: .jsx / .tsx — JSX expressions are recognised; intrinsic elements map to
//               builtin types; component calls register through the registry.
//   - dts_mode: .d.ts ambient declarations — no function bodies; populate registry only,
//               emit no resolved calls.
//
// Modes are independent: a `.tsx` file sets jsx_mode=true with js_mode=false; a `.jsx` file
// sets both true.
typedef struct {
    CBMArena *arena;
    const char *source;
    int source_len;
    const CBMTypeRegistry *registry;
    CBMScope *current_scope;
    CBMScope *written_functions; // file-level writes block only new function-value aliases

    // Import map: local_name -> module QN (resolved or opaque).
    // Parallel arrays of length import_count.
    const char **import_local_names;
    const char **import_module_qns;
    int import_count;
    int import_capacity;     // rows the two arrays hold (ts_lsp_add_import)
    CBMNameRows import_rows; // import_local_names by name, rows in table order

    // Named import evidence: renamed imports and known library identity imports.
    // Local binding -> exported name, in parallel arrays of import_alias_count.
    // A binding absent here keeps its local name for ordinary symbol lookup.
    const char **import_alias_locals;
    const char **import_alias_exports;
    int import_alias_count;
    size_t import_alias_capacity;

    // File / surrounding context.
    const char *module_qn;          // QN of this file's module
    const char *enclosing_func_qn;  // current function being walked, NULL at module scope
    const char *enclosing_class_qn; // current class for `this` resolution
    CBMJsObjectOwners js_object_owners;
    const CBMDefArray *file_defs;

    // Output: resolved calls accumulate here.
    CBMResolvedCallArray *resolved_calls;
    // Optional raw usages owned by the per-file extraction result. The scope
    // pass marks occurrence-exact module/import shadows without emitting a
    // semantic reference record for them.
    CBMUsageArray *usages;

    // Type-parameter scope (innermost generic function/class).
    // type_param_constraints may be NULL or shorter — entries default to "any".
    const char **type_param_names;
    const CBMType **type_param_constraints;
    int type_param_count;

    // Mode flags — see comment above.
    bool js_mode;
    bool jsx_mode;
    bool dts_mode;
    bool cross_file_mode; // project-wide registry is available for exact reference proof
    bool strict; // tsconfig "strict": true → fewer implicit-any fallbacks
    bool debug;  // CBM_LSP_DEBUG env

    // Recursion guard for ts_eval_expr_type (mirrors c_lsp).
    int eval_depth;
    // Expression-type memo: node.id -> evaluated type (lazily created on the
    // first completed eval; see TsEvalMemo in ts_lsp.c). Kills the exponential
    // re-evaluation of shared subexpressions under overload resolution.
    struct TsEvalMemo *eval_memo;
    // Declaration facts stay separate from exact callable identities.
    unsigned library_environment; // 0 unknown, 1 Node, 2 browser
    struct TSLibCallbackFacts *callback_facts;
    TSNode file_root;
    bool collecting_callback_facts;
    bool has_library_facts;
    bool isolated_page_context;
    bool page_fetch_blocked;
    bool require_shadowed; // module declarations shadow the loader even without registry defs
    uint32_t commonjs_load_end; // end of the leading verified Node load declarations
    const struct CBMCompilerFacts *compiler_facts;
    const char *compiler_path;
    const char *compiler_sha256;
} TSLSPContext;

/* The imports with this local name, in table order (lsp_name_rows.h). */
static inline int ts_import_first(TSLSPContext *ctx, const char *name) {
    return cbm_name_rows_first(&ctx->import_rows, ctx->arena, ctx->import_local_names,
                               ctx->import_count, name);
}
static inline int ts_import_next(const TSLSPContext *ctx, const char *name, int row) {
    return cbm_name_rows_next(&ctx->import_rows, ctx->import_local_names, ctx->import_count, name,
                              row);
}

#ifdef CBM_ENABLE_TEST_SEAMS
// Complexity-regression seam: remaining expression-eval budget / warned flag
// for the calling thread, valid after a cbm_run_ts_lsp on the same thread.
long cbm_ts_lsp_test_budget_remaining(void);
bool cbm_ts_lsp_test_budget_warned(void);
// Registry entries/probes visited by the two AST signature passes in the last run.
unsigned long cbm_ts_lsp_test_signature_lookup_work(void);
// Inspect signature-index selection and checked walker addition without huge ASTs.
int cbm_ts_lsp_test_signature_func_index(CBMTypeRegistry *reg, const char *qn);
int cbm_ts_lsp_test_walk_pending_count(int top, uint32_t count);
// Maximum recursive calls in one member/method lookup during the last TS LSP run,
// including attempts rejected by the depth or visited-type guard.
int cbm_ts_lsp_test_max_member_lookup_steps(void);
int cbm_ts_lsp_test_max_method_lookup_steps(void);
#endif

// --- Initialization ---

// Initialise a TSLSPContext for processing one file. Mode flags select dialect.
void ts_lsp_init(TSLSPContext *ctx, CBMArena *arena, const char *source, int source_len,
                 const CBMTypeRegistry *registry, const char *module_qn, bool js_mode,
                 bool jsx_mode, bool dts_mode, CBMResolvedCallArray *out);

// Register an import: local binding name → module QN (or unresolved module specifier).
void ts_lsp_add_import(TSLSPContext *ctx, const char *local_name, const char *module_qn);

// Walk the entire file: bind module-level declarations, then process every function /
// method body. Safe on any tree-sitter root; emits zero calls in dts_mode.
void ts_lsp_process_file(TSLSPContext *ctx, TSNode root);

/* Start anchor for a TS/JS invocation or its callee. The end stays unchanged. */
TSNode cbm_ts_call_start_node(TSNode node, const char *source);

// --- Internals exposed for tests and stdlib data ---

// Evaluate the type of a TS/JS expression node. Returns cbm_type_unknown() on miss.
const CBMType *ts_eval_expr_type(TSLSPContext *ctx, TSNode node);

// Parse a TS/JS type-position AST node into a CBMType.
const CBMType *ts_parse_type_node(TSLSPContext *ctx, TSNode node);

// Process a single statement node, binding any variables it declares into ctx->current_scope.
void ts_process_statement(TSLSPContext *ctx, TSNode node);

// --- Entry points ---

// Single-file LSP. Builds a registry from result->defs + the TS stdlib subset, runs
// resolution, and writes resolved calls into result->resolved_calls.
void cbm_run_ts_lsp(CBMArena *arena, CBMFileResult *result, const char *source, int source_len,
                    TSNode root, bool js_mode, bool jsx_mode, bool dts_mode);

// Cross-file LSP. Caller passes in cross-file definitions (CBMLSPDef list) and the
// resolved import → module-QN map. Re-parses source if cached_tree is NULL.
void cbm_run_ts_lsp_cross_for_file(
    CBMArena *arena, const char *source, int source_len, const char *module_qn, bool js_mode,
    bool jsx_mode, bool dts_mode, CBMLSPDef *defs, int def_count, const char **import_names,
    const char **import_qns, int import_count, TSTree *cached_tree, CBMResolvedCallArray *out,
    const CBMDefArray *file_defs);

static inline void cbm_run_ts_lsp_cross(
    CBMArena *arena, const char *source, int source_len, const char *module_qn, bool js_mode,
    bool jsx_mode, bool dts_mode, CBMLSPDef *defs, int def_count, const char **import_names,
    const char **import_qns, int import_count, TSTree *cached_tree, CBMResolvedCallArray *out) {
    cbm_run_ts_lsp_cross_for_file(arena, source, source_len, module_qn, js_mode, jsx_mode, dts_mode,
                                  defs, def_count, import_names, import_qns, import_count,
                                  cached_tree, out, NULL);
}

// Tier 2: build a project-wide TS/JS/TSX registry ONCE from all defs
// (filters by lang). Shared READ-ONLY base; per-file overlays chain to
// it via the registry fallback pointer.
CBMTypeRegistry *cbm_ts_build_cross_registry(CBMArena *arena, CBMLSPDef *defs, int def_count);

// Tier 2 per-file resolve. Builds a small per-file overlay (the file's
// own-module defs, AST-refined) that chains to the shared base `reg`.
// `defs`/`def_count` are the file's relevant defs (own + imports); only
// own-module ones are registered into the overlay.
void cbm_run_ts_lsp_cross_with_registry(CBMArena *arena, const char *source, int source_len,
                                        const char *module_qn, bool js_mode, bool jsx_mode,
                                        bool dts_mode, CBMTypeRegistry *reg, CBMLSPDef *defs,
                                        int def_count, const char **import_names,
                                        const char **import_qns, int import_count,
                                        TSTree *cached_tree, CBMResolvedCallArray *out);

/* Verified snapshot types are merged after native AST refinement. */
void cbm_run_ts_lsp_cross_with_compiler(
    CBMArena *arena, const char *source, int source_len, const char *module_qn, bool js_mode,
    bool jsx_mode, bool dts_mode, CBMTypeRegistry *reg, CBMLSPDef *defs, int def_count,
    const char **import_names, const char **import_qns, int import_count, TSTree *cached_tree,
    CBMResolvedCallArray *out, const struct CBMCompilerFacts *facts, const char *rel_path,
    const char *sha256, const CBMDefArray *file_defs);

// Register the TypeScript / JavaScript stdlib subset (Promise, Array<T>, Map<K,V>, Set<T>,
// Object, Function, console, JSON) into a registry. v1 is hand-curated; a generator script
// will replace this in v1.3.
void cbm_ts_stdlib_register(CBMTypeRegistry *reg, CBMArena *arena);

// TEST HOOKS: count of full per-file cross-registry builds (the quadratic the
// shared-registry dispatch eliminates; must stay 0 on the shared path).
long cbm_ts_full_registry_builds(void);
void cbm_ts_full_registry_builds_reset(void);

// --- Batch cross-file LSP ---

// Per-file input for batch TS LSP processing.
typedef struct {
    const char *source;
    int source_len;
    const char *module_qn;
    bool js_mode;
    bool jsx_mode;
    bool dts_mode;
    TSTree *cached_tree; // from TSTree caching (NULL = parse internally)
    CBMLSPDef *defs;     // combined file-local + cross-file defs
    int def_count;
    const char **import_names; // parallel arrays, import_count long
    const char **import_qns;
    int import_count;
} CBMBatchTSLSPFile;

// Process multiple TS/JS files' cross-file LSP in one CGo call.
// out must point to file_count pre-zeroed CBMResolvedCallArray structs.
// Project-scope declaration merging happens here (per plan §17 finding #4).
void cbm_batch_ts_lsp_cross(CBMArena *arena, CBMBatchTSLSPFile *files, int file_count,
                            CBMResolvedCallArray *out);

#endif // CBM_LSP_TS_LSP_H
