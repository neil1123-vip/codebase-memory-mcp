#ifndef CBM_COMPILER_FACTS_H
#define CBM_COMPILER_FACTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../graph_buffer/graph_buffer.h"
#include "lsp/type_registry.h"
#include "../../vendored/yyjson/yyjson.h"

typedef struct CBMCompilerFacts CBMCompilerFacts;

/* Check stored dependencies beneath the configured compiler directory only.
 * Success alone never establishes that the stored facts are current. */
bool cbm_compiler_facts_ts_dependencies_current(yyjson_val *context, const char *typescript);

/* Raw-source identities survive logical-QN aggregation without clearing
 * the aggregate's ambiguity. All fields are part of the stable physical key. */
char *cbm_compiler_go_declaration_qn(CBMArena *arena, const char *logical, const char *path,
                                    const char *label, const char *sha256, uint32_t start,
                                    uint32_t end, uint32_t origin);
char *cbm_compiler_js_declaration_qn(CBMArena *arena, const char *logical, const char *path,
                                    const char *label, const char *sha256, uint32_t start,
                                    uint32_t end, uint32_t origin);

typedef struct {
    size_t argument;
    size_t parameter_count;
    const char **param_names;
    const CBMType **param_types;
} CBMCompilerContextParams;

typedef struct {
    const char *path;
    const char *sha256;
    uint64_t byte_length;
} CBMCompilerInput;

typedef struct {
    const char *path;
    const char *sha256;
    uint32_t start_byte;
    uint32_t end_byte;
    uint32_t callee_start_byte;
    uint32_t callee_end_byte;
    const char *dispatch;
    const char *target_qn;
    const char *target_package;
    const char *symbol_name;
    const char *reason;
    bool external_symbol;
    bool proof_partial;
    bool target_authoritative;
    bool types_authoritative;
    const CBMType *type;
    const CBMType *signature;
    const CBMType *receiver;
    const CBMCompilerContextParams *contextual_params;
    size_t contextual_param_count;
    const char *route_handler_qn;
} CBMCompilerSite;

/* Inputs are the complete language-specific discovery whitelist. Parsing never
 * executes helpers. Any invalid snapshot is rejected in full with a short error.
 * JSON, input strings and gbuf may be released after successful parsing.
 * Context/cache fingerprints are shape-checked; the runner must bind them to the
 * current invocation and may only admit a successful, context-current export.
 * TypeScript discovery, dependency hashes and project resolution observations
 * are mandatory and rechecked before projection. Schema-2 TypeScript partial
 * indexes retain complete Error diagnostics and expose only source-verified
 * local targets; all their types stay UNKNOWN and registry merge is a no-op. */
CBMCompilerFacts *cbm_compiler_facts_parse(const char *json, size_t length, const char *root,
                                           const char *language, const CBMCompilerInput *inputs,
                                           size_t input_count, const cbm_gbuf_t *gbuf, char *error,
                                           size_t error_size);

/* Schema-2 Go index with independently bounded package-cache fragments.
 * The directory is runner-owned. Every descriptor, fragment and manifest is
 * verified before any site is exposed. Partial indexes retain native fallback
 * for files with incomplete variants and never enrich the global registry. */
CBMCompilerFacts *cbm_compiler_facts_parse_index(
    const char *json, size_t length, const char *root, const CBMCompilerInput *inputs,
    size_t input_count, const cbm_gbuf_t *gbuf, const char *fragment_directory, char *error,
    size_t error_size);

/* Explicit schema-3 chunk_index_v1 profile. All chunks are validated before
 * admission. The catalogue owns declaration names, so gbuf may be released.
 * One chunk view may be borrowed at a time, in nondecreasing file_order.
 * A repeated file in the current chunk reuses its projection. After release,
 * finish_files verifies the complete manifest and compressed ledger again.
 * Any acquire/finish failure after admission must abort the staged index. */
CBMCompilerFacts *cbm_compiler_facts_parse_chunk_index(
    const char *json, size_t length, const char *root, const CBMCompilerInput *inputs,
    size_t input_count, const cbm_gbuf_t *gbuf, const char *fragment_directory, char *error,
    size_t error_size);
/* Explicit schema-4/helper-5 chunk_index_v2. Fragment-local dictionaries are
 * read directly; the catalogue/view ownership contract is identical to v1. */
CBMCompilerFacts *cbm_compiler_facts_parse_compact_chunk_index(
    const char *json, size_t length, const char *root, const CBMCompilerInput *inputs,
    size_t input_count, const cbm_gbuf_t *gbuf, const char *fragment_directory, char *error,
    size_t error_size);
/* Explicit TypeScript schema-3 file_index_v1 or partial proof_index_v1.
 * The final global JSONL ledger shares the 32 MiB document allowance.
 * Proof views expose target/type authority separately and never merge registry
 * declarations. File views contain dense closed rows. */
CBMCompilerFacts *cbm_compiler_facts_parse_ts_chunk_index(
    const char *json, size_t length, const char *root, const CBMCompilerInput *inputs,
    size_t input_count, const cbm_gbuf_t *gbuf, const char *fragment_directory, char *error,
    size_t error_size);
bool cbm_compiler_facts_is_chunk_index(const CBMCompilerFacts *facts);
size_t cbm_compiler_facts_file_order(const CBMCompilerFacts *facts, const char *path);
bool cbm_compiler_facts_file_matches(const CBMCompilerFacts *facts, const char *path,
                                      const char *sha256);
/* Selection evidence exists only for an exact source in a complete Go index. */
bool cbm_compiler_facts_go_file_unselected(const CBMCompilerFacts *facts, const char *path,
                                          const char *sha256);
bool cbm_compiler_facts_go_selection_digest(const CBMCompilerFacts *facts, char digest[65]);
bool cbm_compiler_facts_acquire_file(CBMCompilerFacts *facts, const char *path,
                                      const CBMCompilerFacts **view, char *error,
                                      size_t error_size);
void cbm_compiler_facts_release_file(CBMCompilerFacts *facts);
bool cbm_compiler_facts_finish_files(CBMCompilerFacts *facts, char *error, size_t error_size);

/* Re-parse the retained document against a fresh discovery manifest and graph.
 * Source hashes, TypeScript context observations and declaration spans are
 * checked again; node IDs never carry. */
CBMCompilerFacts *cbm_compiler_facts_rebind(const CBMCompilerFacts *facts, const char *root,
                                            const CBMCompilerInput *inputs, size_t input_count,
                                            const cbm_gbuf_t *gbuf, char *error, size_t error_size);

/* Package-key membership used by the incremental planner. Inputs are a
 * previously verified manifest; this check never reads historical source bytes. */
bool cbm_compiler_facts_go_package_manifest_valid(yyjson_val *cache,
                                                  const CBMCompilerInput *inputs, size_t count);

void cbm_compiler_facts_free(CBMCompilerFacts *facts);
/* Chunk catalogues return their prevalidated consensus total. Their rows are
 * available only through acquire_file views; site/find do not enumerate the
 * catalogue. Other profiles expose the retained rows as before. */
size_t cbm_compiler_facts_count(const CBMCompilerFacts *facts);
const CBMCompilerSite *cbm_compiler_facts_site(const CBMCompilerFacts *facts, size_t index);

/* Only the complete AST call occurrence matches, never another call's callee
 * alias. Conflicting variants still return their verified unknown consensus. */
const CBMCompilerSite *cbm_compiler_facts_find_occurrence(
    const CBMCompilerFacts *facts, const char *path, const char *sha256, uint32_t start,
    uint32_t end);

/* Only exact whole-call or callee spans match, including variant aliases.
 * Conflicts return an unknown site so native fallback cannot erase ambiguity. */
const CBMCompilerSite *cbm_compiler_facts_find(const CBMCompilerFacts *facts, const char *path,
                                               const char *sha256, uint32_t start, uint32_t end);

/* Borrowed read-only snapshot/index document, including context and coverage.
 * All returned pointers remain valid until cbm_compiler_facts_free(). */
yyjson_val *cbm_compiler_facts_json(const CBMCompilerFacts *facts);

/* Immutable arena projections; zero/unsupported IDs are UNKNOWN. Shape never
 * establishes exact callable identity. All pointers live until facts_free. */
const CBMType *cbm_compiler_facts_type(const CBMCompilerFacts *facts, size_t id);

/* Merge only verified exact-QN declarations into a writable registry/overlay.
 * NULL path selects all declarations; a path selects its indexed file range.
 * Native metadata and missing/unknown fields or slots survive. On success,
 * retained fact types, strings and metadata belong to the registry arena, so
 * facts may be freed before registry users finish. Native/fallback ownership
 * is unchanged. Copy allocations are additional registry-arena memory. */
bool cbm_compiler_facts_merge_registry(const CBMCompilerFacts *facts, CBMTypeRegistry *registry,
                                       const char *rel_path);

#endif
