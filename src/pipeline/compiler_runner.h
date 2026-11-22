#ifndef CBM_COMPILER_RUNNER_H
#define CBM_COMPILER_RUNNER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>

#include "discover/discover.h"
#include "pipeline/compiler_facts.h"

typedef struct CBMCompilerRun CBMCompilerRun;

/* Helpers are opt-in. Without either helper setting, no child is started. */
bool cbm_compiler_runner_enabled(void);

/* Run each configured language helper once with its complete discovery
 * manifest. gbuf must contain final declaration identities. Rejected facts
 * leave a usable owner with degraded status; partial indexes can expose
 * verified direct sites without complete type coverage. NULL means allocation failure. */
CBMCompilerRun *cbm_compiler_runner_prepare(const char *root, const cbm_file_info_t *files,
                                            int file_count, const cbm_gbuf_t *gbuf,
                                            atomic_int *cancel, char *error, size_t error_size);
/* Revalidate the complete discovery/hash set and bind retained facts to fresh
 * declaration identities without starting another helper. NULL aborts repair. */
CBMCompilerRun *cbm_compiler_runner_rebind(const CBMCompilerRun *run, const char *root,
                                           const cbm_file_info_t *files, int file_count,
                                           const cbm_gbuf_t *gbuf, atomic_int *cancel, char *error,
                                           size_t error_size);
void cbm_compiler_runner_free(CBMCompilerRun *run);

const CBMCompilerFacts *cbm_compiler_runner_facts(const CBMCompilerRun *run, CBMLanguage language);
bool cbm_compiler_runner_go_file_unselected(const CBMCompilerRun *run, const char *path,
                                           const char *sha256);

/* Chunk profiles have no global view. Resolve their files in returned order,
 * acquire/apply/release each file, then seal before publishing the generation.
 * A NULL order preserves the original schedule. All calls are single-threaded. */
bool cbm_compiler_runner_order_files(const CBMCompilerRun *run, const cbm_file_info_t *files,
                                      int file_count, int **order);
bool cbm_compiler_runner_has_chunk_index(const CBMCompilerRun *run);
bool cbm_compiler_runner_language_has_chunk_index(const CBMCompilerRun *run,
                                                  CBMLanguage language);
bool cbm_compiler_runner_acquire_file(CBMCompilerRun *run, CBMLanguage language,
                                       const char *path, const char *source_sha256,
                                       const CBMCompilerFacts **view);
void cbm_compiler_runner_release_file(CBMCompilerRun *run, CBMLanguage language);
bool cbm_compiler_runner_finish_files(CBMCompilerRun *run);

/* Borrowed immutable site, or NULL when no admitted exact site exists. */
const CBMCompilerSite *cbm_compiler_runner_find(const CBMCompilerRun *run, CBMLanguage language,
                                                const char *path, const char *sha256,
                                                uint32_t start_byte, uint32_t end_byte);

/* Borrowed JSON object containing per-language status/reason/counts. */
const char *cbm_compiler_runner_status(const CBMCompilerRun *run);

/* Called during single-threaded registry preparation. Exact admitted site
 * facts remain available, while coverage records the failed type enhancement. */
void cbm_compiler_runner_registry_failed(CBMCompilerRun *run, CBMLanguage language);

#ifdef CBM_ENABLE_TEST_SEAMS
void cbm_compiler_runner_test_timeout_ms(int timeout_ms);
#endif

#endif
