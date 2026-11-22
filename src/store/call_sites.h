#ifndef CBM_CALL_SITES_H
#define CBM_CALL_SITES_H

#include "store/store.h"

typedef struct cbm_call_site_spool cbm_call_site_spool_t;

typedef struct {
    const char *rel_path;
    const char *source_hash;
    bool counts_complete;
    bool analysis_limited;
} cbm_call_site_file_t;

typedef struct {
    uint32_t start_byte;
    uint32_t end_byte;
    int origin;
    bool is_reference;
    const char *leaf;
    const char *caller_qn;
    const char *category;
    const char *target_qn;
    const char *reason;
    const char *strategy;
} cbm_call_site_t;

/* A disk-backed SQLite temporary database, removed when freed. The caller
 * serializes access. put_file copies all input and atomically replaces a file;
 * site_index is its zero-based position in the caller's sorted site array.
 * A missing source hash or unlocated site requires counts_complete=false. */
cbm_call_site_spool_t *cbm_call_site_spool_new(void);
void cbm_call_site_spool_free(cbm_call_site_spool_t *spool);
int cbm_call_site_spool_put_file(cbm_call_site_spool_t *spool, const cbm_call_site_file_t *file,
                                 const cbm_call_site_t *sites, int count);

/* Replaces only this project's rows inside a savepoint, preserving an outer
 * transaction. Full publication passes NULL baseline_path. Incremental
 * publication streams baseline files absent from spool and still present with
 * matching baseline/target file_hashes manifest digests, then adds spool files.
 * source_hash is the raw source digest, retained separately from the manifest.
 * Missing baseline tables return CBM_STORE_NOT_FOUND so callers can rebuild.
 * Any other failure returns CBM_STORE_ERR and rolls back the replacement.
 * NULL spool is an empty fresh set. No generation is guessed here: these tables
 * are published with the enclosing graph database's generation. */
int cbm_store_call_sites_publish(cbm_store_t *store, const char *project,
                                 cbm_call_site_spool_t *spool, const char *baseline_path);

/* Details for the latest operation on this thread; NULL after success. */
const char *cbm_call_sites_last_error(void);

#endif
