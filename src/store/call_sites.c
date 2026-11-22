#include "store/call_sites.h"
#include "foundation/compat.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cbm_call_site_spool {
    sqlite3 *db;
};

typedef struct {
    sqlite3_stmt *file;
    sqlite3_stmt *site;
} call_site_writer_t;

static CBM_TLS char call_site_error[512];

static const char call_site_schema[] =
    "CREATE TABLE IF NOT EXISTS call_site_files ("
    "project TEXT NOT NULL, rel_path TEXT NOT NULL, source_hash TEXT NOT NULL,"
    "counts_complete INTEGER NOT NULL CHECK(counts_complete IN (0,1)),"
    "analysis_limited INTEGER NOT NULL CHECK(analysis_limited IN (0,1)),"
    "PRIMARY KEY(project,rel_path)) WITHOUT ROWID;"
    "CREATE TABLE IF NOT EXISTS call_sites ("
    "project TEXT NOT NULL, rel_path TEXT NOT NULL,"
    "site_index INTEGER NOT NULL CHECK(site_index>=0),"
    "start_byte INTEGER NOT NULL CHECK(start_byte BETWEEN 0 AND 4294967295),"
    "end_byte INTEGER NOT NULL CHECK(end_byte BETWEEN start_byte AND 4294967295),"
    "origin INTEGER NOT NULL,"
    "is_reference INTEGER NOT NULL CHECK(is_reference IN (0,1)),"
    "leaf TEXT NOT NULL, caller_qn TEXT NOT NULL, category TEXT NOT NULL,"
    "target_qn TEXT NOT NULL, reason TEXT NOT NULL, strategy TEXT NOT NULL,"
    "PRIMARY KEY(project,rel_path,site_index)) WITHOUT ROWID;";

static int site_error(const char *context, const char *detail) {
    snprintf(call_site_error, sizeof(call_site_error), "%s: %s", context,
             detail ? detail : "unknown error");
    return CBM_STORE_ERR;
}

static int site_sql_error(sqlite3 *db, const char *context) {
    return site_error(context, sqlite3_errmsg(db));
}

const char *cbm_call_sites_last_error(void) {
    return call_site_error[0] ? call_site_error : NULL;
}

static int site_exec(sqlite3 *db, const char *sql, const char *context) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? CBM_STORE_OK
                                                                : site_sql_error(db, context);
}

static int site_prepare(sqlite3 *db, const char *sql, sqlite3_stmt **stmt) {
    return sqlite3_prepare_v2(db, sql, -1, stmt, NULL) == SQLITE_OK
               ? CBM_STORE_OK
               : site_sql_error(db, "call sites prepare");
}

static int site_bind_text(sqlite3_stmt *stmt, int index, const char *text) {
    if (sqlite3_bind_text(stmt, index, text ? text : "", -1, SQLITE_TRANSIENT) == SQLITE_OK) {
        return CBM_STORE_OK;
    }
    return site_sql_error(sqlite3_db_handle(stmt), "call sites bind");
}

static int site_step_write(sqlite3_stmt *stmt) {
    int result = CBM_STORE_OK;
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        result = site_sql_error(sqlite3_db_handle(stmt), "call sites write");
    }
    (void)sqlite3_reset(stmt);
    (void)sqlite3_clear_bindings(stmt);
    return result;
}

static void site_writer_close(call_site_writer_t *writer) {
    sqlite3_finalize(writer->file);
    sqlite3_finalize(writer->site);
    memset(writer, 0, sizeof(*writer));
}

static int site_writer_open(sqlite3 *db, call_site_writer_t *writer) {
    if (site_prepare(db,
                     "INSERT INTO call_site_files "
                     "(project,rel_path,source_hash,counts_complete,analysis_limited)"
                     " VALUES (?1,?2,?3,?4,?5)",
                     &writer->file) != CBM_STORE_OK ||
        site_prepare(db,
                     "INSERT INTO call_sites "
                     "(project,rel_path,site_index,start_byte,end_byte,origin,is_reference,"
                     "leaf,caller_qn,category,target_qn,reason,strategy)"
                     " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                     &writer->site) != CBM_STORE_OK) {
        site_writer_close(writer);
        return CBM_STORE_ERR;
    }
    return CBM_STORE_OK;
}

static int site_write_file(call_site_writer_t *writer, const char *project,
                           const cbm_call_site_file_t *file) {
    sqlite3_stmt *stmt = writer->file;
    if (site_bind_text(stmt, 1, project) != CBM_STORE_OK ||
        site_bind_text(stmt, 2, file->rel_path) != CBM_STORE_OK ||
        site_bind_text(stmt, 3, file->source_hash) != CBM_STORE_OK ||
        sqlite3_bind_int(stmt, 4, file->counts_complete) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 5, file->analysis_limited) != SQLITE_OK) {
        return site_sql_error(sqlite3_db_handle(stmt), "call sites file bind");
    }
    return site_step_write(stmt);
}

static int site_write(call_site_writer_t *writer, const char *project, const char *path, int index,
                      const cbm_call_site_t *site) {
    sqlite3_stmt *stmt = writer->site;
    if (site_bind_text(stmt, 1, project) != CBM_STORE_OK ||
        site_bind_text(stmt, 2, path) != CBM_STORE_OK ||
        sqlite3_bind_int(stmt, 3, index) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 4, site->start_byte) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 5, site->end_byte) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 6, site->origin) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 7, site->is_reference) != SQLITE_OK ||
        site_bind_text(stmt, 8, site->leaf) != CBM_STORE_OK ||
        site_bind_text(stmt, 9, site->caller_qn) != CBM_STORE_OK ||
        site_bind_text(stmt, 10, site->category) != CBM_STORE_OK ||
        site_bind_text(stmt, 11, site->target_qn) != CBM_STORE_OK ||
        site_bind_text(stmt, 12, site->reason) != CBM_STORE_OK ||
        site_bind_text(stmt, 13, site->strategy) != CBM_STORE_OK) {
        return site_sql_error(sqlite3_db_handle(stmt), "call sites site bind");
    }
    return site_step_write(stmt);
}

static int site_delete(sqlite3 *db, const char *sql, const char *project, const char *path) {
    sqlite3_stmt *stmt = NULL;
    int result = CBM_STORE_ERR;
    if (site_prepare(db, sql, &stmt) == CBM_STORE_OK &&
        site_bind_text(stmt, 1, project) == CBM_STORE_OK &&
        (!path || site_bind_text(stmt, 2, path) == CBM_STORE_OK)) {
        result = site_step_write(stmt);
    }
    sqlite3_finalize(stmt);
    return result;
}

cbm_call_site_spool_t *cbm_call_site_spool_new(void) {
    call_site_error[0] = '\0';
    cbm_call_site_spool_t *spool = calloc(1, sizeof(*spool));
    if (!spool) {
        site_error("call site spool", "out of memory");
        return NULL;
    }
    /* An empty filename creates a private disk database deleted at close.
     * Bound its page cache rather than retaining every site's text in RAM. */
    if (sqlite3_open_v2("", &spool->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) !=
        SQLITE_OK) {
        site_sql_error(spool->db, "call site spool open");
        cbm_call_site_spool_free(spool);
        return NULL;
    }
    if (site_exec(spool->db, "PRAGMA temp_store=FILE; PRAGMA cache_size=-2048; PRAGMA mmap_size=0;",
                  "call site spool settings") != CBM_STORE_OK ||
        site_exec(spool->db, call_site_schema, "call site spool schema") != CBM_STORE_OK) {
        cbm_call_site_spool_free(spool);
        return NULL;
    }
    return spool;
}

void cbm_call_site_spool_free(cbm_call_site_spool_t *spool) {
    if (spool) {
        sqlite3_close(spool->db);
        free(spool);
    }
}

int cbm_call_site_spool_put_file(cbm_call_site_spool_t *spool, const cbm_call_site_file_t *file,
                                 const cbm_call_site_t *sites, int count) {
    call_site_error[0] = '\0';
    if (!spool || !file || !file->rel_path || !file->rel_path[0] || count < 0 ||
        (count > 0 && !sites)) {
        return site_error("call site spool", "invalid file or site array");
    }
    if (file->counts_complete && (!file->source_hash || !file->source_hash[0])) {
        return site_error("call site spool", "complete file needs a source hash");
    }
    for (int i = 0; i < count; i++) {
        if (sites[i].end_byte < sites[i].start_byte ||
            (file->counts_complete && sites[i].end_byte == sites[i].start_byte)) {
            return site_error("call site spool",
                              "invalid span or complete file has unlocated site");
        }
    }
    sqlite3 *db = spool->db;
    call_site_writer_t writer = {0};
    if (site_exec(db, "SAVEPOINT cbm_call_site_put", "call site spool savepoint") != CBM_STORE_OK) {
        return CBM_STORE_ERR;
    }
    if (site_delete(db, "DELETE FROM call_sites WHERE project=?1 AND rel_path=?2", "",
                    file->rel_path) != CBM_STORE_OK ||
        site_delete(db, "DELETE FROM call_site_files WHERE project=?1 AND rel_path=?2", "",
                    file->rel_path) != CBM_STORE_OK ||
        site_writer_open(db, &writer) != CBM_STORE_OK ||
        site_write_file(&writer, "", file) != CBM_STORE_OK) {
        goto fail;
    }
    for (int i = 0; i < count; i++) {
        if (site_write(&writer, "", file->rel_path, i, &sites[i]) != CBM_STORE_OK) {
            goto fail;
        }
    }
    site_writer_close(&writer);
    if (site_exec(db, "RELEASE cbm_call_site_put", "call site spool release") == CBM_STORE_OK) {
        return CBM_STORE_OK;
    }
fail:
    site_writer_close(&writer);
    (void)sqlite3_exec(db, "ROLLBACK TO cbm_call_site_put; RELEASE cbm_call_site_put", NULL, NULL,
                       NULL);
    return CBM_STORE_ERR;
}

static int site_baseline_open(const char *path, sqlite3 **baseline) {
    char api_path[4096];
    if (!cbm_path_for_file_api(path, api_path, sizeof(api_path))) {
        return site_error("call site baseline", "cannot normalize path");
    }
    if (sqlite3_open_v2(api_path, baseline, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        return site_sql_error(*baseline, "call site baseline open");
    }
    if (site_exec(*baseline, "BEGIN", "call site baseline snapshot") != CBM_STORE_OK) {
        return CBM_STORE_ERR;
    }
    sqlite3_stmt *stmt = NULL;
    int result = CBM_STORE_ERR;
    if (site_prepare(*baseline,
                     "SELECT count(*) FROM sqlite_schema WHERE type='table' "
                     "AND name IN ('call_site_files','call_sites')",
                     &stmt) == CBM_STORE_OK) {
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 2) {
            result = CBM_STORE_OK;
        } else if (rc == SQLITE_ROW) {
            site_error("call site baseline", "missing per-site tables; full rebuild required");
            result = CBM_STORE_NOT_FOUND;
        } else {
            site_sql_error(*baseline, "call site baseline schema");
        }
    }
    sqlite3_finalize(stmt);
    return result;
}

static int site_file_valid(sqlite3_stmt *file) {
    const char *path = (const char *)sqlite3_column_text(file, 0);
    const char *hash = (const char *)sqlite3_column_text(file, 1);
    int complete = sqlite3_column_int(file, 2);
    int limited = sqlite3_column_int(file, 3);
    if (!path || !path[0] || !hash || (complete != 0 && complete != 1) ||
        (limited != 0 && limited != 1) || (complete && !hash[0])) {
        return site_error("call site copy", "invalid file metadata");
    }
    return CBM_STORE_OK;
}

static int site_copy_file(call_site_writer_t *writer, sqlite3_stmt *file, sqlite3_stmt *sites,
                          const char *source_project, const char *target_project) {
    if (site_file_valid(file) != CBM_STORE_OK) {
        return CBM_STORE_ERR;
    }
    const char *path = (const char *)sqlite3_column_text(file, 0);
    cbm_call_site_file_t metadata = {
        .rel_path = path,
        .source_hash = (const char *)sqlite3_column_text(file, 1),
        .counts_complete = sqlite3_column_int(file, 2) != 0,
        .analysis_limited = sqlite3_column_int(file, 3) != 0,
    };
    if (site_write_file(writer, target_project, &metadata) != CBM_STORE_OK ||
        site_bind_text(sites, 1, source_project) != CBM_STORE_OK ||
        site_bind_text(sites, 2, path) != CBM_STORE_OK) {
        return CBM_STORE_ERR;
    }
    sqlite3_int64 expected_index = 0;
    int rc;
    while ((rc = sqlite3_step(sites)) == SQLITE_ROW) {
        sqlite3_int64 start = sqlite3_column_int64(sites, 1);
        sqlite3_int64 end = sqlite3_column_int64(sites, 2);
        int is_reference = sqlite3_column_int(sites, 4);
        if (sqlite3_column_int64(sites, 0) != expected_index || start < 0 || end < start ||
            end > UINT32_MAX || (metadata.counts_complete && start == end) ||
            (is_reference != 0 && is_reference != 1)) {
            return site_error("call site copy", "invalid site index, span or reference flag");
        }
        if (site_bind_text(writer->site, 1, target_project) != CBM_STORE_OK ||
            site_bind_text(writer->site, 2, path) != CBM_STORE_OK) {
            return CBM_STORE_ERR;
        }
        for (int i = 0; i < 11; i++) {
            if (sqlite3_bind_value(writer->site, i + 3, sqlite3_column_value(sites, i)) !=
                SQLITE_OK) {
                return site_sql_error(sqlite3_db_handle(writer->site), "call sites copy bind");
            }
        }
        if (site_step_write(writer->site) != CBM_STORE_OK) {
            return CBM_STORE_ERR;
        }
        expected_index++;
    }
    if (rc != SQLITE_DONE) {
        return site_sql_error(sqlite3_db_handle(sites), "call site source read");
    }
    (void)sqlite3_reset(sites);
    (void)sqlite3_clear_bindings(sites);
    return CBM_STORE_OK;
}

/* A fresh spool row supersedes the entire baseline file. Otherwise the file
 * must still exist and its two semantic manifest digests must agree. */
static int site_should_inherit(sqlite3_stmt *file, sqlite3_stmt *replaced, sqlite3_stmt *live,
                               const char *project) {
    const char *path = (const char *)sqlite3_column_text(file, 0);
    if (!path || !path[0]) {
        return site_error("call site inheritance", "missing baseline path");
    }
    if (replaced) {
        if (site_bind_text(replaced, 1, path) != CBM_STORE_OK) {
            return CBM_STORE_ERR;
        }
        int rc = sqlite3_step(replaced);
        (void)sqlite3_reset(replaced);
        (void)sqlite3_clear_bindings(replaced);
        if (rc == SQLITE_ROW) {
            return 0;
        }
        if (rc != SQLITE_DONE) {
            return site_sql_error(sqlite3_db_handle(replaced), "call site replacement lookup");
        }
    }
    if (site_bind_text(live, 1, project) != CBM_STORE_OK ||
        site_bind_text(live, 2, path) != CBM_STORE_OK) {
        return CBM_STORE_ERR;
    }
    int rc = sqlite3_step(live);
    if (rc == SQLITE_DONE) {
        (void)sqlite3_reset(live);
        (void)sqlite3_clear_bindings(live);
        return 0;
    }
    if (rc != SQLITE_ROW) {
        return site_sql_error(sqlite3_db_handle(live), "call site live manifest read");
    }
    const char *old_hash = (const char *)sqlite3_column_text(file, 4);
    const char *new_hash = (const char *)sqlite3_column_text(live, 0);
    bool same =
        old_hash && old_hash[0] && new_hash && new_hash[0] && strcmp(old_hash, new_hash) == 0;
    (void)sqlite3_reset(live);
    (void)sqlite3_clear_bindings(live);
    return same ? 1 : site_error("call site inheritance", "changed file lacks fresh site evidence");
}

static int site_copy_source(call_site_writer_t *writer, sqlite3 *source, const char *source_project,
                            const char *target_project, sqlite3 *spool, bool baseline) {
    sqlite3_stmt *files = NULL, *sites = NULL, *replaced = NULL, *live = NULL, *orphans = NULL;
    int result = CBM_STORE_ERR;
    const char *file_sql = baseline
                               ? "SELECT f.rel_path,f.source_hash,f.counts_complete,"
                                 "f.analysis_limited,h.sha256 FROM call_site_files f "
                                 "LEFT JOIN file_hashes h ON h.project=f.project "
                                 "AND h.rel_path=f.rel_path WHERE f.project=?1 ORDER BY f.rel_path"
                               : "SELECT rel_path,source_hash,counts_complete,analysis_limited "
                                 "FROM call_site_files WHERE project=?1 ORDER BY rel_path";
    if (site_prepare(source, file_sql, &files) != CBM_STORE_OK ||
        site_bind_text(files, 1, source_project) != CBM_STORE_OK ||
        site_prepare(source,
                     "SELECT site_index,start_byte,end_byte,origin,is_reference,leaf,caller_qn,"
                     "category,target_qn,reason,strategy FROM call_sites "
                     "WHERE project=?1 AND rel_path=?2 ORDER BY site_index",
                     &sites) != CBM_STORE_OK ||
        site_prepare(source,
                     "SELECT 1 FROM call_sites s LEFT JOIN call_site_files f "
                     "ON f.project=s.project AND f.rel_path=s.rel_path "
                     "WHERE s.project=?1 AND f.rel_path IS NULL LIMIT 1",
                     &orphans) != CBM_STORE_OK ||
        site_bind_text(orphans, 1, source_project) != CBM_STORE_OK) {
        goto done;
    }
    int rc = sqlite3_step(orphans);
    if (rc == SQLITE_ROW) {
        site_error("call site copy", "source has sites without file metadata");
        goto done;
    }
    if (rc != SQLITE_DONE) {
        site_sql_error(source, "call site orphan check");
        goto done;
    }
    if (baseline && (site_prepare(sqlite3_db_handle(writer->file),
                                  "SELECT sha256 FROM file_hashes WHERE project=?1 AND rel_path=?2",
                                  &live) != CBM_STORE_OK ||
                     (spool && site_prepare(spool,
                                            "SELECT 1 FROM call_site_files "
                                            "WHERE project='' AND rel_path=?1",
                                            &replaced) != CBM_STORE_OK))) {
        goto done;
    }
    while ((rc = sqlite3_step(files)) == SQLITE_ROW) {
        if (baseline) {
            int inherit = site_should_inherit(files, replaced, live, target_project);
            if (inherit < 0) {
                goto done;
            }
            if (!inherit) {
                continue;
            }
        }
        if (site_copy_file(writer, files, sites, source_project, target_project) != CBM_STORE_OK) {
            goto done;
        }
    }
    if (rc != SQLITE_DONE) {
        site_sql_error(source, "call site file read");
        goto done;
    }
    result = CBM_STORE_OK;
done:
    sqlite3_finalize(files);
    sqlite3_finalize(sites);
    sqlite3_finalize(replaced);
    sqlite3_finalize(live);
    sqlite3_finalize(orphans);
    return result;
}

int cbm_store_call_sites_publish(cbm_store_t *store, const char *project,
                                 cbm_call_site_spool_t *spool, const char *baseline_path) {
    call_site_error[0] = '\0';
    if (!store || !project || !project[0] || (baseline_path && !baseline_path[0])) {
        return site_error("call site publish", "invalid store, project or baseline path");
    }
    sqlite3 *db = cbm_store_get_db(store);
    sqlite3 *baseline = NULL;
    if (baseline_path) {
        int result = site_baseline_open(baseline_path, &baseline);
        if (result != CBM_STORE_OK) {
            sqlite3_close(baseline);
            return result;
        }
    }
    call_site_writer_t writer = {0};
    if (site_exec(db, "SAVEPOINT cbm_call_site_publish", "call site publish savepoint") !=
        CBM_STORE_OK) {
        sqlite3_close(baseline);
        return CBM_STORE_ERR;
    }
    if (site_exec(db, call_site_schema, "call site publish schema") != CBM_STORE_OK ||
        site_delete(db, "DELETE FROM call_sites WHERE project=?1", project, NULL) != CBM_STORE_OK ||
        site_delete(db, "DELETE FROM call_site_files WHERE project=?1", project, NULL) !=
            CBM_STORE_OK ||
        site_writer_open(db, &writer) != CBM_STORE_OK ||
        (baseline && site_copy_source(&writer, baseline, project, project, spool ? spool->db : NULL,
                                      true) != CBM_STORE_OK) ||
        (spool && site_copy_source(&writer, spool->db, "", project, NULL, false) != CBM_STORE_OK)) {
        goto fail;
    }
    site_writer_close(&writer);
    /* Release a same-file baseline reader before committing the writer. */
    sqlite3_close(baseline);
    baseline = NULL;
    if (site_exec(db, "RELEASE cbm_call_site_publish", "call site publish release") ==
        CBM_STORE_OK) {
        return CBM_STORE_OK;
    }
fail:
    site_writer_close(&writer);
    sqlite3_close(baseline);
    (void)sqlite3_exec(db, "ROLLBACK TO cbm_call_site_publish; RELEASE cbm_call_site_publish", NULL,
                       NULL, NULL);
    return CBM_STORE_ERR;
}
