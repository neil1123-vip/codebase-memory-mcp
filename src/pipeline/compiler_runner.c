#include "pipeline/compiler_runner.h"

#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/platform.h"
#include "foundation/profile.h"
#include "foundation/sha256.h"
#include "foundation/subprocess.h"
#include "helpers.h"
#include "lang_specs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RUN_PATH_MAX 4096
#define RUN_MAX_FILES 50000
#define RUN_MAX_SOURCE (256U * 1024U * 1024U)
#define RUN_MAX_FILE (8U * 1024U * 1024U)
#define RUN_MAX_MANIFEST (16U * 1024U * 1024U)
#define RUN_MAX_OUTPUT (32U * 1024U * 1024U)
#define RUN_MAX_LOG (1024U * 1024U)
#define RUN_MAX_BROWSER_DOCUMENTS 256
#define RUN_MAX_BROWSER_SCRIPTS 128
#define RUN_MAX_BROWSER_SCRIPT_SRC 2048
#define RUN_MAX_BROWSER_SOURCE (16U * 1024U * 1024U)
#define RUN_MAX_BROWSER_MANIFEST (2U * 1024U * 1024U)

typedef struct {
    const char *status;
    char reason[256];
    size_t files;
} run_status_t;

typedef struct {
    char directory[RUN_PATH_MAX];
    unsigned references;
} run_chunk_storage_t;

struct CBMCompilerRun {
    CBMCompilerFacts *facts[2];
    run_status_t languages[2];
    char *status;
    run_chunk_storage_t *chunk_storage[2];
};

#ifdef CBM_ENABLE_TEST_SEAMS
static atomic_int test_timeout_ms;

void cbm_compiler_runner_test_timeout_ms(int timeout_ms) {
    atomic_store_explicit(&test_timeout_ms, timeout_ms, memory_order_relaxed);
}
#endif

static int language_group(CBMLanguage language) {
    if (language == CBM_LANG_GO) {
        return 0;
    }
    if (language == CBM_LANG_JAVASCRIPT || language == CBM_LANG_TYPESCRIPT ||
        language == CBM_LANG_TSX) {
        return 1;
    }
    return -1;
}

static int manifest_group(const cbm_file_info_t *file, bool cgo_headers) {
    if (cgo_headers) {
        const char *extension = strrchr(file->rel_path, '.');
        if (extension && (file->language == CBM_LANG_C || file->language == CBM_LANG_CPP) &&
            strcmp(extension, ".h") == 0)
            return 0;
#ifdef __APPLE__
        if (extension && file->language == CBM_LANG_OBJC && strcmp(extension, ".m") == 0)
            return 0;
#endif
    }
    return language_group(file->language);
}

static bool cancelled(const atomic_int *cancel) {
    return cancel && atomic_load_explicit(cancel, memory_order_relaxed) != 0;
}

static void reject(run_status_t *status, const char *reason) {
    status->status = "degraded";
    snprintf(status->reason, sizeof(status->reason), "%s", reason);
}

bool cbm_compiler_runner_enabled(void) {
    char go[RUN_PATH_MAX], ts[RUN_PATH_MAX];
    const char *g = cbm_safe_getenv("CBM_GO_FACTS_HELPER", go, sizeof(go), "");
    const char *t = cbm_safe_getenv("CBM_TS_FACTS_HELPER", ts, sizeof(ts), "");
    return !g || !t || g[0] || t[0];
}

static bool canonical_relative(const char *path) {
    if (!path || !path[0] || path[0] == '/' || strchr(path, '\\') || strchr(path, ':')) {
        return false;
    }
    for (const char *p = path; *p;) {
        const char *end = strchr(p, '/');
        size_t length = end ? (size_t)(end - p) : strlen(p);
        if (!length || (length == 1 && p[0] == '.') ||
            (length == 2 && p[0] == '.' && p[1] == '.')) {
            return false;
        }
        if (length >= 12) {
            static const char prefix[] = ".tmp-rebase-";
            bool temporary = true;
            for (size_t i = 0; i < sizeof(prefix) - 1; i++) {
                char c = p[i];
                if (c >= 'A' && c <= 'Z') {
                    c = (char)(c + ('a' - 'A'));
                }
                temporary = temporary && c == prefix[i];
            }
            if (temporary) {
                return false;
            }
        }
        if (!end) {
            return true;
        }
        p = end + 1;
        if (!*p) {
            return false;
        }
    }
    return false;
}

static bool join_path(char out[RUN_PATH_MAX], const char *root, const char *relative) {
    int n = snprintf(out, RUN_PATH_MAX, "%s%s%s", root,
                     root[0] && root[strlen(root) - 1] == '/' ? "" : "/", relative);
    return n > 0 && n < RUN_PATH_MAX;
}

static bool source_snapshot(const char *root, const char *relative, char hash[65], uint64_t *length,
                            uint64_t max_size, char **contents, const atomic_int *cancel) {
    char path[RUN_PATH_MAX], real[RUN_PATH_MAX];
    cbm_path_info_t info;
    if (!canonical_relative(relative) || !join_path(path, root, relative) ||
        cbm_path_info_utf8(path, &info) != CBM_PATH_INFO_OK || !info.is_regular ||
        info.is_symlink || info.size < 0 || (uint64_t)info.size > max_size ||
        !cbm_canonical_path(path, real, sizeof(real))) {
        return false;
    }
    cbm_normalize_path_sep(real);
    if (strcmp(path, real) != 0) {
        return false;
    }
    FILE *file = cbm_fopen(path, "rb");
    if (!file) {
        return false;
    }
    char *source = contents ? malloc((size_t)info.size + 1U) : NULL;
    if (contents && !source) {
        (void)fclose(file);
        return false;
    }
    cbm_sha256_ctx digest;
    cbm_sha256_init(&digest);
    unsigned char buffer[65536], bytes[32];
    size_t got;
    *length = 0;
    bool ok = true;
    while ((got = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (*length + got > (uint64_t)info.size || cancelled(cancel)) {
            ok = false;
            break;
        }
        if (source)
            memcpy(source + *length, buffer, got);
        *length += got;
        cbm_sha256_update(&digest, buffer, got);
    }
    ok = ok && !ferror(file) && *length == (uint64_t)info.size;
    if (fclose(file) != 0) {
        ok = false;
    }
    if (!ok) {
        free(source);
        return false;
    }
    cbm_sha256_final(&digest, bytes);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(bytes); i++) {
        hash[2 * i] = hex[bytes[i] >> 4];
        hash[2 * i + 1] = hex[bytes[i] & 15];
    }
    hash[64] = '\0';
    if (contents) {
        source[*length] = '\0';
        *contents = source;
    }
    return true;
}

static bool source_hash(const char *root, const char *relative, char hash[65], uint64_t *length,
                        const atomic_int *cancel) {
    return source_snapshot(root, relative, hash, length, RUN_MAX_FILE, NULL, cancel);
}

typedef struct {
    uint32_t start, end, value_start, value_end;
} browser_script_t;

typedef struct {
    const char *path;
    char sha256[65];
} browser_document_t;

static bool html_kind(TSNode node, const char *kind) {
    return !ts_node_is_null(node) && strcmp(ts_node_type(node), kind) == 0;
}

static char html_ascii_lower(char c) {
    return c >= 'A' && c <= 'Z' ? (char)(c + ('a' - 'A')) : c;
}

static bool html_name(const char *source, TSNode node, const char *word) {
    if (ts_node_is_null(node))
        return false;
    uint32_t start = ts_node_start_byte(node), end = ts_node_end_byte(node);
    if (end - start != strlen(word))
        return false;
    for (uint32_t i = start; i < end; i++)
        if (html_ascii_lower(source[i]) != word[i - start])
            return false;
    return true;
}

static bool html_script_context(const char *source, TSNode script) {
    for (TSNode node = ts_node_parent(script); !ts_node_is_null(node); node = ts_node_parent(node)) {
        if (html_kind(node, "document"))
            return true;
        TSNode open = ts_node_named_child(node, 0);
        TSNode name = ts_node_named_child(open, 0);
        if (!html_kind(open, "start_tag") || !html_kind(name, "tag_name") ||
            (!html_name(source, name, "html") && !html_name(source, name, "head") &&
             !html_name(source, name, "body")))
            return false;
    }
    return false;
}

static bool html_script_src(const char *s, size_t n) {
    if (n <= 3 || n > RUN_MAX_BROWSER_SCRIPT_SRC || memcmp(s + n - 3, ".js", 3) != 0)
        return false;
    if (s[0] == '.' && s[1] == '/') {
        s += 2;
        n -= 2;
    }
    size_t start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || s[i] == '/') {
            size_t segment = i - start;
            if (!segment || (segment <= 2 && s[start] == '.' && s[i - 1] == '.'))
                return false;
            start = i + 1;
        } else {
            char c = html_ascii_lower(s[i]);
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                  c == '-' || c == '_' || c == '.'))
                return false;
        }
    }
    return true;
}

static bool html_script(const char *source, TSNode node, browser_script_t *script) {
    TSNode open = ts_node_named_child(node, 0), close = ts_node_named_child(node, 2);
    TSNode raw = ts_node_named_child(node, 1);
    TSNode attribute = ts_node_named_child(open, 1);
    if (!html_script_context(source, node) ||
        !html_kind(open, "start_tag") || !html_kind(raw, "raw_text") ||
        !html_kind(close, "end_tag") || ts_node_named_child_count(node) != 3 ||
        ts_node_named_child_count(open) != 2 ||
        ts_node_end_byte(open) != ts_node_start_byte(close) ||
        !html_kind(attribute, "attribute") || ts_node_named_child_count(attribute) != 2 ||
        !html_name(source, ts_node_named_child(attribute, 0), "src"))
        return false;
    TSNode wrapper = ts_node_named_child(attribute, 1);
    TSNode value = ts_node_named_child(wrapper, 0);
    if (!html_kind(wrapper, "quoted_attribute_value") || !html_kind(value, "attribute_value"))
        return false;
    *script = (browser_script_t){ts_node_start_byte(node), ts_node_end_byte(node),
                                ts_node_start_byte(value), ts_node_end_byte(value)};
    return html_script_src(source + script->value_start, script->value_end - script->value_start);
}

static bool html_tag_is_ambiguous(const char *source, TSNode tag) {
    TSNode name = ts_node_named_child(tag, 0);
    static const char *const excluded[] = {
        "base", "iframe", "object", "embed", "applet", "frame", "frameset",
        "portal", "noscript", "noembed", "noframes", "xmp", "plaintext", "textarea",
        "foreignobject", "math", "select",
    };
    if (!html_kind(name, "tag_name"))
        return true;
    for (size_t i = 0; i < sizeof(excluded) / sizeof(excluded[0]); i++)
        if (html_name(source, name, excluded[i]))
            return true;
    /* A script-free empty placeholder does not create a separate script scope. */
    if (html_name(source, name, "template")) {
        TSNode close = ts_node_named_child(ts_node_parent(tag), 1);
        if (!html_kind(close, "end_tag") || ts_node_end_byte(tag) != ts_node_start_byte(close))
            return true;
    }
    return false;
}

static bool html_parse_cancel(TSParseState *state) {
    return cancelled(state->payload);
}

static size_t browser_scripts(TSParser *parser, const char *source, uint32_t length,
                              browser_script_t out[RUN_MAX_BROWSER_SCRIPTS],
                              const atomic_int *cancel) {
    if (memchr(source, '\0', length) || cancelled(cancel))
        return 0;
    TSParseOptions parse = {.payload = (void *)cancel, .progress_callback = html_parse_cancel};
    TSTree *tree = cbm_parse_source(parser, source, length, parse);
    ts_parser_reset(parser);
    if (!tree)
        return 0;
    TSNode root = ts_tree_root_node(tree);
    size_t count = 0;
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    if (ts_node_has_error(root))
        goto reject;
    for (;;) {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        if (cancelled(cancel))
            goto reject;
        if ((html_kind(node, "start_tag") || html_kind(node, "self_closing_tag")) &&
            html_tag_is_ambiguous(source, node))
            goto reject;
        if (html_kind(node, "attribute")) {
            TSNode name = ts_node_named_child(node, 0);
            if (!html_kind(name, "attribute_name"))
                goto reject;
            uint32_t at = ts_node_start_byte(name), end = ts_node_end_byte(name);
            if ((end - at > 2 && html_ascii_lower(source[at]) == 'o' &&
                 html_ascii_lower(source[at + 1]) == 'n') ||
                html_name(source, name, "http-equiv") || html_name(source, name, "srcdoc"))
                goto reject;
        }
        if (html_kind(node, "script_element")) {
            if (count >= RUN_MAX_BROWSER_SCRIPTS || !html_script(source, node, &out[count]))
                goto reject;
            count++;
        }
        if (ts_tree_cursor_goto_first_child(&cursor))
            continue;
        while (!ts_tree_cursor_goto_next_sibling(&cursor))
            if (!ts_tree_cursor_goto_parent(&cursor))
                goto done;
    }
reject:
    count = 0;
done:
    ts_tree_cursor_delete(&cursor);
    ts_tree_delete(tree);
    return count;
}

static size_t write_browser_documents(yyjson_mut_doc *doc, yyjson_mut_val *manifest,
                                      const char *root, const cbm_file_info_t *files, int file_count,
                                      uint64_t source_remaining, const atomic_int *cancel,
                                      browser_document_t documents[RUN_MAX_BROWSER_DOCUMENTS]) {
    TSParser *parser = ts_parser_new();
    if (!parser)
        return 0;
    if (!ts_parser_set_language(parser, cbm_ts_language(CBM_LANG_HTML))) {
        ts_parser_delete(parser);
        return 0;
    }
    yyjson_mut_val *list = yyjson_mut_arr(doc);
    uint64_t remaining = source_remaining < RUN_MAX_BROWSER_SOURCE
                             ? source_remaining : RUN_MAX_BROWSER_SOURCE;
    size_t count = 0, wire_bytes = 0;
    bool ok = list != NULL;
    for (int i = 0; ok && i < file_count && count < RUN_MAX_BROWSER_DOCUMENTS &&
                    !cancelled(cancel); i++) {
        const char *path = files[i].rel_path;
        if (files[i].language != CBM_LANG_HTML || !path)
            continue;
        size_t n = strlen(path);
        if (n <= 5 || strcmp(path + n - 5, ".html") != 0)
            continue;
        uint64_t length = 0, limit = remaining < RUN_MAX_FILE ? remaining : RUN_MAX_FILE;
        char *source = NULL;
        if (!source_snapshot(root, path, documents[count].sha256, &length, limit, &source, cancel))
            continue;
        remaining -= length;
        browser_script_t scripts[RUN_MAX_BROWSER_SCRIPTS];
        size_t script_count = browser_scripts(parser, source, (uint32_t)length, scripts, cancel);
        if (script_count) {
            size_t cost = 128 + 6 * n;
            for (size_t s = 0; s < script_count; s++)
                cost += 64 + scripts[s].value_end - scripts[s].value_start;
            if (wire_bytes + cost > RUN_MAX_BROWSER_MANIFEST) {
                free(source);
                break;
            }
            yyjson_mut_val *page = yyjson_mut_obj(doc), *rows = yyjson_mut_arr(doc);
            ok = page && rows && yyjson_mut_obj_add_str(doc, page, "path", path) &&
                 yyjson_mut_obj_add_str(doc, page, "sha256", documents[count].sha256) &&
                 yyjson_mut_obj_add_val(doc, page, "scripts", rows);
            for (size_t s = 0; ok && s < script_count; s++) {
                browser_script_t span = scripts[s];
                yyjson_mut_val *row = yyjson_mut_obj(doc);
                ok = row && yyjson_mut_obj_add_strncpy(doc, row, "src", source + span.value_start,
                                                       span.value_end - span.value_start) &&
                     yyjson_mut_obj_add_uint(doc, row, "start", span.start) &&
                     yyjson_mut_obj_add_uint(doc, row, "end", span.end) &&
                     yyjson_mut_arr_add_val(rows, row);
            }
            ok = ok && yyjson_mut_arr_add_val(list, page);
            if (ok) {
                documents[count++].path = path;
                wire_bytes += cost;
            }
        }
        free(source);
    }
    ts_parser_delete(parser);
    return ok && count && yyjson_mut_obj_add_val(doc, manifest, "browser_documents", list)
               ? count : 0;
}

static int compare_input(const void *a, const void *b) {
    return strcmp(((const CBMCompilerInput *)a)->path, ((const CBMCompilerInput *)b)->path);
}

static bool write_manifest(const char *path, const CBMCompilerInput *inputs, size_t count,
                           const char *project_root, const cbm_file_info_t *discovery, int file_count,
                           uint64_t source_remaining, const atomic_int *cancel,
                           browser_document_t *documents, size_t *document_count) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        return false;
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc), *files = yyjson_mut_arr(doc);
    bool ok = root && files && yyjson_mut_obj_add_val(doc, root, "files", files);
    yyjson_mut_doc_set_root(doc, root);
    size_t path_bytes = 0;
    for (size_t i = 0; ok && i < count; i++) {
        path_bytes += strlen(inputs[i].path);
        if (path_bytes > RUN_MAX_MANIFEST) {
            ok = false;
            break;
        }
        yyjson_mut_val *file = yyjson_mut_obj(doc);
        ok = file && yyjson_mut_obj_add_str(doc, file, "path", inputs[i].path) &&
             yyjson_mut_obj_add_str(doc, file, "sha256", inputs[i].sha256) &&
             yyjson_mut_obj_add_uint(doc, file, "byte_length", inputs[i].byte_length) &&
             yyjson_mut_arr_add_val(files, file);
    }
    if (ok && documents)
        *document_count = write_browser_documents(doc, root, project_root, discovery, file_count,
                                                  source_remaining, cancel, documents);
    size_t length = 0;
    char *json = ok ? yyjson_mut_write(doc, 0, &length) : NULL;
    if (*document_count && (!json || length > RUN_MAX_MANIFEST)) {
        free(json);
        (void)yyjson_mut_obj_remove_key(root, "browser_documents");
        *document_count = 0;
        json = yyjson_mut_write(doc, 0, &length);
    }
    ok = json && length <= RUN_MAX_MANIFEST;
    FILE *file = ok ? cbm_fopen(path, "wb") : NULL;
    if (!file) {
        ok = false;
    } else {
        ok = fwrite(json, 1, length, file) == length;
        if (fclose(file) != 0) {
            ok = false;
        }
    }
    free(json);
    yyjson_mut_doc_free(doc);
    return ok;
}

static uint64_t monotonic_ms(void) {
    struct timespec now;
    if (cbm_clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static bool capture_within_budget(const char *path, uint64_t limit) {
    cbm_path_info_t info;
    int rc = cbm_path_info_utf8(path, &info);
    return rc == CBM_PATH_INFO_ABSENT ||
           (rc == CBM_PATH_INFO_OK && info.is_regular && !info.is_symlink && info.size >= 0 &&
            (uint64_t)info.size <= limit);
}

static bool execute(const char *const *argv, const char *output, const char *log, int budget_ms,
                    atomic_int *cancel, run_status_t *status, bool *quiesced) {
#ifdef CBM_ENABLE_TEST_SEAMS
    int test_budget = atomic_load_explicit(&test_timeout_ms, memory_order_relaxed);
    if (test_budget > 0 && test_budget < budget_ms) {
        budget_ms = test_budget;
    }
#endif
    cbm_proc_opts_t opts = {
        .bin = argv[0],
        .argv = argv,
        .stdout_file = output,
        .log_file = log,
        .quiet_timeout_ms = budget_ms,
        .cancel_grace_ms = 100,
    };
    cbm_subprocess_t *process = NULL;
    *quiesced = true;
    if (cancelled(cancel)) {
        reject(status, "cancelled");
        return false;
    }
    uint64_t start = monotonic_ms();
    if (!start || cbm_subprocess_spawn(&opts, &process) != 0) {
        reject(status, start ? "helper_spawn_failed" : "clock_unavailable");
        return false;
    }
    cbm_proc_result_t result = {0};
    const char *failure = NULL;
    for (;;) {
        cbm_proc_poll_t poll = cbm_subprocess_poll(process, &result);
        if (poll == CBM_PROC_POLL_TERMINAL) {
            break;
        }
        uint64_t now = monotonic_ms();
        if (!failure) {
            if (poll == CBM_PROC_POLL_ERROR) {
                failure = "helper_supervision_failed";
            } else if (cancelled(cancel)) {
                failure = "cancelled";
            } else if (!now || now - start >= (uint64_t)budget_ms) {
                failure = "helper_timeout";
            } else if (!capture_within_budget(output, RUN_MAX_OUTPUT) ||
                       !capture_within_budget(log, RUN_MAX_LOG)) {
                failure = "helper_output_budget";
            }
        }
        if (failure) {
            (void)cbm_subprocess_request_cancel(process);
        }
        cbm_usleep(10000);
    }
    *quiesced = result.tree_quiesced;
    cbm_subprocess_destroy(process);
    if (failure || result.outcome != CBM_PROC_CLEAN || result.exit_code != 0 ||
        !result.tree_quiesced || result.supervision_failed || result.cancellation_requested ||
        cancelled(cancel)) {
        reject(status, failure             ? failure
                       : cancelled(cancel) ? "cancelled"
                       : !result.tree_quiesced || result.supervision_failed
                           ? "helper_supervision_failed"
                       : result.outcome == CBM_PROC_HANG ? "helper_timeout"
                                                         : cbm_proc_outcome_str(result.outcome));
        return false;
    }
    if (!capture_within_budget(output, RUN_MAX_OUTPUT) ||
        !capture_within_budget(log, RUN_MAX_LOG)) {
        reject(status, "helper_output_budget");
        return false;
    }
    return true;
}

static char *read_output(const char *path, size_t *length) {
    cbm_path_info_t info;
    if (cbm_path_info_utf8(path, &info) != CBM_PATH_INFO_OK || !info.is_regular ||
        info.is_symlink || info.size <= 0 || (uint64_t)info.size > RUN_MAX_OUTPUT) {
        return NULL;
    }
    FILE *file = cbm_fopen(path, "rb");
    char *json = file ? malloc((size_t)info.size + 1) : NULL;
    bool ok = json && fread(json, 1, (size_t)info.size, file) == (size_t)info.size &&
              fgetc(file) == EOF && !ferror(file);
    if (file && fclose(file) != 0) {
        ok = false;
    }
    if (!ok) {
        free(json);
        return NULL;
    }
    *length = (size_t)info.size;
    json[*length] = '\0';
    return json;
}

static bool remove_owned(const char *path) {
    return cbm_unlink(path) == 0 || errno == ENOENT;
}

static bool remove_chunk_directory(const char *path) {
    cbm_dir_t *directory = cbm_opendir(path);
    if (!directory)
        return errno == ENOENT;
    bool ok = true;
    cbm_dirent_t *entry;
    while ((entry = cbm_readdir(directory))) {
        if (!strcmp(entry->name, ".") || !strcmp(entry->name, ".."))
            continue;
        char joined[RUN_PATH_MAX];
        cbm_path_info_t info;
        if (strchr(entry->name, '/') || strchr(entry->name, '\\') ||
            strchr(entry->name, ':') || !join_path(joined, path, entry->name) ||
            cbm_path_info_utf8(joined, &info) != CBM_PATH_INFO_OK ||
            (!info.is_regular && !info.is_symlink) || !remove_owned(joined))
            ok = false;
    }
    ok = !cbm_dir_failed(directory) && ok;
    cbm_closedir(directory);
    return cbm_rmdir(path) == 0 && ok;
}

static void release_chunk_storage(run_chunk_storage_t *storage) {
    if (storage && --storage->references == 0) {
        char chunks[RUN_PATH_MAX];
        if (join_path(chunks, storage->directory, "chunks") && remove_chunk_directory(chunks))
            (void)cbm_rmdir(storage->directory);
        free(storage);
    }
}

static CBMCompilerFacts *run_language(const char *root, const cbm_file_info_t *files,
                                      int file_count, int group, const char *helper,
                                      const char *node, const char *typescript,
                                      const cbm_gbuf_t *gbuf, atomic_int *cancel, bool cgo_headers,
                                      run_status_t *status, run_chunk_storage_t **storage) {
    CBMCompilerFacts *facts = NULL;
    browser_document_t *documents = NULL;
    size_t document_count = 0;
    CBMCompilerInput *inputs = calloc(status->files, sizeof(*inputs));
    char (*hashes)[65] = calloc(status->files, sizeof(*hashes));
    if (!inputs || !hashes) {
        free(inputs);
        free(hashes);
        reject(status, "allocation_failed");
        return NULL;
    }
    size_t count = 0;
    uint64_t total = 0;
    for (int i = 0; i < file_count; i++) {
        if (manifest_group(&files[i], cgo_headers) != group) {
            continue;
        }
        uint64_t length = 0;
        if (cancelled(cancel) ||
            !source_hash(root, files[i].rel_path, hashes[count], &length, cancel)) {
            reject(status, cancelled(cancel) ? "cancelled" : "manifest_source_invalid");
            goto done;
        }
        total += length;
        if (total > RUN_MAX_SOURCE) {
            reject(status, "source_budget");
            goto done;
        }
        inputs[count] = (CBMCompilerInput){files[i].rel_path, hashes[count], length};
        count++;
    }
    qsort(inputs, count, sizeof(*inputs), compare_input);
    for (size_t i = 1; i < count; i++) {
        if (strcmp(inputs[i - 1].path, inputs[i].path) == 0) {
            reject(status, "manifest_duplicate_path");
            goto done;
        }
    }
    char temporary[RUN_PATH_MAX], manifest[RUN_PATH_MAX], output[RUN_PATH_MAX], log[RUN_PATH_MAX];
    char temporary_base[RUN_PATH_MAX], canonical_temporary_base[RUN_PATH_MAX];
#ifdef _WIN32
    const char *base = cbm_native_getenv("TEMP", temporary_base, sizeof(temporary_base), "");
    if (base && !base[0])
        base = cbm_native_getenv("TMP", temporary_base, sizeof(temporary_base), "");
#else
    const char *base = cbm_native_getenv("TMPDIR", temporary_base, sizeof(temporary_base), "/tmp");
#endif
    /* Helper transport must not introduce a new input into project include scans. */
    if (!base || !base[0] ||
        !cbm_canonical_path(base, canonical_temporary_base, sizeof(canonical_temporary_base)) ||
        !join_path(temporary, canonical_temporary_base, ".tmp-compiler-XXXXXX") ||
        !cbm_mkdtemp(temporary)) {
        reject(status, "temporary_directory_failed");
        goto done;
    }
    bool paths_ok = join_path(manifest, temporary, "manifest.json") &&
                    join_path(output, temporary, "facts.json") &&
                    join_path(log, temporary, "stderr.log");
    bool quiesced = true;
    bool private_chunks = false;
    if (!paths_ok) {
        reject(status, "temporary_path_too_long");
        (void)cbm_rmdir(temporary);
        goto done;
    }
    const char *argv[24];
    size_t n = 0;
    argv[n++] = group == 0 ? helper : node;
    if (group == 1) {
        argv[n++] = helper;
    }
    argv[n++] = "--root";
    argv[n++] = root;
    argv[n++] = "--manifest";
    argv[n++] = manifest;
    if (group == 1) {
        argv[n++] = "--max-files";
        argv[n++] = "50000";
        if (typescript && typescript[0]) {
            argv[n++] = "--typescript";
            argv[n++] = typescript;
        }
    }
    char cache[RUN_PATH_MAX] = {0}, profile_buffer[64];
    const char *profile = cbm_safe_getenv(
        group == 0 ? "CBM_GO_FACTS_PROFILE" : "CBM_TS_FACTS_PROFILE",
        profile_buffer, sizeof(profile_buffer), "");
    bool compact_profile = group == 0 && profile && strcmp(profile, "chunk_index_v2") == 0;
    bool ts_proof_profile = group == 1 && profile && strcmp(profile, "proof_index_v1") == 0;
    /* The proof profile verifies browser dependencies after writing the ledger. */
    argv[n++] = "--budget-ms";
    argv[n++] = group == 0 ? "60000" : ts_proof_profile ? "40000" : "30000";
    bool ts_chunk_profile = ts_proof_profile ||
                            (group == 1 && profile && strcmp(profile, "file_index_v1") == 0);
    bool chunk_profile = compact_profile || ts_chunk_profile ||
                         (group == 0 && profile && strcmp(profile, "chunk_index_v1") == 0);
    if (!profile || (profile[0] && !chunk_profile)) {
        reject(status, "helper_profile_invalid");
        goto cleanup;
    }
    if (ts_proof_profile)
        documents = calloc(RUN_MAX_BROWSER_DOCUMENTS, sizeof(*documents));
    if (!write_manifest(manifest, inputs, count, root, files, file_count, RUN_MAX_SOURCE - total,
                        cancel, documents, &document_count)) {
        reject(status, "manifest_write_or_budget");
        goto cleanup;
    }
    const char *cache_base = cbm_resolve_cache_dir();
    bool cache_available = chunk_profile
        ? join_path(cache, temporary, "chunks") && cbm_mkdir_p(cache, 0700)
        : cache_base && join_path(cache, cache_base, "compiler-facts");
    private_chunks = chunk_profile && cache_available;
    if (chunk_profile && !cache_available) {
        reject(status, "chunk_directory_failed");
        goto cleanup;
    }
    if (cache_available) {
        argv[n++] = ts_chunk_profile ? "--chunk-index-dir" : "--cache";
        argv[n++] = cache;
        if (group == 0) {
            argv[n++] = compact_profile ? "--chunk-index-v2" :
                        chunk_profile ? "--chunk-index" : "--package-index";
        }
    }
    if (ts_proof_profile) {
        argv[n++] = "--profile";
        argv[n++] = "proof_index_v1";
    }
    argv[n] = NULL;
    if (!execute(argv, output, log, group == 0 ? 65000 : ts_proof_profile ? 45000 : 35000,
                 cancel, status, &quiesced)) {
        goto cleanup;
    }
    for (size_t i = 0; i < count; i++) {
        char hash[65];
        uint64_t length;
        if (cancelled(cancel) || !source_hash(root, inputs[i].path, hash, &length, cancel) ||
            length != inputs[i].byte_length || strcmp(hash, inputs[i].sha256) != 0) {
            reject(status, cancelled(cancel) ? "cancelled" : "manifest_source_changed");
            goto cleanup;
        }
    }
    for (size_t i = 0; i < document_count; i++) {
        char hash[65];
        uint64_t length;
        if (cancelled(cancel) || !source_hash(root, documents[i].path, hash, &length, cancel) ||
            strcmp(hash, documents[i].sha256) != 0) {
            reject(status, cancelled(cancel) ? "cancelled" : "manifest_source_changed");
            goto cleanup;
        }
    }
    size_t json_length = 0;
    char *json = read_output(output, &json_length);
    if (!json) {
        reject(status, "helper_output_invalid");
        goto cleanup;
    }
    char parse_error[256] = {0};
    yyjson_doc *metadata = yyjson_read(json, json_length, 0);
    yyjson_val *envelope = yyjson_doc_get_root(metadata);
    uint64_t schema = yyjson_get_uint(yyjson_obj_get(envelope, "schema"));
    const char *kind = yyjson_get_str(yyjson_obj_get(envelope, "kind"));
    const char *actual_profile = yyjson_get_str(yyjson_obj_get(envelope, "profile"));
    bool ts_profile_matches = group != 1 || !ts_chunk_profile ||
        (schema == 3 && kind && strcmp(kind, "typescript_chunk_index") == 0 &&
         actual_profile && strcmp(actual_profile, profile) == 0) ||
        (!ts_proof_profile && schema == 2 && kind &&
         strcmp(kind, "typescript_local_target_index") == 0);
    bool package_index = group == 0 && schema == 2;
    bool ts_partial_index = group == 1 && schema == 2 && kind &&
                            strcmp(kind, "typescript_local_target_index") == 0;
    bool chunk_index = group == 0 ? schema == 3 || schema == 4 : schema == 3;
    bool requested_chunk = chunk_profile && schema == (compact_profile ? 4 : 3);
    yyjson_val *errors = yyjson_obj_get(envelope, "errors");
    bool go_timed_out = group == 0 && schema >= 1 && schema <= 4 &&
                        yyjson_is_false(yyjson_obj_get(envelope, "complete")) &&
                        yyjson_arr_size(errors) == 1 &&
                        yyjson_equals_str(yyjson_arr_get_first(errors), "context deadline exceeded");
    yyjson_val *message = yyjson_obj_get(envelope, "message");
    bool ts_budget_exceeded = group == 1 && schema == 1 &&
                              yyjson_is_false(yyjson_obj_get(envelope, "complete")) &&
                              yyjson_equals_str(yyjson_obj_get(envelope, "language"), "typescript") &&
                              yyjson_equals_str(yyjson_obj_get(envelope, "status"), "budget_exceeded");
    bool ts_timed_out = ts_budget_exceeded &&
                        (yyjson_equals_str(message, "Worker exceeded its time budget") ||
                         yyjson_equals_str(message, "Project analysis exceeded its time budget"));
    bool ts_type_budget = ts_budget_exceeded && yyjson_equals_str(message, "Type budget exceeded");
    bool ts_resource_limit = group == 1 && schema == 1 &&
                             yyjson_is_false(yyjson_obj_get(envelope, "complete")) &&
                             yyjson_equals_str(yyjson_obj_get(envelope, "language"), "typescript") &&
                             yyjson_equals_str(yyjson_obj_get(envelope, "status"), "resource_limit");
    yyjson_doc_free(metadata);
    if (ts_timed_out) {
        snprintf(parse_error, sizeof(parse_error), "helper_timeout");
    } else if (ts_budget_exceeded) {
        snprintf(parse_error, sizeof(parse_error), "%s",
                 ts_type_budget ? "helper_type_budget" : "helper_budget_exceeded");
    } else if (ts_resource_limit) {
        snprintf(parse_error, sizeof(parse_error), "helper_resource_limit");
    } else if (!ts_profile_matches) {
        snprintf(parse_error, sizeof(parse_error), "requested compiler chunk profile missing");
    } else if (chunk_profile && !requested_chunk && !(ts_chunk_profile && ts_partial_index)) {
        snprintf(parse_error, sizeof(parse_error), "requested compiler chunk profile missing");
    } else if ((package_index || chunk_index) && !cache_available) {
        snprintf(parse_error, sizeof(parse_error), "package index cache unavailable");
    } else if (chunk_index && !chunk_profile) {
        snprintf(parse_error, sizeof(parse_error), "unrequested compiler chunk profile");
    } else if (go_timed_out) {
        snprintf(parse_error, sizeof(parse_error), "helper_timeout");
    } else if (chunk_index && ts_chunk_profile) {
        facts = cbm_compiler_facts_parse_ts_chunk_index(
            json, json_length, root, inputs, count, gbuf, cache, parse_error, sizeof(parse_error));
    } else if (chunk_index && compact_profile) {
        facts = cbm_compiler_facts_parse_compact_chunk_index(json, json_length, root, inputs, count,
                                                             gbuf, cache, parse_error,
                                                             sizeof(parse_error));
    } else if (chunk_index && chunk_profile) {
        facts = cbm_compiler_facts_parse_chunk_index(json, json_length, root, inputs, count, gbuf,
                                                     cache, parse_error, sizeof(parse_error));
    } else if (package_index && !chunk_profile) {
        facts = cbm_compiler_facts_parse_index(json, json_length, root, inputs, count, gbuf,
                                               cache, parse_error, sizeof(parse_error));
    } else {
        facts = cbm_compiler_facts_parse(json, json_length, root,
                                         group == 0 ? "go" : "typescript", inputs, count, gbuf,
                                         parse_error, sizeof(parse_error));
    }
    free(json);
    if (!facts) {
        reject(status, parse_error[0] ? parse_error : "facts_rejected");
    } else if (cancelled(cancel)) {
        cbm_compiler_facts_free(facts);
        facts = NULL;
        reject(status, "cancelled");
    } else {
        yyjson_val *document = cbm_compiler_facts_json(facts);
        bool complete = yyjson_is_true(yyjson_obj_get(document, "complete"));
        status->status = complete ? "complete" : "partial";
        if (!complete) {
            const char *kind = yyjson_get_str(yyjson_obj_get(document, "kind"));
            snprintf(status->reason, sizeof(status->reason), "%s",
                     ts_proof_profile ? "proof_index_partial" :
                     kind && strcmp(kind, "typescript_local_target_index") == 0
                         ? "project_errors_local_targets_only" : "package_index_incomplete");
        }
    }
cleanup:
    /* Never remove a live child's immutable input after containment failed. */
    if (quiesced) {
        bool retained = facts && cbm_compiler_facts_is_chunk_index(facts);
        if (retained) {
            *storage = calloc(1, sizeof(**storage));
            if (*storage) {
                strcpy((*storage)->directory, temporary);
                (*storage)->references = 1;
            } else {
                cbm_compiler_facts_free(facts);
                facts = NULL;
                retained = false;
                reject(status, "allocation_failed");
            }
        }
        bool cleaned = remove_owned(manifest);
        cleaned = remove_owned(output) && cleaned;
        cleaned = remove_owned(log) && cleaned;
        if (!retained) {
            char chunks[RUN_PATH_MAX];
            if (private_chunks && join_path(chunks, temporary, "chunks"))
                cleaned = remove_chunk_directory(chunks) && cleaned;
            cleaned = cbm_rmdir(temporary) == 0 && cleaned;
        }
        if (!cleaned) {
            cbm_compiler_facts_free(facts);
            facts = NULL;
            release_chunk_storage(*storage);
            *storage = NULL;
            reject(status, "temporary_cleanup_failed");
        } else if (facts && group == 1) {
            /* A configured include may observe the transport even outside root. */
            char error[256] = {0};
            CBMCompilerFacts *rebound = cbm_compiler_facts_rebind(
                facts, root, inputs, count, gbuf, error, sizeof(error));
            cbm_compiler_facts_free(facts);
            facts = rebound;
            if (!facts)
                reject(status, error[0] ? error : "facts_rejected_after_cleanup");
            else if (cancelled(cancel)) {
                cbm_compiler_facts_free(facts);
                facts = NULL;
                reject(status, "cancelled");
            }
        }
    }
done:
    free(documents);
    free(inputs);
    free(hashes);
    return facts;
}

static bool make_status(CBMCompilerRun *run, const run_status_t status[2]) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) {
        return false;
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    bool ok = root && yyjson_mut_obj_add_uint(doc, root, "schema", 1);
    for (int i = 0; ok && i < 2; i++) {
        yyjson_mut_val *item = yyjson_mut_obj(doc);
        ok = item && yyjson_mut_obj_add_str(doc, item, "status", status[i].status) &&
             yyjson_mut_obj_add_str(doc, item, "reason", status[i].reason) &&
             yyjson_mut_obj_add_uint(doc, item, "files", status[i].files) &&
             yyjson_mut_obj_add_uint(doc, item, "sites", cbm_compiler_facts_count(run->facts[i])) &&
             yyjson_mut_obj_add_val(doc, root, i == 0 ? "go" : "typescript", item);
        yyjson_val *facts = cbm_compiler_facts_json(run->facts[i]);
        char selection_digest[CBM_SHA256_HEX_LEN + 1];
        if (ok && i == 0 && strcmp(status[i].status, "complete") == 0 &&
            cbm_compiler_facts_go_selection_digest(run->facts[i], selection_digest))
            ok = yyjson_mut_obj_add_strcpy(doc, item, "selection_evidence_sha256", selection_digest);
        if (ok && facts && (strcmp(status[i].status, "complete") == 0 ||
                            strcmp(status[i].status, "partial") == 0)) {
            yyjson_val *context = yyjson_obj_get(facts, "context");
            yyjson_val *cache = yyjson_obj_get(facts, "cache");
            ok = yyjson_is_obj(context) && yyjson_is_obj(cache) &&
                 yyjson_mut_obj_add_val(doc, item, "context", yyjson_val_mut_copy(doc, context)) &&
                 yyjson_mut_obj_add_val(doc, item, "cache", yyjson_val_mut_copy(doc, cache));
            uint64_t facts_schema = yyjson_get_uint(yyjson_obj_get(facts, "schema"));
            if (ok && (facts_schema == 2 || facts_schema == 3 || facts_schema == 4)) {
                const char *kind = yyjson_get_str(yyjson_obj_get(facts, "kind"));
                bool ts_chunks = i == 1 && kind && strcmp(kind, "typescript_chunk_index") == 0;
                yyjson_val *coverage = yyjson_obj_get(facts, ts_chunks ? "counts" : "summary");
                ok = yyjson_is_obj(coverage) &&
                     yyjson_mut_obj_add_uint(doc, item, "facts_schema", facts_schema) &&
                     yyjson_mut_obj_add_val(doc, item, "coverage",
                                            yyjson_val_mut_copy(doc, coverage));
                const char *profile = yyjson_get_str(yyjson_obj_get(facts, "profile"));
                if (ok && kind)
                    ok = yyjson_mut_obj_add_strcpy(doc, item, "kind", kind);
                if (ok && profile)
                    ok = yyjson_mut_obj_add_strcpy(doc, item, "profile", profile);
                if (ok && ts_chunks && profile && strcmp(profile, "proof_index_v1") == 0) {
                    yyjson_val *diagnostics = yyjson_obj_get(facts, "diagnostics");
                    ok = yyjson_is_arr(diagnostics) &&
                         yyjson_mut_obj_add_bool(doc, item, "complete", false) &&
                         yyjson_mut_obj_add_val(doc, item, "diagnostics",
                                                yyjson_val_mut_copy(doc, diagnostics));
                }
                if (ok && i == 1 && strcmp(status[i].status, "partial") == 0 && profile &&
                    (strcmp(profile, "proof_index_v1") == 0 ||
                     (kind && strcmp(kind, "typescript_local_target_index") == 0 &&
                      strcmp(profile, "lexical_target_v1") == 0))) {
                    yyjson_mut_doc *verified = yyjson_mut_doc_new(NULL);
                    yyjson_mut_val *value = verified ? yyjson_val_mut_copy(verified, facts) : NULL;
                    if (value)
                        yyjson_mut_doc_set_root(verified, value);
                    /* JSON order differences conservatively rebuild; cache observations do not. */
                    size_t length = 0;
                    char *json = value && yyjson_mut_obj_remove_key(value, "cache")
                        ? yyjson_mut_write(verified, 0, &length) : NULL;
                    char digest[CBM_SHA256_HEX_LEN + 1];
                    if (json)
                        cbm_sha256_hex(json, length, digest);
                    yyjson_mut_val *evidence = json
                        ? yyjson_mut_obj_add_obj(doc, item, "evidence") : NULL;
                    ok = evidence && yyjson_mut_obj_add_uint(doc, evidence, "version", 1) &&
                         yyjson_mut_obj_add_strcpy(doc, evidence, "sha256", digest);
                    free(json);
                    yyjson_mut_doc_free(verified);
                }
            }
        }
    }
    run->status = ok ? yyjson_mut_write(doc, 0, NULL) : NULL;
    yyjson_mut_doc_free(doc);
    return run->status != NULL;
}

CBMCompilerRun *cbm_compiler_runner_prepare(const char *root, const cbm_file_info_t *files,
                                            int file_count, const cbm_gbuf_t *gbuf,
                                            atomic_int *cancel, char *error, size_t error_size) {
    if (error && error_size) {
        error[0] = '\0';
    }
    CBMCompilerRun *run = calloc(1, sizeof(*run));
    if (!run) {
        if (error && error_size) {
            snprintf(error, error_size, "allocation_failed");
        }
        return NULL;
    }
    run_status_t *status = run->languages;
    status[0].status = status[1].status = "disabled";
    char helpers[2][RUN_PATH_MAX], node_buffer[RUN_PATH_MAX], ts_buffer[RUN_PATH_MAX];
    const char *helper[2] = {
        cbm_safe_getenv("CBM_GO_FACTS_HELPER", helpers[0], sizeof(helpers[0]), ""),
        cbm_safe_getenv("CBM_TS_FACTS_HELPER", helpers[1], sizeof(helpers[1]), ""),
    };
    const char *node =
        cbm_safe_getenv("CBM_NODE_COMMAND", node_buffer, sizeof(node_buffer), "node");
    const char *typescript =
        cbm_safe_getenv("CBM_TYPESCRIPT_PATH", ts_buffer, sizeof(ts_buffer), "");
    char canonical[RUN_PATH_MAX] = {0};
    bool cgo_headers = cbm_go_cgo_enabled();
    for (int group = 0; group < 2; group++) {
        if (helper[group] && !helper[group][0]) {
            continue;
        }
        if (!helper[group] || (group == 1 && (!node || !node[0] || !typescript))) {
            reject(&status[group], "helper_configuration_invalid");
            continue;
        }
        if (file_count < 0 || (file_count && !files) || !gbuf) {
            reject(&status[group], "invalid_inputs");
            continue;
        }
        bool has_language_file = false;
        for (int i = 0; i < file_count; i++) {
            has_language_file |= language_group(files[i].language) == group;
            status[group].files += manifest_group(&files[i], cgo_headers) == group;
        }
        if (!has_language_file) {
            status[group].files = 0;
            status[group].status = "no_files";
            continue;
        }
        if (status[group].files > RUN_MAX_FILES) {
            reject(&status[group], "file_budget");
            continue;
        }
        if (cancelled(cancel)) {
            reject(&status[group], "cancelled");
            continue;
        }
        if (!canonical[0] && (!root || !cbm_canonical_path(root, canonical, sizeof(canonical)))) {
            canonical[0] = '\0';
            reject(&status[group], "root_invalid");
            continue;
        }
        cbm_normalize_path_sep(canonical);
        CBM_PROF_START(t_language);
        run->facts[group] = run_language(canonical, files, file_count, group, helper[group], node,
                                         typescript, gbuf, cancel, cgo_headers, &status[group],
                                         &run->chunk_storage[group]);
        CBM_PROF_END_N("compiler_facts", group == 0 ? "go" : "typescript", t_language,
                       status[group].files);
    }
    for (int group = 0; group < 2; group++) {
        if (error && error_size && !error[0] &&
            strcmp(status[group].status, "degraded") == 0 && status[group].reason[0]) {
            snprintf(error, error_size, "%s: %s", group == 0 ? "go" : "typescript",
                     status[group].reason);
        }
    }
    if (!make_status(run, status)) {
        if (error && error_size) {
            snprintf(error, error_size, "allocation_failed");
        }
        cbm_compiler_runner_free(run);
        return NULL;
    }
    return run;
}

CBMCompilerRun *cbm_compiler_runner_rebind(const CBMCompilerRun *previous, const char *root,
                                           const cbm_file_info_t *files, int file_count,
                                           const cbm_gbuf_t *gbuf, atomic_int *cancel, char *error,
                                           size_t error_size) {
    if (error && error_size)
        error[0] = '\0';
    char canonical[RUN_PATH_MAX];
    CBMCompilerRun *run = NULL;
    const char *reason = "invalid_rebind_inputs";
    if (!previous || !root || !gbuf || file_count < 0 || (file_count && !files) ||
        !cbm_canonical_path(root, canonical, sizeof(canonical)))
        goto failed;
    cbm_normalize_path_sep(canonical);
    run = calloc(1, sizeof(*run));
    if (!run) {
        reason = "allocation_failed";
        goto failed;
    }
    memcpy(run->languages, previous->languages, sizeof(run->languages));
    bool cgo_headers = cbm_go_cgo_enabled();
    for (int group = 0; group < 2; group++) {
        run->chunk_storage[group] = previous->chunk_storage[group];
        if (run->chunk_storage[group])
            run->chunk_storage[group]->references++;
    }
    for (int group = 0; group < 2; group++) {
        if (!previous->facts[group])
            continue;
        size_t count = 0;
        for (int i = 0; i < file_count; i++)
            count += manifest_group(&files[i], cgo_headers) == group;
        if (!count || count != previous->languages[group].files || count > RUN_MAX_FILES) {
            reason = "rebind_manifest_differs";
            goto failed;
        }
        CBMCompilerInput *inputs = calloc(count, sizeof(*inputs));
        char (*hashes)[65] = calloc(count, sizeof(*hashes));
        if (!inputs || !hashes) {
            free(inputs);
            free(hashes);
            reason = "allocation_failed";
            goto failed;
        }
        bool valid = true;
        size_t next = 0;
        uint64_t total = 0;
        for (int i = 0; i < file_count; i++) {
            if (manifest_group(&files[i], cgo_headers) != group)
                continue;
            uint64_t length = 0;
            if (cancelled(cancel) ||
                !source_hash(canonical, files[i].rel_path, hashes[next], &length, cancel) ||
                length > RUN_MAX_SOURCE - total) {
                valid = false;
                break;
            }
            total += length;
            inputs[next] = (CBMCompilerInput){files[i].rel_path, hashes[next], length};
            next++;
        }
        if (valid)
            run->facts[group] = cbm_compiler_facts_rebind(previous->facts[group], canonical,
                                                         inputs, count, gbuf, error, error_size);
        free(inputs);
        free(hashes);
        if (!valid || !run->facts[group]) {
            reason = cancelled(cancel) ? "cancelled" : "rebind_source_or_manifest_changed";
            goto failed;
        }
    }
    if (cancelled(cancel) || !make_status(run, run->languages)) {
        reason = cancelled(cancel) ? "cancelled" : "allocation_failed";
        goto failed;
    }
    return run;
failed:
    if (error && error_size && !error[0])
        snprintf(error, error_size, "%s", reason);
    cbm_compiler_runner_free(run);
    return NULL;
}

void cbm_compiler_runner_free(CBMCompilerRun *run) {
    if (run) {
        cbm_compiler_facts_free(run->facts[0]);
        cbm_compiler_facts_free(run->facts[1]);
        release_chunk_storage(run->chunk_storage[0]);
        release_chunk_storage(run->chunk_storage[1]);
        free(run->status);
        free(run);
    }
}

const CBMCompilerFacts *cbm_compiler_runner_facts(const CBMCompilerRun *run, CBMLanguage language) {
    int group = language_group(language);
    const CBMCompilerFacts *facts = run && group >= 0 ? run->facts[group] : NULL;
    return cbm_compiler_facts_is_chunk_index(facts) ? NULL : facts;
}

bool cbm_compiler_runner_go_file_unselected(const CBMCompilerRun *run, const char *path,
                                           const char *sha256) {
    return run && strcmp(run->languages[0].status, "complete") == 0 &&
           cbm_compiler_facts_go_file_unselected(run->facts[0], path, sha256);
}

typedef struct {
    int index;
    int group;
    size_t rank;
} run_file_order_t;

static int compare_file_order(const void *left, const void *right) {
    const run_file_order_t *a = left, *b = right;
    if (a->group != b->group)
        return a->group < b->group ? -1 : 1;
    if (a->rank != b->rank)
        return a->rank < b->rank ? -1 : 1;
    return (a->index > b->index) - (a->index < b->index);
}

bool cbm_compiler_runner_has_chunk_index(const CBMCompilerRun *run) {
    return run && (cbm_compiler_facts_is_chunk_index(run->facts[0]) ||
                   cbm_compiler_facts_is_chunk_index(run->facts[1]));
}

bool cbm_compiler_runner_language_has_chunk_index(const CBMCompilerRun *run,
                                                  CBMLanguage language) {
    int group = language_group(language);
    return run && group >= 0 && cbm_compiler_facts_is_chunk_index(run->facts[group]);
}

bool cbm_compiler_runner_order_files(const CBMCompilerRun *run, const cbm_file_info_t *files,
                                      int file_count, int **order) {
    if (!order || file_count < 0 || (file_count && !files))
        return false;
    *order = NULL;
    if (!cbm_compiler_runner_has_chunk_index(run) || !file_count)
        return true;
    run_file_order_t *ranked = calloc((size_t)file_count, sizeof(*ranked));
    int *indices = calloc((size_t)file_count, sizeof(*indices));
    if (!ranked || !indices) {
        free(ranked);
        free(indices);
        return false;
    }
    for (int i = 0; i < file_count; i++) {
        size_t rank = SIZE_MAX;
        int group = language_group(files[i].language);
        bool chunked = cbm_compiler_runner_language_has_chunk_index(run, files[i].language);
        if (chunked) {
            rank = cbm_compiler_facts_file_order(run->facts[group], files[i].rel_path);
            if (rank == SIZE_MAX)
                rank--;
        }
        ranked[i] = (run_file_order_t){i, chunked ? group : 2, rank};
    }
    qsort(ranked, (size_t)file_count, sizeof(*ranked), compare_file_order);
    for (int i = 0; i < file_count; i++)
        indices[i] = ranked[i].index;
    free(ranked);
    *order = indices;
    return true;
}

bool cbm_compiler_runner_acquire_file(CBMCompilerRun *run, CBMLanguage language,
                                       const char *path, const char *source_sha256,
                                       const CBMCompilerFacts **view) {
    if (!view)
        return false;
    int group = language_group(language);
    CBMCompilerFacts *facts = run && group >= 0 ? run->facts[group] : NULL;
    *view = facts;
    if (!cbm_compiler_facts_is_chunk_index(facts))
        return true;
    if (!cbm_compiler_facts_file_matches(facts, path, source_sha256))
        return false;
    char error[256];
    return cbm_compiler_facts_acquire_file(facts, path, view, error, sizeof(error));
}

void cbm_compiler_runner_release_file(CBMCompilerRun *run, CBMLanguage language) {
    int group = language_group(language);
    if (run && group >= 0 && cbm_compiler_facts_is_chunk_index(run->facts[group]))
        cbm_compiler_facts_release_file(run->facts[group]);
}

bool cbm_compiler_runner_finish_files(CBMCompilerRun *run) {
    char error[256];
    bool ok = true;
    for (int group = 0; run && group < 2; group++) {
        if (cbm_compiler_facts_is_chunk_index(run->facts[group]) &&
            !cbm_compiler_facts_finish_files(run->facts[group], error, sizeof(error)))
            ok = false;
    }
    return ok;
}

const CBMCompilerSite *cbm_compiler_runner_find(const CBMCompilerRun *run, CBMLanguage language,
                                                const char *path, const char *sha256,
                                                uint32_t start_byte, uint32_t end_byte) {
    const CBMCompilerFacts *facts = cbm_compiler_runner_facts(run, language);
    return facts ? cbm_compiler_facts_find(facts, path, sha256, start_byte, end_byte) : NULL;
}

const char *cbm_compiler_runner_status(const CBMCompilerRun *run) {
    if (!run)
        return NULL;
    return run->status ? run->status
                       : "{\"schema\":1,\"go\":{\"status\":\"degraded\",\"reason\":\"status_"
                         "allocation_failed\"},"
                         "\"typescript\":{\"status\":\"degraded\",\"reason\":\"status_allocation_"
                         "failed\"}}";
}

void cbm_compiler_runner_registry_failed(CBMCompilerRun *run, CBMLanguage language) {
    int group = language_group(language);
    if (!run || group < 0 || !run->facts[group])
        return;
    reject(&run->languages[group], "registry_merge_failed");
    free(run->status);
    run->status = NULL;
    (void)make_status(run, run->languages);
}
