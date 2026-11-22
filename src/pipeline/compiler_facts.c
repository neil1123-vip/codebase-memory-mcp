#include "pipeline/compiler_facts.h"

#include "foundation/compat_fs.h"
#include "foundation/platform.h"
#include "foundation/sha256.h"
#include "helpers.h"
#include "tree_sitter/api.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

extern const TSLanguage *tree_sitter_typescript(void);
extern const TSLanguage *tree_sitter_tsx(void);
extern const TSLanguage *tree_sitter_javascript(void);
extern const TSLanguage *tree_sitter_html(void);

enum {
    CF_MAX_JSON = 32 * 1024 * 1024,
    CF_MAX_FILES = 65536,
    CF_MAX_IDENTITIES = 131072,
    CF_MAX_SITES = 262144,
    CF_MAX_PACKAGE_FILES = 200000,
    CF_MAX_DISCOVERY_PROBES = 200000,
    CF_MAX_INPUT_BYTES = 256 * 1024 * 1024,
    CF_PATH_SIZE = 4096,
    CF_TYPE_DEPTH = 64,
    CF_MAX_TYPE_BYTES = 64 * 1024 * 1024,
    CF_MAX_LOCAL_AST_BYTES = 64 * 1024 * 1024,
    CF_MAX_LOCAL_AST_NODES = 8 * 1024 * 1024,
    CF_MAX_LOCAL_AST_DEPTH = 4096,
    CF_CHUNK_MAX_SITES = 100000,
    CF_CHUNK_MAX_IDENTITIES = 50000,
    CF_CHUNK_MAX_EXPANDED = 256 * 1024 * 1024,
    CF_CHUNK_MAX_ENCODED = 512 * 1024 * 1024,
    CF_TS_MAX_TYPES = 20000,
    CF_TS_MAX_SYMBOLS = 20000,
    CF_TS_MAX_SITES = 100000,
};

typedef struct {
    const char *path;
    const char *sha256;
    uint64_t length;
} CFFile;

typedef struct {
    const char *id;
    const char *path;
    bool external;
} CFPackage;

typedef struct {
    uint32_t slots;
    uint8_t family;
    uint8_t positions[19];
} CFCompactSchema;

typedef struct {
    const char **strings;
    CFCompactSchema *schemas;
    size_t string_count, schema_count;
    size_t next_string, next_schema;
} CFCompact;

typedef struct {
    yyjson_val *raw;
    const CFCompact *codec;
} CFValue;

typedef struct {
    CFValue json;
    const char *package;
    char *qn;
    char *external_name;
    bool external;
    bool excluded;
    bool callable;
    bool cgo_native;
} CFSymbol;

typedef struct {
    CBMCompilerSite site;
    const CFSymbol *symbol;
} CFRow;

typedef struct {
    const char *path;
    const char *sha256;
    uint32_t start;
    uint32_t end;
    size_t site;
} CFMatch;

typedef struct {
    const CFFile *file;
    uint32_t start;
    uint32_t end;
    const char *qn;
    const char *name;
    size_t logical_length;
    uint8_t callable_kind;
    bool go_physical;
    bool cgo_preamble;
    bool nominal_type;
    bool ambiguous;
} CFDeclaration;

typedef struct {
    CFValue json;
    const char *qn;
    const CBMType *value;
    const CBMType *shape_value;
    bool active;
    bool static_type;
    bool external;
} CFType;

typedef struct {
    const char *path;
    const CFSymbol *symbol;
    size_t type_id;
    bool is_type;
    bool ambiguous;
} CFBinding;

typedef struct {
    const CBMType *value;
    uint64_t active_mask;
    size_t active_ids[CF_TYPE_DEPTH];
    unsigned depth, height;
} CFContextMemo;

typedef struct {
    const CBMType *value;
    unsigned height;
    CFContextMemo *context;
} CFIndependentMemo;

typedef struct {
    uint64_t cut_epoch, active_frames;
    unsigned frame_heights[CF_TYPE_DEPTH];
    size_t frame_ids[CF_TYPE_DEPTH];
    size_t context_hits, context_replacements, context_count;
    CFIndependentMemo memo[];
} CFProjectionState;

typedef struct CFIndexPackage CFIndexPackage;

struct CBMCompilerFacts {
    yyjson_doc *doc;
    CFCompact *compact;
    bool compact_index;
    CFFile *files;
    size_t file_count;
    CFPackage *packages;
    size_t package_count;
    CFSymbol *symbols;
    size_t symbol_count;
    CFRow *rows;
    size_t row_count;
    CFMatch *matches;
    size_t match_count;
    CBMCompilerSite *conflicts;
    CBMArena arena;
    CFType *types;
    size_t type_count;
    CFBinding *bindings;
    size_t binding_count;
    bool projection_failed;
    size_t type_budget;
    size_t auxiliary_bytes;
    CFProjectionState *projection_state;
    bool borrowed_tables;
    bool package_fragment;
    bool chunk_fragment;
    bool package_index;
    bool local_target_index;
    CBMCompilerFacts **children;
    size_t child_count;
    char *fragment_directory;
    bool chunk_index;
    bool ts_chunk_index;
    bool proof_index;
    yyjson_val *proof_root;
    yyjson_val **ts_descriptors[3];
    CFIndexPackage *index_packages;
    bool *go_unselected;
    bool *file_eligible;
    size_t *file_members;
    size_t *file_chunks;
    yyjson_val **file_package_ids;
    CFDeclaration *declarations;
    size_t declaration_count;
    CBMArena declaration_arena;
    size_t catalogue_bytes;
    size_t verified_sites;
    size_t next_chunk;
    size_t active_chunk;
    size_t consumed_expanded;
    CBMCompilerFacts *active_view;
    bool file_acquired;
    bool chunks_failed;
    bool files_finished;
};

static const char *cf_string(yyjson_val *value) {
    const char *text = yyjson_get_str(value);
    return text && strlen(text) == yyjson_get_len(value) ? text : NULL;
}

static const char *cf_str(yyjson_val *object, const char *key) {
    return cf_string(yyjson_obj_get(object, key));
}

static void cf_diagnostic_text(char *out, size_t size, const char *text) {
    size_t used = 0;
    while (text && *text && used + 1 < size) {
        unsigned char c = (unsigned char)*text;
        size_t width = c < 0x80 ? 1 : c < 0xe0 ? 2 : c < 0xf0 ? 3 : 4;
        if (width > size - used - 1)
            break;
        if (c < 0x20 || c == 0x7f)
            out[used++] = ' ';
        else {
            memcpy(out + used, text, width);
            used += width;
        }
        text += width;
    }
    out[used] = '\0';
}

static bool cf_equal(const char *a, const char *b) {
    return a == b || (a && b && strcmp(a, b) == 0);
}

static bool cf_hash(const char *text) {
    if (!text || strlen(text) != CBM_SHA256_HEX_LEN)
        return false;
    for (size_t i = 0; i < CBM_SHA256_HEX_LEN; i++) {
        if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f')))
            return false;
    }
    return true;
}

static bool cf_cgo_header(const char *path) {
    return path && cf_equal(strrchr(path, '.'), ".h");
}

static uint8_t cf_callable_kind(const char *label) {
    return cf_equal(label, "Function") ? 1 : cf_equal(label, "Method") ? 2 : 0;
}

static char *cf_physical_declaration_qn(CBMArena *arena, const char *logical, const char *path,
                                        const char *label, const char *sha256, uint32_t start,
                                        uint32_t end, uint32_t origin, const char *domain,
                                        const char *suffix) {
    if (!arena || !logical || !*logical || !path || !*path ||
        !cf_hash(sha256) || start >= end || origin != 0)
        return NULL;
    cbm_sha256_ctx hash;
    cbm_sha256_init(&hash);
    const char *fields[] = {domain, logical, path, label, sha256};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        uint64_t length = strlen(fields[i]);
        uint8_t encoded[8];
        for (size_t j = 0; j < sizeof(encoded); j++)
            encoded[j] = (uint8_t)(length >> ((7 - j) * 8));
        cbm_sha256_update(&hash, encoded, sizeof(encoded));
        cbm_sha256_update(&hash, fields[i], (size_t)length);
    }
    const uint32_t offsets[] = {start, end, origin};
    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        uint8_t encoded[4];
        for (size_t j = 0; j < sizeof(encoded); j++)
            encoded[j] = (uint8_t)(offsets[i] >> ((3 - j) * 8));
        cbm_sha256_update(&hash, encoded, sizeof(encoded));
    }
    uint8_t digest[CBM_SHA256_DIGEST_LEN];
    char hex[CBM_SHA256_HEX_LEN + 1];
    static const char digits[] = "0123456789abcdef";
    cbm_sha256_final(&hash, digest);
    for (size_t i = 0; i < sizeof(digest); i++) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    hex[CBM_SHA256_HEX_LEN] = '\0';
    return cbm_arena_sprintf(arena, "%s%s%s", logical, suffix, hex);
}

char *cbm_compiler_go_declaration_qn(CBMArena *arena, const char *logical, const char *path,
                                    const char *label, const char *sha256, uint32_t start,
                                    uint32_t end, uint32_t origin) {
    if (!cf_callable_kind(label) && !cf_equal(label, "Field"))
        return NULL;
    return cf_physical_declaration_qn(arena, logical, path, label, sha256, start, end, origin,
                                      "cbm-go-physical-v1", ".@go:");
}

char *cbm_compiler_js_declaration_qn(CBMArena *arena, const char *logical, const char *path,
                                    const char *label, const char *sha256, uint32_t start,
                                    uint32_t end, uint32_t origin) {
    const char *ext = path ? strrchr(path, '.') : NULL;
    char extension[5] = {0};
    if (!cf_callable_kind(label) || !ext || strlen(ext) >= sizeof(extension))
        return NULL;
    for (size_t i = 0; ext[i]; i++)
        extension[i] = (char)tolower((unsigned char)ext[i]);
    if (!(cf_equal(extension, ".js") || cf_equal(extension, ".jsx") ||
          cf_equal(extension, ".mjs") || cf_equal(extension, ".cjs") ||
          cf_equal(extension, ".ts") || cf_equal(extension, ".tsx") ||
          cf_equal(extension, ".mts") || cf_equal(extension, ".cts")))
        return NULL;
    return cf_physical_declaration_qn(arena, logical, path, label, sha256, start, end, origin,
                                      "cbm-js-physical-v1", ".@js:");
}

static bool cf_uint(yyjson_val *object, const char *key, uint64_t *out) {
    yyjson_val *value = yyjson_obj_get(object, key);
    if (!yyjson_is_uint(value))
        return false;
    *out = yyjson_get_uint(value);
    return true;
}

static const char *const cf_compact_names[][19] = {
    {"Package", "Types", "Symbols", "Sites"},
    {"id", "path", "dir", "name", "for_test", "ill_typed", "errors"},
    {"id", "kind", "name", "package", "origin_symbol", "underlying", "elem", "key",
     "length", "direction", "receiver", "variadic", "params", "returns", "type_params",
     "args", "fields", "methods", "embeds"},
    {"name", "type", "package", "embedded"},
    {"id", "package_id", "package", "kind", "name", "internal", "type", "receiver",
     "declaration", "location_status"},
    {"path", "sha256", "start", "end", "name_start", "name_end"},
    {"path", "sha256", "package_id", "start", "end", "callee_start", "callee_end",
     "dispatch", "reason", "target_symbol", "target_package", "receiver", "type",
     "args", "arguments", "handler_symbol"},
};

static CFValue cf_value(yyjson_val *raw) {
    return (CFValue){.raw = raw};
}

static bool cfv_is_arr(CFValue value) {
    if (!value.codec)
        return yyjson_is_arr(value.raw);
    yyjson_val *tag = yyjson_arr_get_first(value.raw);
    return yyjson_is_sint(tag) && yyjson_get_sint(tag) == -1;
}

static bool cfv_is_obj(CFValue value) {
    return value.codec ? yyjson_is_arr(value.raw) &&
                            yyjson_is_uint(yyjson_arr_get_first(value.raw))
                      : yyjson_is_obj(value.raw);
}

static CFValue cfv_get(CFValue value, const char *key) {
    if (!value.codec)
        return cf_value(yyjson_obj_get(value.raw, key));
    CFValue absent = {.codec = value.codec};
    if (!cfv_is_obj(value))
        return absent;
    size_t index = (size_t)yyjson_get_uint(yyjson_arr_get_first(value.raw));
    if (index >= value.codec->schema_count)
        return absent;
    const CFCompactSchema *schema = &value.codec->schemas[index];
    for (size_t slot = 0; slot < 19 && cf_compact_names[schema->family][slot]; slot++) {
        if (strcmp(cf_compact_names[schema->family][slot], key) == 0) {
            uint8_t position = schema->positions[slot];
            return (CFValue){position ? yyjson_arr_get(value.raw, position) : NULL,
                             value.codec};
        }
    }
    return absent;
}

static size_t cfv_size(CFValue value) {
    size_t count = cfv_is_arr(value) ? yyjson_arr_size(value.raw) : 0;
    return count && value.codec ? count - 1 : count;
}

static CFValue cfv_at(CFValue value, size_t index) {
    return (CFValue){index < cfv_size(value)
                         ? yyjson_arr_get(value.raw, index + (value.codec != NULL))
                         : NULL,
                     value.codec};
}

typedef struct {
    yyjson_arr_iter raw;
    const CFCompact *codec;
} CFValueIterator;

static CFValueIterator cfv_iterator(CFValue value) {
    CFValueIterator iter = {.raw = yyjson_arr_iter_with(cfv_is_arr(value) ? value.raw : NULL),
                            .codec = value.codec};
    if (value.codec && cfv_is_arr(value))
        yyjson_arr_iter_next(&iter.raw);
    return iter;
}

static CFValue cfv_next(CFValueIterator *iter) {
    return (CFValue){yyjson_arr_iter_next(&iter->raw), iter->codec};
}

#define cfv_foreach(array, index, count, value)                                             \
    for (CFValueIterator cf_iter = cfv_iterator(array);                                    \
         ((value) = cfv_next(&cf_iter)).raw &&                                             \
         (((index) = cf_iter.raw.idx - 1 - (cf_iter.codec != NULL)),                        \
          ((count) = cfv_size(array)), true);)

static const char *cfv_string(CFValue value) {
    if (!value.codec)
        return cf_string(value.raw);
    if (!yyjson_is_sint(value.raw))
        return NULL;
    int64_t number = yyjson_get_sint(value.raw);
    uint64_t index = number < 0 ? (uint64_t)(-(number + 1)) : UINT64_MAX;
    return index < value.codec->string_count ? value.codec->strings[index] : NULL;
}

static const char *cfv_str(CFValue value, const char *key) {
    return cfv_string(cfv_get(value, key));
}

static bool cfv_is_uint(CFValue value) {
    return yyjson_is_uint(value.raw);
}

static uint64_t cfv_get_uint(CFValue value) {
    return yyjson_get_uint(value.raw);
}

static int64_t cfv_get_sint(CFValue value) {
    yyjson_val *raw = value.raw;
    yyjson_val *tag = value.codec ? yyjson_arr_get_first(raw) : NULL;
    if (yyjson_arr_size(raw) == 2 && yyjson_is_sint(tag) && yyjson_get_sint(tag) == -2)
        raw = yyjson_arr_get(raw, 1);
    return yyjson_get_sint(raw);
}

static bool cfv_uint(CFValue value, const char *key, uint64_t *out) {
    CFValue field = cfv_get(value, key);
    if (!cfv_is_uint(field))
        return false;
    *out = cfv_get_uint(field);
    return true;
}

static bool cfv_is_bool(CFValue value) {
    return yyjson_is_bool(value.raw);
}

static bool cfv_is_true(CFValue value) {
    return yyjson_is_true(value.raw);
}

static bool cfv_is_false(CFValue value) {
    return yyjson_is_false(value.raw);
}

static bool cfv_is_null(CFValue value) {
    return yyjson_is_null(value.raw);
}

static bool cfv_empty_array(CFValue object, const char *key) {
    CFValue value = cfv_get(object, key);
    return !value.raw || (cfv_is_arr(value) && !cfv_size(value));
}

static const char *cfv_optional_string(CFValue object, const char *key) {
    CFValue value = cfv_get(object, key);
    return value.raw ? cfv_string(value) : "";
}

static CFValue cf_fact_root(const CBMCompilerFacts *facts) {
    yyjson_val *raw = yyjson_doc_get_root(facts->doc);
    return facts->compact ? (CFValue){yyjson_obj_get(raw, "Root"), facts->compact}
                          : cf_value(raw);
}

static int cf_string_compare(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Reject duplicate keys before exposing the borrowed document to consumers. */
static bool cf_json_shape(yyjson_val *value, unsigned depth) {
    if (!value || depth > 64)
        return false;
    if (yyjson_is_str(value))
        return cf_string(value) != NULL;
    if (yyjson_is_arr(value)) {
        size_t i, count;
        yyjson_val *child;
        yyjson_arr_foreach(value, i, count, child) {
            if (!cf_json_shape(child, depth + 1))
                return false;
        }
    } else if (yyjson_is_obj(value)) {
        size_t count = yyjson_obj_size(value), i = 0;
        const char **keys = count ? malloc(count * sizeof(*keys)) : NULL;
        if (count && !keys)
            return false;
        yyjson_obj_iter iter = yyjson_obj_iter_with(value);
        yyjson_val *key;
        while ((key = yyjson_obj_iter_next(&iter))) {
            const char *text = cf_string(key);
            if (!text || !cf_json_shape(yyjson_obj_iter_get_val(key), depth + 1)) {
                free(keys);
                return false;
            }
            keys[i++] = text;
        }
        if (count > 1)
            qsort(keys, count, sizeof(*keys), cf_string_compare);
        for (i = 1; i < count; i++) {
            if (strcmp(keys[i - 1], keys[i]) == 0) {
                free(keys);
                return false;
            }
        }
        free(keys);
    }
    return true;
}

static bool cf_temporary(const char *path) {
    if (!path)
        return true;
    for (const char *p = path; *p;) {
        const char *end = p;
        while (*end && *end != '/' && *end != '\\')
            end++;
        static const char prefix[] = ".tmp-rebase-";
        if ((size_t)(end - p) >= sizeof(prefix) - 1) {
            size_t i = 0;
            while (i < sizeof(prefix) - 1 &&
                   tolower((unsigned char)p[i]) == (unsigned char)prefix[i])
                i++;
            if (i == sizeof(prefix) - 1)
                return true;
        }
        p = *end ? end + 1 : end;
    }
    return false;
}

static bool cf_relative(const char *path) {
    if (!path || !*path || strlen(path) >= CF_PATH_SIZE || cf_temporary(path))
        return false;
    for (const char *p = path; *p;) {
        const char *end = p;
        while (*end && *end != '/') {
            if ((unsigned char)*end < 32 || *end == '\\' || *end == ':')
                return false;
            end++;
        }
        size_t length = (size_t)(end - p);
        if (!length || (length == 1 && *p == '.') || (length == 2 && p[0] == '.' && p[1] == '.') ||
            (*end && !end[1]))
            return false;
        p = *end ? end + 1 : end;
    }
    return true;
}

static void cf_slashes(char *path) {
    for (char *p = path; *p; p++) {
        if (*p == '\\')
            *p = '/';
    }
    size_t length = strlen(path);
    while (length > 1 && path[length - 1] == '/' && !(length == 3 && path[1] == ':'))
        path[--length] = '\0';
}

static bool cf_path_equal(const char *a, const char *b) {
    if (!a || !b)
        return false;
    while (*a && *b) {
        unsigned char x = (unsigned char)*a++, y = (unsigned char)*b++;
        x = x == '\\' ? '/' : x;
        y = y == '\\' ? '/' : y;
#ifdef _WIN32
        x = (unsigned char)tolower(x);
        y = (unsigned char)tolower(y);
#endif
        if (x != y)
            return false;
    }
    return *a == *b;
}

static bool cf_absolute(const char *path) {
    if (!path || cf_temporary(path) || strlen(path) >= CF_PATH_SIZE)
        return false;
    if (path[0] == '/' && path[1] != '/')
        return !path[1] || cf_relative(path + 1);
    if (isalpha((unsigned char)path[0]) && path[1] == ':' && path[2] == '/')
        return !path[3] || cf_relative(path + 3);
    return path[0] == '/' && path[1] == '/' && cf_relative(path + 2);
}

static int cf_file_compare(const void *a, const void *b) {
#ifdef _WIN32
    const char *x = ((const CFFile *)a)->path, *y = ((const CFFile *)b)->path;
    while (*x && *y) {
        int delta = tolower((unsigned char)*x++) - tolower((unsigned char)*y++);
        if (delta)
            return delta;
    }
    return (unsigned char)*x - (unsigned char)*y;
#else
    return strcmp(((const CFFile *)a)->path, ((const CFFile *)b)->path);
#endif
}

static const CFFile *cf_file(const CBMCompilerFacts *facts, const char *path) {
    if (!path)
        return NULL;
    CFFile key = {.path = path};
    const CFFile *file =
        bsearch(&key, facts->files, facts->file_count, sizeof(*facts->files), cf_file_compare);
    return file && cf_equal(file->path, path) ? file : NULL;
}

static int cf_package_compare(const void *a, const void *b) {
    return strcmp(((const CFPackage *)a)->id, ((const CFPackage *)b)->id);
}

static const CFPackage *cf_package(const CBMCompilerFacts *facts, const char *id) {
    if (!id)
        return NULL;
    CFPackage key = {.id = id};
    return bsearch(&key, facts->packages, facts->package_count, sizeof(*facts->packages),
                   cf_package_compare);
}

static bool cf_source_current(const char *path, const CBMCompilerInput *input) {
    FILE *file = cbm_fopen(path, "rb");
    if (!file)
        return false;
    cbm_sha256_ctx hash;
    cbm_sha256_init(&hash);
    char buffer[32768];
    uint64_t length = 0;
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        if (length > input->byte_length || n > input->byte_length - length) {
            fclose(file);
            return false;
        }
        cbm_sha256_update(&hash, buffer, n);
        length += n;
    }
    bool valid = !ferror(file) && length == input->byte_length;
    fclose(file);
    uint8_t bytes[CBM_SHA256_DIGEST_LEN];
    char hex[CBM_SHA256_HEX_LEN + 1];
    cbm_sha256_final(&hash, bytes);
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(bytes); i++) {
        hex[i * 2] = digits[bytes[i] >> 4];
        hex[i * 2 + 1] = digits[bytes[i] & 15];
    }
    hex[CBM_SHA256_HEX_LEN] = '\0';
    return valid && strcmp(hex, input->sha256) == 0;
}

static const char *cf_files(CBMCompilerFacts *facts, yyjson_val *root, const char *canonical,
                            const CBMCompilerInput *inputs, size_t count) {
    yyjson_val *files = yyjson_obj_get(root, "files");
    if (!yyjson_is_arr(files) || yyjson_arr_size(files) != count)
        return "discovery whitelist differs";
    facts->files = calloc(count, sizeof(*facts->files));
    CFFile *expected = calloc(count, sizeof(*expected));
    if (!facts->files || !expected) {
        free(expected);
        return "out of memory";
    }
    facts->file_count = count;
    const char *error = NULL;
    for (size_t i = 0; i < count; i++) {
        yyjson_val *file = yyjson_arr_get(files, i);
        const CBMCompilerInput *input = &inputs[i];
        if (!cf_relative(input->path) || !cf_hash(input->sha256) ||
            input->byte_length > UINT32_MAX) {
            error = "invalid discovery input";
            break;
        }
        expected[i] = (CFFile){input->path, input->sha256, input->byte_length};
        facts->files[i] = (CFFile){cf_str(file, "path"), cf_str(file, "sha256"), 0};
        if (!cf_relative(facts->files[i].path) || !cf_hash(facts->files[i].sha256)) {
            error = "invalid fact file";
            break;
        }
        char joined[CF_PATH_SIZE], actual[CF_PATH_SIZE];
        int length = snprintf(joined, sizeof(joined), "%s%s%s", canonical,
                              canonical[strlen(canonical) - 1] == '/' ? "" : "/", input->path);
        if (length < 0 || (size_t)length >= sizeof(joined) ||
            !cbm_canonical_path(joined, actual, sizeof(actual)) || !cf_path_equal(joined, actual) ||
            cf_temporary(actual)) {
            error = "discovery file is not canonical";
            break;
        }
        if (!cf_source_current(actual, input)) {
            error = "source hash or length changed";
            break;
        }
    }
    if (!error) {
        qsort(expected, count, sizeof(*expected), cf_file_compare);
        qsort(facts->files, count, sizeof(*facts->files), cf_file_compare);
        for (size_t i = 0; i < count; i++) {
            if ((i && cf_path_equal(expected[i - 1].path, expected[i].path)) ||
                !cf_equal(expected[i].path, facts->files[i].path) ||
                !cf_equal(expected[i].sha256, facts->files[i].sha256)) {
                error = "discovery whitelist differs";
                break;
            }
            facts->files[i].length = expected[i].length;
        }
    }
    free(expected);
    return error;
}

static bool cf_empty_array(yyjson_val *object, const char *key) {
    yyjson_val *value = yyjson_obj_get(object, key);
    return !value || (yyjson_is_arr(value) && yyjson_arr_size(value) == 0);
}

bool cbm_compiler_facts_go_package_manifest_valid(yyjson_val *cache,
                                                  const CBMCompilerInput *inputs, size_t count) {
    yyjson_val *keys = yyjson_obj_get(cache, "package_keys");
    yyjson_val *members = yyjson_obj_get(cache, "package_files");
    size_t packages = yyjson_obj_size(keys);
    if (!inputs || !count || count > CF_MAX_FILES || !cf_json_shape(cache, 0) ||
        !yyjson_is_obj(keys) || !yyjson_is_obj(members) || !packages || packages > 50000 ||
        packages != yyjson_obj_size(members))
        return false;
    const char **paths = malloc(count * sizeof(*paths));
    if (!paths)
        return false;
    bool valid = true;
    for (size_t i = 0; i < count; i++) {
        paths[i] = inputs[i].path;
        if (!cf_relative(paths[i])) {
            valid = false;
            break;
        }
    }
    if (valid)
        qsort(paths, count, sizeof(*paths), cf_string_compare);
    size_t total = 0;
    yyjson_obj_iter iter = yyjson_obj_iter_with(keys);
    yyjson_val *key;
    while (valid && (key = yyjson_obj_iter_next(&iter))) {
        const char *id = cf_string(key);
        yyjson_val *files = id ? yyjson_obj_get(members, id) : NULL;
        size_t n = yyjson_arr_size(files);
        if (!id || !*id || strlen(id) >= CF_PATH_SIZE ||
            !cf_hash(cf_string(yyjson_obj_iter_get_val(key))) || !yyjson_is_arr(files) || !n ||
            n > CF_MAX_PACKAGE_FILES - total) {
            valid = false;
            break;
        }
        total += n;
        const char *previous = NULL;
        for (size_t i = 0; i < n; i++) {
            const char *path = cf_string(yyjson_arr_get(files, i));
            if (!cf_relative(path) || cf_cgo_header(path) ||
                (previous && strcmp(previous, path) >= 0) ||
                !bsearch(&path, paths, count, sizeof(*paths), cf_string_compare)) {
                valid = false;
                break;
            }
            previous = path;
        }
    }
    free(paths);
    return valid;
}

static int cf_ts_path_info(const char *path, cbm_path_info_t *info);

static const char *cf_ts_discovery(yyjson_val *context) {
    yyjson_val *discovery = yyjson_obj_get(context, "discovery");
    const char *mode = cf_str(discovery, "mode");
    yyjson_val *probes = yyjson_obj_get(discovery, "probes");
    bool automatic = cf_equal(mode, "default");
    if (!yyjson_is_obj(discovery) || yyjson_obj_size(discovery) != 2 ||
        (!automatic && !cf_equal(mode, "explicit")) || !yyjson_is_arr(probes) ||
        yyjson_arr_size(probes) > CF_MAX_DISCOVERY_PROBES ||
        (automatic && !yyjson_arr_size(probes)))
        return "invalid TypeScript discovery observations";
    size_t i, count;
    yyjson_val *probe;
    yyjson_arr_foreach(probes, i, count, probe) {
        const char *path = cf_str(probe, "path");
        yyjson_val *exists = yyjson_obj_get(probe, "exists");
        if (!yyjson_is_obj(probe) || yyjson_obj_size(probe) != 2 || !cf_absolute(path) ||
            !yyjson_is_bool(exists))
            return "invalid TypeScript discovery observation";
        /* Missing default configs are inputs too; repeat this at parse and rebind. */
        cbm_path_info_t info;
        int status = cf_ts_path_info(path, &info);
        if (status == CBM_PATH_INFO_UNAVAILABLE)
            return "TypeScript discovery path unavailable";
        if ((status == CBM_PATH_INFO_OK) != yyjson_is_true(exists))
            return "TypeScript discovery changed";
    }
    return NULL;
}

static const char *cf_ts_dependencies(yyjson_val *context, const CBMCompilerInput *inputs,
                                      size_t input_count, uint64_t *remaining,
                                      const char *trusted_prefix) {
    *remaining = CF_MAX_INPUT_BYTES;
    for (size_t i = 0; i < input_count; i++) {
        if (inputs[i].byte_length > *remaining)
            return "TypeScript input byte budget exceeded";
        *remaining -= inputs[i].byte_length;
    }
    yyjson_val *projects = yyjson_obj_get(context, "projects");
    if (!yyjson_is_arr(projects) || !yyjson_arr_size(projects) ||
        yyjson_arr_size(projects) > CF_MAX_FILES)
        return "invalid TypeScript dependency contexts";
    size_t i, project_count, total = 0;
    yyjson_val *project;
    yyjson_arr_foreach(projects, i, project_count, project) {
        yyjson_val *dependencies = yyjson_obj_get(project, "dependencies");
        if (!yyjson_is_obj(project) || !yyjson_is_arr(dependencies) ||
            yyjson_arr_size(dependencies) > CF_MAX_DISCOVERY_PROBES - total)
            return "invalid TypeScript dependencies";
        total += yyjson_arr_size(dependencies);
    }
    CFFile *files = total ? malloc(total * sizeof(*files)) : NULL;
    if (total && !files)
        return "out of memory";
    const char *error = NULL;
    size_t used = 0, prefix_length = trusted_prefix ? strlen(trusted_prefix) : 0;
    yyjson_arr_foreach(projects, i, project_count, project) {
        size_t j, count;
        yyjson_val *dependency;
        yyjson_arr_foreach(yyjson_obj_get(project, "dependencies"), j, count, dependency) {
            const char *path = cf_str(dependency, "path"), *sha256 = cf_str(dependency, "sha256");
            if (!yyjson_is_obj(dependency) || yyjson_obj_size(dependency) != 2 ||
                !cf_absolute(path) || !cf_hash(sha256)) {
                error = "invalid TypeScript dependency";
                goto done;
            }
            if (prefix_length && strncmp(path, trusted_prefix, prefix_length) != 0)
                continue;
            files[used++] = (CFFile){path, sha256, 0};
        }
    }
    if (used > 1)
        qsort(files, used, sizeof(*files), cf_file_compare);
    for (i = 0; i < used; i++) {
        /* Shared libraries must be hashed once, with the same identity in every context. */
        if (i && cf_path_equal(files[i - 1].path, files[i].path)) {
            if (!cf_equal(files[i - 1].sha256, files[i].sha256)) {
                error = "conflicting TypeScript dependency";
                break;
            }
            continue;
        }
        char actual[CF_PATH_SIZE];
        cbm_path_info_t info;
        if (!cbm_canonical_path(files[i].path, actual, sizeof(actual)) ||
            !cf_path_equal(files[i].path, actual) ||
            cbm_path_info_utf8(actual, &info) != CBM_PATH_INFO_OK ||
            !info.is_regular || info.is_symlink || info.size < 0) {
            error = "TypeScript dependency path changed";
            break;
        }
        if ((uint64_t)info.size > *remaining) {
            error = "TypeScript input byte budget exceeded";
            break;
        }
        *remaining -= (uint64_t)info.size;
        CBMCompilerInput input = {files[i].path, files[i].sha256, (uint64_t)info.size};
        if (!cf_source_current(actual, &input)) {
            error = "TypeScript dependency changed";
            break;
        }
    }
done:
    free(files);
    return error;
}

bool cbm_compiler_facts_ts_dependencies_current(yyjson_val *context, const char *typescript) {
    char directory[CF_PATH_SIZE];
    cbm_path_info_t info;
    if (!cf_absolute(typescript) || (typescript[0] == '/' && typescript[1] == '/') ||
        !cbm_canonical_path(typescript, directory, sizeof(directory)))
        return true;
    cbm_normalize_path_sep(directory);
    size_t length = strlen(directory);
    if (!length || directory[length - 1] == '/' || length >= sizeof(directory) - 1 ||
        (directory[0] == '/' && directory[1] == '/') ||
        cbm_path_info_utf8(directory, &info) != CBM_PATH_INFO_OK || !info.is_directory)
        return true;
    memcpy(directory + length, "/", 2);
    uint64_t remaining;
    return cf_ts_dependencies(context, NULL, 0, &remaining, directory) == NULL;
}

static int cf_ts_path_info(const char *path, cbm_path_info_t *info) {
    int status = cbm_path_info_utf8(path, info);
    if (status == CBM_PATH_INFO_OK && info->is_symlink) {
        char target[CF_PATH_SIZE];
        if (!cbm_canonical_path(path, target, sizeof(target)))
            return CBM_PATH_INFO_UNAVAILABLE;
        status = cbm_path_info_utf8(target, info);
    }
    return status;
}

typedef struct {
    const char *name;
    bool directory;
    bool seen;
} CFTSDirectoryEntry;

static bool cf_ts_basename(const char *name) {
    if (!name || !*name || cf_equal(name, ".") || cf_equal(name, "..") ||
        strlen(name) >= CBM_DIRENT_NAME_MAX)
        return false;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        if (*p == '/')
            return false;
#ifdef _WIN32
        if (*p < 32 || *p == '\\' || *p == ':')
            return false;
#endif
    }
    return true;
}

static int cf_ts_entry_compare(const void *a, const void *b) {
    return strcmp(((const CFTSDirectoryEntry *)a)->name,
                  ((const CFTSDirectoryEntry *)b)->name);
}

static const char *cf_ts_entries(const char *path, yyjson_val *result,
                                 size_t *expected_total, size_t *actual_total) {
    cbm_path_info_t info;
    int status = cf_ts_path_info(path, &info);
    if (status == CBM_PATH_INFO_UNAVAILABLE)
        return "TypeScript resolution directory unavailable";
    if (yyjson_is_null(result))
        return status == CBM_PATH_INFO_ABSENT || !info.is_directory
                   ? NULL : "TypeScript resolution directory changed";
    yyjson_val *files = yyjson_obj_get(result, "files");
    yyjson_val *directories = yyjson_obj_get(result, "directories");
    size_t count = yyjson_arr_size(files) + yyjson_arr_size(directories);
    if (!yyjson_is_obj(result) || yyjson_obj_size(result) != 2 || !yyjson_is_arr(files) ||
        !yyjson_is_arr(directories))
        return "invalid TypeScript resolution directory observation";
    if (count > CF_MAX_DISCOVERY_PROBES - *expected_total)
        return "TypeScript resolution directory budget exceeded";
    *expected_total += count;
    if (status != CBM_PATH_INFO_OK || !info.is_directory)
        return "TypeScript resolution directory changed";
    CFTSDirectoryEntry *entries = count ? calloc(count, sizeof(*entries)) : NULL;
    if (count && !entries)
        return "out of memory";
    const char *error = NULL;
    size_t used = 0;
    for (size_t kind = 0; kind < 2; kind++) {
        yyjson_val *names = kind ? directories : files;
        size_t i, n;
        yyjson_val *name;
        yyjson_arr_foreach(names, i, n, name) {
            const char *text = cf_string(name);
            if (!cf_ts_basename(text)) {
                error = "invalid TypeScript resolution directory entry";
                goto done;
            }
            entries[used++] = (CFTSDirectoryEntry){text, kind != 0, false};
        }
    }
    /* JS sorts UTF-16; compare basename sets without depending on that ordering. */
    if (count > 1)
        qsort(entries, count, sizeof(*entries), cf_ts_entry_compare);
    for (size_t i = 1; i < count; i++) {
        if (cf_equal(entries[i - 1].name, entries[i].name)) {
            error = "duplicate TypeScript resolution directory entry";
            goto done;
        }
    }
    cbm_dir_t *directory = cbm_opendir(path);
    if (!directory) {
        error = "TypeScript resolution directory unavailable";
        goto done;
    }
    size_t matched = 0;
    cbm_dirent_t *entry;
    while ((entry = cbm_readdir(directory))) {
        if (++*actual_total > CF_MAX_DISCOVERY_PROBES) {
            error = "TypeScript resolution directory budget exceeded";
            break;
        }
        char joined[CF_PATH_SIZE];
        int length = snprintf(joined, sizeof(joined), "%s%s%s", path,
                              path[strlen(path) - 1] == '/' ? "" : "/", entry->name);
        if (length < 0 || (size_t)length >= sizeof(joined) ||
            cf_ts_path_info(joined, &info) != CBM_PATH_INFO_OK) {
            error = "TypeScript resolution directory entry unavailable";
            break;
        }
        if (!info.is_regular && !info.is_directory)
            continue;
        CFTSDirectoryEntry key = {.name = entry->name};
        CFTSDirectoryEntry *expected =
            count ? bsearch(&key, entries, count, sizeof(*entries), cf_ts_entry_compare) : NULL;
        if (!expected || expected->seen || expected->directory != info.is_directory) {
            error = "TypeScript resolution directory changed";
            break;
        }
        expected->seen = true;
        matched++;
    }
    if (!error && (cbm_dir_failed(directory) || matched != count))
        error = "TypeScript resolution directory changed";
    cbm_closedir(directory);
done:
    free(entries);
    return error;
}

static const char *cf_ts_probes(yyjson_val *context, uint64_t *remaining) {
    yyjson_val *projects = yyjson_obj_get(context, "projects");
    size_t i, project_count, total = 0, expected_entries = 0, actual_entries = 0;
    yyjson_val *project;
    yyjson_arr_foreach(projects, i, project_count, project) {
        yyjson_val *probes = yyjson_obj_get(project, "probes");
        if (!yyjson_is_arr(probes))
            return "invalid TypeScript resolution observations";
        if (yyjson_arr_size(probes) > CF_MAX_DISCOVERY_PROBES - total)
            return "TypeScript resolution probe budget exceeded";
        total += yyjson_arr_size(probes);
        size_t j, count;
        yyjson_val *probe;
        yyjson_arr_foreach(probes, j, count, probe) {
            const char *method = cf_str(probe, "method");
            yyjson_val *args = yyjson_obj_get(probe, "args");
            yyjson_val *result = yyjson_obj_get(probe, "result");
            const char *path = cf_string(yyjson_arr_get(args, 0));
            if (!yyjson_is_obj(probe) || yyjson_obj_size(probe) != 3 || !method ||
                !yyjson_is_arr(args) || yyjson_arr_size(args) != 1 || !path || !result)
                return "invalid TypeScript resolution observation";
            if (cf_equal(method, "getEnvironmentVariable")) {
                const char *expected = cf_string(result);
                if (!*path || strlen(path) >= CF_PATH_SIZE || strchr(path, '=') || !expected)
                    return "invalid TypeScript resolution environment observation";
                size_t size = strlen(expected) + 1;
                char *value = malloc(size);
                if (!value)
                    return "out of memory";
                bool current = cf_equal(cbm_native_getenv(path, value, size, ""), expected);
                free(value);
                if (!current)
                    return "TypeScript resolution environment changed";
                continue;
            }
            if (!cf_absolute(path))
                return "invalid TypeScript resolution observation path";
            if (cf_equal(method, "entries")) {
                const char *error = cf_ts_entries(path, result, &expected_entries, &actual_entries);
                if (error)
                    return error;
                continue;
            }
            cbm_path_info_t info;
            int status = cf_ts_path_info(path, &info);
            if (status == CBM_PATH_INFO_UNAVAILABLE)
                return "TypeScript resolution path unavailable";
            if (cf_equal(method, "exists") || cf_equal(method, "fileExists") ||
                cf_equal(method, "directoryExists")) {
                if (!yyjson_is_bool(result))
                    return "invalid TypeScript resolution existence observation";
                bool exists = status == CBM_PATH_INFO_OK &&
                              (cf_equal(method, "exists") ||
                               (cf_equal(method, "fileExists") ? info.is_regular : info.is_directory));
                if (exists != yyjson_is_true(result))
                    return "TypeScript resolution existence changed";
            } else if (cf_equal(method, "canonical") || cf_equal(method, "realpath")) {
                const char *expected = cf_string(result);
                bool canonical = cf_equal(method, "canonical");
                if ((!expected && !(canonical && yyjson_is_null(result))) ||
                    (expected && !cf_absolute(expected)))
                    return "invalid TypeScript resolution path observation";
                char actual[CF_PATH_SIZE];
                if (status == CBM_PATH_INFO_ABSENT) {
                    if (canonical ? !yyjson_is_null(result) : !cf_path_equal(path, expected))
                        return "TypeScript resolution path changed";
                } else if (!expected || !cbm_canonical_path(path, actual, sizeof(actual)) ||
                           !cf_path_equal(actual, expected)) {
                    return "TypeScript resolution path changed";
                }
            } else if (cf_equal(method, "readable")) {
                const char *expected = cf_string(result);
                if (yyjson_is_null(result)) {
                    if (status == CBM_PATH_INFO_OK && info.is_regular)
                        return "TypeScript resolution readable input changed";
                } else {
                    if (!cf_hash(expected))
                        return "invalid TypeScript resolution readable observation";
                    if (status != CBM_PATH_INFO_OK || !info.is_regular || info.size < 0)
                        return "TypeScript resolution readable input changed";
                    if ((uint64_t)info.size > *remaining)
                        return "TypeScript input byte budget exceeded";
                    *remaining -= (uint64_t)info.size;
                    CBMCompilerInput input = {path, expected, (uint64_t)info.size};
                    if (!cf_source_current(path, &input))
                        return "TypeScript resolution readable input changed";
                }
            } else {
                return "unsupported TypeScript resolution observation";
            }
        }
    }
    return NULL;
}

static const char *cf_context(yyjson_val *root, bool go, bool go_index,
                              const CBMCompilerInput *inputs, size_t input_count) {
    yyjson_val *context = yyjson_obj_get(root, "context");
    yyjson_val *cache = yyjson_obj_get(root, "cache");
    if (!yyjson_is_obj(context) || !yyjson_is_obj(cache) || !cf_hash(cf_str(cache, "key")) ||
        !yyjson_is_bool(yyjson_obj_get(cache, "hit")))
        return "invalid context or cache";
    static const char *const hashes[] = {"manifest_sha256", "config_sha256", "source_sha256",
                                         "dependencies_sha256"};
    for (size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
        if (!cf_hash(cf_str(context, hashes[i])))
            return "invalid context fingerprint";
    }
    const char *tool = cf_str(context, "tool_version");
    if (go) {
        yyjson_val *env = yyjson_obj_get(context, "env");
        const char *cgo_policy = cf_str(context, "cgo_policy");
        const char *goos = cf_str(env, "GOOS"), *goarch = cf_str(env, "GOARCH");
        bool native_cgo = go_index && cbm_go_cgo_enabled() && cf_equal(goos, "linux") &&
                          cf_equal(cgo_policy, "explicit-native") &&
                          cf_equal(cf_str(env, "CGO_ENABLED"), "1") &&
                          cf_equal(goos, cf_str(env, "GOHOSTOS")) &&
                          goarch && *goarch && cf_equal(goarch, cf_str(env, "GOHOSTARCH"));
        if (!tool || strncmp(tool, "go1.", 4) != 0 || !isdigit((unsigned char)tool[4]) ||
            !cf_hash(cf_str(context, "helper_sha256")) ||
            !cf_hash(cf_str(context, "tool_sha256")) ||
            !cf_hash(cf_str(context, "exports_sha256")) ||
            (!cf_equal(cgo_policy, "disabled-for-pilot") && !native_cgo) ||
            !yyjson_is_obj(env) ||
            !yyjson_is_arr(yyjson_obj_get(context, "patterns")) ||
            !yyjson_is_arr(yyjson_obj_get(context, "build_flags")))
            return "unsupported Go context";
    } else if (!cf_equal(tool, "5.9.3") || !yyjson_is_obj(yyjson_obj_get(context, "options")) ||
               !yyjson_is_obj(yyjson_obj_get(context, "project"))) {
        return "unsupported TypeScript context";
    } else {
        uint64_t remaining;
        const char *error = cf_ts_discovery(context);
        if (!error)
            error = cf_ts_dependencies(context, inputs, input_count, &remaining, NULL);
        return error ? error : cf_ts_probes(context, &remaining);
    }
    return NULL;
}

static const char *cf_packages(CBMCompilerFacts *facts, yyjson_val *root, bool go) {
    yyjson_val *packages = yyjson_obj_get(root, "packages");
    if (!yyjson_is_arr(packages) || !yyjson_arr_size(packages) ||
        yyjson_arr_size(packages) > CF_MAX_FILES)
        return "invalid packages";
    facts->package_count = yyjson_arr_size(packages);
    facts->packages = calloc(facts->package_count, sizeof(*facts->packages));
    if (!facts->packages)
        return "out of memory";
    for (size_t i = 0; i < facts->package_count; i++) {
        yyjson_val *package = yyjson_arr_get(packages, i);
        const char *id = cf_str(package, "id");
        yyjson_val *ill = yyjson_obj_get(package, "ill_typed");
        yyjson_val *external = yyjson_obj_get(package, "external");
        if (!id || !*id || !cf_str(package, "path") || (go && !yyjson_is_false(ill)) ||
            (ill && !yyjson_is_false(ill)) || !cf_empty_array(package, "errors") ||
            yyjson_obj_get(package, "error") || (!go && !yyjson_is_bool(external)))
            return "ill-typed or invalid package";
        facts->packages[i] = (CFPackage){id, cf_str(package, "path"), yyjson_is_true(external)};
    }
    qsort(facts->packages, facts->package_count, sizeof(*facts->packages), cf_package_compare);
    for (size_t i = 1; i < facts->package_count; i++) {
        if (cf_equal(facts->packages[i - 1].id, facts->packages[i].id))
            return "duplicate package identity";
    }
    return NULL;
}

static bool cf_ref(CFValue object, const char *key, size_t limit) {
    CFValue value = cfv_get(object, key);
    return !value.raw || (cfv_is_uint(value) && cfv_get_uint(value) <= limit);
}

static bool cf_refs(CFValue object, const char *key, size_t limit) {
    CFValue array = cfv_get(object, key);
    if (!array.raw)
        return true;
    if (!cfv_is_arr(array))
        return false;
    size_t i, count;
    CFValue value;
    cfv_foreach(array, i, count, value) {
        if (!cfv_is_uint(value) || cfv_get_uint(value) > limit)
            return false;
    }
    return true;
}

static bool cf_contextual_params(CFValue site, size_t type_count) {
    CFValue array = cfv_get(site, "contextual_params");
    if (!array.raw)
        return true;
    if (!cfv_is_arr(array))
        return false;
    size_t argument_count = cfv_size(cfv_get(site, "arguments"));
    bool *seen = argument_count ? calloc(argument_count, sizeof(*seen)) : NULL;
    if (argument_count && !seen)
        return false;
    bool valid = true;
    size_t i, count;
    CFValue context;
    cfv_foreach(array, i, count, context) {
        CFValue params = cfv_get(context, "parameters");
        uint64_t argument;
        if (!cfv_uint(context, "argument", &argument) || argument >= argument_count ||
            seen[argument] || !cf_ref(context, "type", type_count) || !cfv_is_arr(params)) {
            valid = false;
            break;
        }
        seen[argument] = true;
        size_t j, parameter_count;
        CFValue param;
        cfv_foreach(params, j, parameter_count, param) {
            if (!cfv_str(param, "name") || !cf_ref(param, "type", type_count)) {
                valid = false;
                break;
            }
        }
        if (!valid)
            break;
    }
    free(seen);
    return valid;
}

static bool cf_location(const CBMCompilerFacts *facts, CFValue decl, bool external) {
    uint64_t start, end, ns, ne;
    if (!cfv_is_obj(decl) || !cf_hash(cfv_str(decl, "sha256")) ||
        !cfv_uint(decl, "start", &start) || !cfv_uint(decl, "end", &end) ||
        !cfv_uint(decl, "name_start", &ns) || !cfv_uint(decl, "name_end", &ne) || start > ns ||
        ns >= ne || ne > end || end > UINT32_MAX)
        return false;
    const char *path = cfv_str(decl, "path");
    if (external)
        return cf_absolute(path);
    const CFFile *file = cf_file(facts, path);
    return cf_relative(path) && file && cf_equal(file->sha256, cfv_str(decl, "sha256")) &&
           end <= file->length;
}

static bool cf_charge_auxiliary(CBMCompilerFacts *facts, size_t count, size_t width);

static const char *cf_types(CBMCompilerFacts *facts, CFValue array, size_t symbols, bool go) {
    size_t count = cfv_size(array);
    facts->type_count = count;
    if (!cf_charge_auxiliary(facts, count, sizeof(*facts->types)))
        return "aggregate package projection budget exceeded";
    facts->types = count ? calloc(count, sizeof(*facts->types)) : NULL;
    if (count && !facts->types)
        return "type projection allocation failed";
    static const char *const refs[] = {"underlying", "elem", "key", "receiver"};
    static const char *const arrays[] = {"params", "returns",    "args",
                                         "embeds", "signatures", "type_params"};
    size_t i;
    CFValue type;
    cfv_foreach(array, i, count, type)
        facts->types[i].json = type;
    cfv_foreach(array, i, count, type) {
        uint64_t id;
        if (!cfv_uint(type, "id", &id) || id != i + 1 || !cfv_str(type, "kind"))
            return "invalid type identity";
        if (!cf_ref(type, "origin_symbol", symbols) ||
            (!go && cfv_get(type, "origin_symbol").raw))
            return "invalid type origin";
        for (size_t j = 0; j < sizeof(refs) / sizeof(refs[0]); j++) {
            if (!cf_ref(type, refs[j], count))
                return "invalid type reference";
        }
        for (size_t j = 0; j < sizeof(arrays) / sizeof(arrays[0]); j++) {
            if (!cf_refs(type, arrays[j], count))
                return "invalid type references";
        }
        CFValue parameters = cfv_get(type, "type_params");
        if (parameters.raw) {
            const char *kind = cfv_str(type, "kind");
            if (!(cf_equal(kind, "named") || cf_equal(kind, "alias") || cf_equal(kind, "object")))
                return "invalid generic declaration";
            for (size_t j = 0; j < cfv_size(parameters); j++) {
                size_t parameter = (size_t)cfv_get_uint(cfv_at(parameters, j));
                CFValue entry = parameter ? facts->types[parameter - 1].json : (CFValue){0};
                if (parameter && (!(cf_equal(cfv_str(entry, "kind"), "type_param") ||
                                    cf_equal(cfv_str(entry, "kind"), "type_parameter")) ||
                                  !cfv_str(entry, "name") || !*cfv_str(entry, "name")))
                    return "invalid generic parameter";
            }
        }
        const char *members[] = {"fields", "methods"};
        for (size_t j = 0; j < sizeof(members) / sizeof(members[0]); j++) {
            CFValue list = cfv_get(type, members[j]);
            if (list.raw && !cfv_is_arr(list))
                return "invalid type members";
            size_t k, member_count;
            CFValue member;
            cfv_foreach(list, k, member_count, member) {
                if (!cfv_str(member, "name") || !cf_ref(member, "type", count))
                    return "invalid member reference";
            }
        }
        CFValue decl = cfv_get(type, "declaration");
        if (decl.raw && (go || !cfv_is_bool(cfv_get(decl, "external")) ||
                     !cf_location(facts, decl, cfv_is_true(cfv_get(decl, "external")))))
            return "invalid type declaration";
        CFValue omitted = cfv_get(type, "fields_omitted");
        if (omitted.raw && !cfv_is_uint(omitted))
            return "invalid omitted field count";
        CFValue names = cfv_get(type, "param_names");
        if (names.raw) {
            if (!cfv_is_arr(names) ||
                cfv_size(names) != cfv_size(cfv_get(type, "params")))
                return "invalid parameter names";
            for (size_t j = 0; j < cfv_size(names); j++) {
                if (!cfv_string(cfv_at(names, j)))
                    return "invalid parameter name";
            }
        }
    }
    return NULL;
}

typedef struct {
    CBMCompilerFacts *facts;
    CFDeclaration *items;
    size_t count;
    size_t capacity;
    bool failed;
} CFGraph;

static void cf_graph_node(const cbm_gbuf_node_t *node, void *userdata) {
    CFGraph *graph = userdata;
    const CFFile *file = cf_file(graph->facts, node->file_path);
    if (graph->failed || !file || !node->properties_json || !node->qualified_name)
        return;
    yyjson_doc *doc = yyjson_read(node->properties_json, strlen(node->properties_json), 0);
    yyjson_val *props = doc ? yyjson_doc_get_root(doc) : NULL;
    uint64_t start, end, origin;
    yyjson_val *ambiguous = yyjson_obj_get(props, "decl_ambiguous");
    bool valid = cf_json_shape(props, 0) && cf_uint(props, "name_start_byte", &start) &&
                 cf_uint(props, "name_end_byte", &end) &&
                 cf_uint(props, "name_source_origin", &origin) && origin == 0 && start < end &&
                 end <= file->length && cf_equal(cf_str(props, "source_sha256"), file->sha256);
    if (valid) {
        size_t logical_length = 0;
        uint8_t callable_kind = cf_callable_kind(node->label);
        bool is_ambiguous = ambiguous && !yyjson_is_false(ambiguous);
        yyjson_val *go_marker = yyjson_obj_get(props, "go_physical_decl");
        yyjson_val *go_logical = yyjson_obj_get(props, "go_logical_qn");
        yyjson_val *js_marker = yyjson_obj_get(props, "js_physical_decl");
        yyjson_val *js_logical = yyjson_obj_get(props, "js_logical_qn");
        bool go_physical = go_marker || go_logical || strstr(node->qualified_name, ".@go:");
        bool js_physical = js_marker || js_logical || strstr(node->qualified_name, ".@js:");
        if (go_physical || js_physical) {
            yyjson_val *physical = go_physical ? go_marker : js_marker;
            const char *logical = cf_string(go_physical ? go_logical : js_logical);
            const char *expected = NULL;
            CBMArena scratch;
            cbm_arena_init(&scratch);
            if (go_physical != js_physical && yyjson_is_uint(physical) &&
                yyjson_get_uint(physical) == 1 && callable_kind && end <= UINT32_MAX) {
                if (js_physical) {
                    expected = cbm_compiler_js_declaration_qn(
                        &scratch, logical, file->path, node->label, file->sha256,
                        (uint32_t)start, (uint32_t)end, (uint32_t)origin);
                } else {
                    size_t path_length = strlen(file->path);
                    if (path_length > 3 && strcmp(file->path + path_length - 3, ".go") == 0)
                        expected = cbm_compiler_go_declaration_qn(
                            &scratch, logical, file->path, node->label, file->sha256,
                            (uint32_t)start, (uint32_t)end, (uint32_t)origin);
                }
            }
            if (expected && cf_equal(expected, node->qualified_name) && node->name &&
                strlen(node->name) == end - start)
                logical_length = strlen(logical);
            else
                is_ambiguous = true;
            cbm_arena_destroy(&scratch);
        }
        if (graph->count == graph->capacity) {
            size_t capacity = graph->capacity ? graph->capacity * 2 : 128;
            if (capacity > CF_MAX_SITES) {
                graph->failed = true;
            } else {
                CFDeclaration *items = realloc(graph->items, capacity * sizeof(*items));
                if (!items)
                    graph->failed = true;
                else {
                    graph->items = items;
                    graph->capacity = capacity;
                }
            }
        }
        if (!graph->failed) {
            graph->items[graph->count++] =
                (CFDeclaration){.file = file, .start = (uint32_t)start, .end = (uint32_t)end,
                                .qn = node->qualified_name, .name = node->name,
                                .logical_length = logical_length,
                                .callable_kind = callable_kind,
                                .go_physical = go_physical,
                                .cgo_preamble = cbm_cgo_preamble_qn(node->qualified_name) &&
                                     cf_equal(cf_str(props, CBM_CGO_PREAMBLE_PROPERTY), "true"),
                                .nominal_type = cf_equal(node->label, "Class") ||
                                                cf_equal(node->label, "Interface"),
                                .ambiguous = is_ambiguous};
        }
    }
    yyjson_doc_free(doc);
}

static int cf_declaration_compare(const void *a, const void *b) {
    const CFDeclaration *x = a, *y = b;
    int result = strcmp(x->file->path, y->file->path);
    if (result)
        return result;
    if (x->start != y->start)
        return x->start < y->start ? -1 : 1;
    return x->end == y->end ? 0 : x->end < y->end ? -1 : 1;
}

static const CFDeclaration *cf_graph_declaration(const CBMCompilerFacts *facts, const CFGraph *graph,
                                                CFValue decl) {
    const CFFile *file = cf_file(facts, cfv_str(decl, "path"));
    if (!file || !graph->count)
        return NULL;
    CFDeclaration key = {.file = file,
                         .start = (uint32_t)cfv_get_uint(cfv_get(decl, "name_start")),
                         .end = (uint32_t)cfv_get_uint(cfv_get(decl, "name_end"))};
    const CFDeclaration *match =
        bsearch(&key, graph->items, graph->count, sizeof(*graph->items), cf_declaration_compare);
    if (!match)
        return NULL;
    const CFDeclaration *first = match, *last = match + 1;
    while (first > graph->items && cf_declaration_compare(match, first - 1) == 0)
        first--;
    while (last < graph->items + graph->count && cf_declaration_compare(match, last) == 0)
        last++;
    if (last == first + 1)
        return first->ambiguous ? NULL : first;
    const CFDeclaration *physical = NULL;
    for (const CFDeclaration *item = first; item < last; item++) {
        if (item->logical_length) {
            if (physical || item->ambiguous)
                return NULL;
            physical = item;
        }
    }
    if (!physical)
        return NULL;
    for (const CFDeclaration *item = first; item < last; item++) {
        if (item != physical &&
            (!item->ambiguous || strlen(item->qn) != physical->logical_length ||
             memcmp(item->qn, physical->qn, physical->logical_length) != 0))
            return NULL;
    }
    return physical;
}

static size_t cf_arena_bytes(const CBMCompilerFacts *facts) {
    return facts->package_fragment ? cbm_arena_capacity(&facts->arena)
                                   : cbm_arena_total(&facts->arena);
}

static bool cf_charge_auxiliary(CBMCompilerFacts *facts, size_t count, size_t width) {
    if (!facts->package_fragment)
        return true;
    size_t arena = cf_arena_bytes(facts);
    if ((width && count > SIZE_MAX / width) || arena > facts->type_budget ||
        facts->auxiliary_bytes > facts->type_budget - arena ||
        count * width > facts->type_budget - arena - facts->auxiliary_bytes) {
        facts->projection_failed = true;
        return false;
    }
    facts->auxiliary_bytes += count * width;
    return true;
}

static char *cf_external_method_name(const CBMCompilerFacts *facts, CFValue symbol) {
    uint64_t receiver = cfv_get_uint(cfv_get(symbol, "receiver"));
    for (unsigned depth = 0; receiver && receiver <= facts->type_count && depth < 64; depth++) {
        CFValue type = facts->types[(size_t)receiver - 1].json;
        const char *kind = cfv_str(type, "kind");
        if (cf_equal(kind, "pointer") || cf_equal(kind, "alias")) {
            receiver = cfv_get_uint(
                cfv_get(type, cf_equal(kind, "pointer") ? "elem" : "underlying"));
            continue;
        }
        const char *name = cfv_str(type, "name"), *method = cfv_str(symbol, "name");
        if (!cf_equal(kind, "named") || !name || !*name || !method || !*method ||
            !cf_equal(cfv_str(type, "package"), cfv_str(symbol, "package")))
            return NULL;
        size_t length = strlen(name) + strlen(method) + 2;
        if (length > CF_PATH_SIZE)
            return NULL;
        char *result = malloc(length);
        if (result)
            snprintf(result, length, "%s.%s", name, method);
        return result;
    }
    return NULL;
}

static bool cf_string_member(yyjson_val *array, const char *value);

static bool cf_cgo_native_context(const CFGraph *graph) {
#ifdef __linux__
    yyjson_val *context = yyjson_obj_get(cbm_compiler_facts_json(graph->facts), "context");
    return cf_equal(cf_str(context, "cgo_policy"), "explicit-native") &&
           cf_equal(cf_str(yyjson_obj_get(context, "env"), "GOOS"), "linux");
#else
    (void)graph;
    return false;
#endif
}

static const char *cf_symbols(CBMCompilerFacts *facts, CFValue array, size_t type_count,
                              bool go, const CFGraph *graph) {
    facts->symbol_count = cfv_size(array);
    if (!cf_charge_auxiliary(facts, facts->symbol_count, sizeof(*facts->symbols)))
        return "aggregate package projection budget exceeded";
    facts->symbols =
        facts->symbol_count ? calloc(facts->symbol_count, sizeof(*facts->symbols)) : NULL;
    if (facts->symbol_count && !facts->symbols)
        return "out of memory";
    size_t i, count;
    CFValue symbol;
    cfv_foreach(array, i, count, symbol) {
        CFSymbol *out = &facts->symbols[i];
        uint64_t id;
        if (!cfv_uint(symbol, "id", &id) || id != i + 1 || !cfv_str(symbol, "name") ||
            !cfv_str(symbol, "kind") || !cf_ref(symbol, "type", type_count) ||
            !cf_ref(symbol, "receiver", type_count) ||
            !cf_ref(symbol, "declared_type", type_count) ||
            (cfv_get(symbol, "ambiguous").raw &&
             !cfv_is_bool(cfv_get(symbol, "ambiguous"))))
            return "invalid symbol identity";
        if (cfv_get(symbol, "declared_type").raw &&
            (go || !(cf_equal(cfv_str(symbol, "kind"), "ClassDeclaration") ||
                     cf_equal(cfv_str(symbol, "kind"), "InterfaceDeclaration") ||
                     cf_equal(cfv_str(symbol, "kind"), "TypeAliasDeclaration"))))
            return "invalid declared symbol type";
        out->json = symbol;
        CFValue decl = cfv_get(symbol, "declaration");
        const CFPackage *package = cf_package(facts, cfv_str(symbol, "package_id"));
        if (go) {
            CFValue internal = cfv_get(symbol, "internal");
            if (!cfv_is_bool(internal) || !cfv_str(symbol, "package"))
                return "invalid Go symbol";
            const char *kind = cfv_str(symbol, "kind");
            const char *location_status = cfv_str(symbol, "location_status");
            out->external = !cfv_is_true(internal);
            out->package = cfv_str(symbol, "package");
            out->callable = cf_equal(kind, "function") || cf_equal(kind, "method");
            bool cgo_header = cf_equal(location_status, "cgo_native");
            bool cgo_external = cf_equal(location_status, "cgo_external");
            bool cgo_preamble = cf_equal(location_status, "cgo_preamble");
            out->cgo_native = cgo_header || cgo_external || cgo_preamble;
            const char *declaration_path = cfv_str(decl, "path");
            if (out->cgo_native &&
                (!cf_equal(kind, "function") || !cf_cgo_native_context(graph) ||
                 cfv_get_uint(cfv_get(symbol, "type")) ||
                 cfv_get_uint(cfv_get(symbol, "receiver")) ||
                 (cgo_external ? !out->external || !cf_equal(out->package, "C") || decl.raw ||
                                     cfv_get(symbol, "package_id").raw
                               : out->external || !declaration_path ||
                                     !cf_equal(strrchr(declaration_path, '.'),
                                               cgo_preamble ? ".go" : ".h"))))
                return "invalid cgo native symbol";
            if ((!out->external &&
                 (!package || (!out->cgo_native && !cf_equal(location_status, "exact")))) ||
                (out->external && !cgo_external && !cf_equal(location_status, "export_only")))
                return "invalid symbol provenance";
            if (!out->external && !cf_equal(out->package, package->path))
                return "inconsistent symbol package";
            if (out->external && cf_equal(cfv_str(symbol, "kind"), "method"))
                out->external_name = cf_external_method_name(facts, symbol);
            if (out->external_name &&
                !cf_charge_auxiliary(facts, strlen(out->external_name) + 1, 1))
                return "aggregate package projection budget exceeded";
        } else {
            if (!package || !cfv_is_bool(cfv_get(decl, "external")) ||
                !cfv_is_bool(cfv_get(decl, "excluded")))
                return "invalid TypeScript symbol";
            out->external = cfv_is_true(cfv_get(decl, "external"));
            out->excluded = cfv_is_true(cfv_get(decl, "excluded"));
            out->package = package->id;
            const char *kind = cfv_str(symbol, "kind");
            bool const_function = cf_equal(kind, "ConstFunction");
            if (const_function && (!facts->proof_index || out->external || out->excluded))
                return "invalid TypeScript const function symbol";
            out->callable = cf_equal(kind, "FunctionDeclaration") || const_function;
            if (package->external != out->external || (!out->external && out->excluded))
                return "inconsistent symbol package";
        }
        if ((!out->external || decl.raw) && !cf_location(facts, decl, out->external))
            return "invalid symbol declaration";
        bool preamble = go && cf_equal(cfv_str(symbol, "location_status"), "cgo_preamble");
        if (go && !out->external && (!out->cgo_native || preamble)) {
            yyjson_val *cache = yyjson_obj_get(cbm_compiler_facts_json(graph->facts), "cache");
            yyjson_val *members = yyjson_obj_get(cache, "package_files");
            yyjson_val *paths = yyjson_obj_get(members, cfv_str(symbol, "package_id"));
            if (!cf_string_member(paths, cfv_str(decl, "path")))
                return "symbol declaration package membership differs";
        }
        if (!out->external && !out->excluded) {
            const CFDeclaration *match = cf_graph_declaration(facts, graph, decl);
            if (match && (match->cgo_preamble != preamble ||
                          (out->cgo_native &&
                           (match->logical_length || match->callable_kind != 1 ||
                            !cf_equal(match->name, cfv_str(symbol, "name"))))))
                match = NULL;
            if ((facts->package_fragment || facts->local_target_index ||
                 (match && match->logical_length)) && match &&
                !cf_equal(match->name, cfv_str(symbol, "name")))
                return "package fragment declaration name differs";
            if (match && match->logical_length && match->go_physical != go)
                return "physical declaration language differs";
            if (match && match->logical_length && go &&
                (!out->callable || match->callable_kind !=
                                       (cf_equal(cfv_str(symbol, "kind"), "method") ? 2 : 1)))
                return "physical Go declaration kind differs";
            const char *qn = match ? match->qn : NULL;
            if (qn) {
                if (!cf_charge_auxiliary(facts, strlen(qn) + 1, 1))
                    return "aggregate package projection budget exceeded";
                out->qn = malloc(strlen(qn) + 1);
                if (!out->qn)
                    return "out of memory";
                strcpy(out->qn, qn);
            }
        }
    }
    return NULL;
}

static size_t cf_id(CFValue object, const char *key) {
    return (size_t)cfv_get_uint(cfv_get(object, key));
}

static size_t cf_raw_id(yyjson_val *object, const char *key) {
    return (size_t)yyjson_get_uint(yyjson_obj_get(object, key));
}

static void *cf_type_alloc(CBMCompilerFacts *facts, size_t bytes) {
    if (facts->projection_failed)
        return NULL;
    size_t used = cf_arena_bytes(facts) + facts->auxiliary_bytes;
    if (bytes > facts->type_budget || used > facts->type_budget - bytes) {
        facts->projection_failed = true;
        return NULL;
    }
    void *value = cbm_arena_calloc(&facts->arena, bytes);
    if (!value)
        facts->projection_failed = true;
    return value;
}

static const CBMType *cf_project_type(CBMCompilerFacts *facts, size_t id, unsigned depth);

static const CBMType **cf_project_refs(CBMCompilerFacts *facts, CFValue refs, unsigned depth) {
    size_t count = cfv_size(refs);
    if (count > CF_MAX_IDENTITIES) {
        facts->projection_failed = true;
        return NULL;
    }
    const CBMType **types = cf_type_alloc(facts, (count + 1) * sizeof(*types));
    if (types) {
        for (size_t i = 0; i < count; i++)
            types[i] =
                cf_project_type(facts, (size_t)cfv_get_uint(cfv_at(refs, i)), depth + 1);
    }
    return types;
}

static bool cf_project_members(CBMCompilerFacts *facts, CFValue members, unsigned depth,
                               const char ***names_out, const CBMType ***types_out) {
    size_t count = cfv_size(members);
    if (count > CF_MAX_IDENTITIES) {
        facts->projection_failed = true;
        return false;
    }
    const char **names = cf_type_alloc(facts, (count + 1) * sizeof(*names));
    const CBMType **types = cf_type_alloc(facts, (count + 1) * sizeof(*types));
    if (!names || !types)
        return false;
    size_t i, member_count;
    CFValue member;
    cfv_foreach(members, i, member_count, member) {
        names[i] = cfv_str(member, "name");
        types[i] = cf_project_type(facts, cf_id(member, "type"), depth + 1);
    }
    *names_out = names;
    *types_out = types;
    return true;
}

/* Named recursion terminates at its verified declaration QN; anonymous cycles
 * and depth cuts retain UNKNOWN rather than inventing a nominal identity. */
static const CBMType *cf_project_shape_body(CBMCompilerFacts *facts, CFType *entry, unsigned depth) {
    if (facts->projection_failed)
        return cbm_type_unknown();
    CFValue json = entry->json;
    const char *kind = cfv_str(json, "kind"), *name = cfv_str(json, "name");
    if (facts->proof_index && cf_equal(kind, "object") &&
        cfv_size(cfv_get(json, "unavailable"))) {
        if (cfv_get_uint(cfv_get(json, "fields_omitted")))
            return cbm_type_unknown();
        CFValue signatures = cfv_get(json, "signatures");
        const CBMType *signature = cfv_size(signatures) == 1
            ? cf_project_type(facts, (size_t)cfv_get_uint(cfv_at(signatures, 0)), depth + 1)
            : NULL;
        return signature && signature->kind == CBM_TYPE_FUNC ? signature : cbm_type_unknown();
    }
    if (cf_equal(kind, "builtin") || cf_equal(kind, "primitive") || cf_equal(kind, "type_param") ||
        cf_equal(kind, "type_parameter")) {
        if (!name || !*name)
            return cbm_type_unknown();
        CBMType *type = cf_type_alloc(facts, sizeof(*type));
        if (!type)
            return cbm_type_unknown();
        bool parameter = cf_equal(kind, "type_param") || cf_equal(kind, "type_parameter");
        type->kind = parameter ? CBM_TYPE_TYPE_PARAM : CBM_TYPE_BUILTIN;
        if (parameter)
            type->data.type_param.name = name;
        else
            type->data.builtin.name = name;
        return type;
    }
    if (cf_equal(kind, "named") || cf_equal(kind, "alias"))
        return entry->external ? cf_project_type(facts, cf_id(json, "underlying"), depth + 1)
                               : cbm_type_unknown();
    if (cf_equal(kind, "pointer") || cf_equal(kind, "slice") || cf_equal(kind, "array") ||
        cf_equal(kind, "channel")) {
        const CBMType *elem = cf_project_type(facts, cf_id(json, "elem"), depth + 1);
        if (facts->projection_failed)
            return cbm_type_unknown();
        CBMType *type = cf_type_alloc(facts, sizeof(*type));
        if (!type)
            return cbm_type_unknown();
        if (cf_equal(kind, "pointer")) {
            type->kind = CBM_TYPE_POINTER;
            type->data.pointer.elem = elem;
        } else if (cf_equal(kind, "channel")) {
            type->kind = CBM_TYPE_CHANNEL;
            type->data.channel.elem = elem;
            type->data.channel.direction = (int)cfv_get_sint(cfv_get(json, "direction"));
        } else {
            type->kind = CBM_TYPE_SLICE;
            type->data.slice.elem = elem;
        }
        return type;
    }
    if (cf_equal(kind, "map")) {
        const CBMType *key = cf_project_type(facts, cf_id(json, "key"), depth + 1);
        if (facts->projection_failed)
            return cbm_type_unknown();
        const CBMType *elem = cf_project_type(facts, cf_id(json, "elem"), depth + 1);
        if (facts->projection_failed)
            return cbm_type_unknown();
        CBMType *type = cf_type_alloc(facts, sizeof(*type));
        if (!type)
            return cbm_type_unknown();
        type->kind = CBM_TYPE_MAP;
        type->data.map.key = key;
        type->data.map.value = elem;
        return type;
    }
    if (cf_equal(kind, "signature") || cf_equal(kind, "function")) {
        const CBMType **params = cf_project_refs(facts, cfv_get(json, "params"), depth);
        const CBMType **returns = cf_project_refs(facts, cfv_get(json, "returns"), depth);
        CFValue json_names = cfv_get(json, "param_names");
        size_t count = cfv_size(json_names);
        const char **names = count ? cf_type_alloc(facts, (count + 1) * sizeof(*names)) : NULL;
        for (size_t i = 0; names && i < count; i++)
            names[i] = cfv_string(cfv_at(json_names, i));
        CBMType *type = cf_type_alloc(facts, sizeof(*type));
        if (!type || !params || !returns || (count && !names))
            return cbm_type_unknown();
        type->kind = CBM_TYPE_FUNC;
        type->data.func.param_names = names;
        type->data.func.param_types = params;
        type->data.func.return_types = returns;
        return type;
    }
    if (cf_equal(kind, "tuple") || cf_equal(kind, "union") || cf_equal(kind, "intersection")) {
        CFValue args = cfv_get(json, "args");
        const CBMType **members = cf_project_refs(facts, args, depth);
        if (!members)
            return cbm_type_unknown();
        size_t count = cfv_size(args);
        if (cf_equal(kind, "tuple")) {
            if (facts->projection_failed)
                return cbm_type_unknown();
            CBMType *type = cf_type_alloc(facts, sizeof(*type));
            if (!type)
                return cbm_type_unknown();
            type->kind = CBM_TYPE_TUPLE;
            type->data.tuple.elems = members;
            type->data.tuple.count = (int)count;
            return type;
        }
        /* The shared union constructor drops UNKNOWN, which would turn a
         * truncated `Known | any` into the unsound narrower `Known`. */
        for (size_t i = 0; i < count; i++) {
            if (cbm_type_is_unknown(members[i]))
                return cbm_type_unknown();
        }
        if (!count)
            return cbm_type_unknown();
        if (count == 1)
            return members[0];
        /* The shared constructor's bounded flattening may discard nested
         * members. Retain the complete projected tree instead. */
        CBMType *type = cf_type_alloc(facts, sizeof(*type));
        if (!type)
            return cbm_type_unknown();
        type->kind = cf_equal(kind, "union") ? CBM_TYPE_UNION : CBM_TYPE_INTERSECTION;
        type->data.union_type.members = members;
        type->data.union_type.count = (int)count;
        return type;
    }
    if (cf_equal(kind, "struct") || cf_equal(kind, "object") || cf_equal(kind, "interface")) {
        const char **names = NULL;
        const CBMType **types = NULL;
        bool interface = cf_equal(kind, "interface");
        if (!cf_project_members(facts, cfv_get(json, interface ? "methods" : "fields"),
                                depth, &names, &types))
            return cbm_type_unknown();
        CBMType *type = cf_type_alloc(facts, sizeof(*type));
        if (!type)
            return cbm_type_unknown();
        if (cf_equal(kind, "object")) {
            CFValue signatures = cfv_get(json, "signatures");
            const CBMType *signature =
                cfv_size(signatures) == 1
                    ? cf_project_type(facts, (size_t)cfv_get_uint(cfv_at(signatures, 0)),
                                      depth + 1)
                    : NULL;
            type->kind = CBM_TYPE_OBJECT_LIT;
            type->data.object_lit.prop_names = names;
            type->data.object_lit.prop_types = types;
            type->data.object_lit.call_signature =
                signature && signature->kind == CBM_TYPE_FUNC ? signature : NULL;
            return type;
        }
        type->kind = interface ? CBM_TYPE_INTERFACE : CBM_TYPE_STRUCT;
        if (interface) {
            type->data.interface_type.method_names = names;
            type->data.interface_type.method_sigs = types;
        } else {
            type->data.struct_type.field_names = names;
            type->data.struct_type.field_types = types;
            type->data.struct_type.embedded_types =
                cf_project_refs(facts, cfv_get(json, "embeds"), depth);
        }
        return type;
    }
    return cbm_type_unknown();
}

static const CBMType *cf_project_shape(CBMCompilerFacts *facts, CFType *entry, unsigned depth) {
    if (facts->projection_failed)
        return cbm_type_unknown();
    const CBMType *value = cf_project_shape_body(facts, entry, depth);
    return facts->projection_failed ? cbm_type_unknown() : value;
}

static void cf_projection_child_height(CFProjectionState *state, unsigned depth,
                                       unsigned height) {
    if (depth && (state->active_frames & (UINT64_C(1) << (depth - 1))) &&
        state->frame_heights[depth - 1] < height + 1)
        state->frame_heights[depth - 1] = height + 1;
}

static bool cf_context_matches(const CFProjectionState *state, const CFContextMemo *memo,
                               unsigned depth) {
    if (!memo || !memo->value || memo->depth != depth ||
        memo->active_mask != state->active_frames)
        return false;
    for (unsigned i = 0; i < CF_TYPE_DEPTH; i++)
        if ((memo->active_mask & (UINT64_C(1) << i)) &&
            memo->active_ids[i] != state->frame_ids[i])
            return false;
    return true;
}

static const CBMType *cf_project_type(CBMCompilerFacts *facts, size_t id, unsigned depth) {
    if (!id || id > facts->type_count || facts->projection_failed)
        return cbm_type_unknown();
    if (depth >= CF_TYPE_DEPTH) {
        if (facts->projection_state)
            facts->projection_state->cut_epoch++;
        return cbm_type_unknown();
    }
    CFProjectionState *state = facts->projection_state;
    if (!state) {
        if (facts->type_count > CF_MAX_IDENTITIES) {
            facts->projection_failed = true;
            return cbm_type_unknown();
        }
        size_t bytes = sizeof(*state) + facts->type_count * sizeof(state->memo[0]) +
                       sizeof(facts->projection_state);
        state = cf_type_alloc(facts, bytes);
        if (!state)
            return cbm_type_unknown();
        facts->projection_state = state;
    }
    CFType *entry = &facts->types[id - 1];
    CFIndependentMemo *memo = &state->memo[id - 1];
    bool root = !depth && !state->active_frames;
    if (entry->active) {
        state->cut_epoch++;
        if (!entry->qn || entry->static_type || entry->external)
            return cbm_type_unknown();
        CBMType *type = cf_type_alloc(facts, sizeof(*type));
        if (!type)
            return cbm_type_unknown();
        type->kind = CBM_TYPE_NAMED;
        type->data.named.qualified_name = entry->qn;
        return type;
    }
    if (root && entry->value)
        return entry->value;
    if (memo->value && memo->height <= CF_TYPE_DEPTH - depth) {
        if (root)
            entry->value = memo->value;
        cf_projection_child_height(state, depth, memo->height);
        return memo->value;
    }
    if (cf_context_matches(state, memo->context, depth)) {
        state->cut_epoch++;
        state->context_hits++;
        if (root)
            entry->value = memo->context->value;
        cf_projection_child_height(state, depth, memo->context->height);
        return memo->context->value;
    }
    uint64_t epoch = state->cut_epoch;
    state->frame_heights[depth] = 1;
    state->frame_ids[depth] = id;
    state->active_frames |= UINT64_C(1) << depth;
    entry->active = true;
    const CBMType *value;
    if (entry->qn && !entry->static_type && !entry->external) {
        CBMType *type = cf_type_alloc(facts, sizeof(*type));
        if (!type) {
            entry->active = false;
            state->active_frames &= ~(UINT64_C(1) << depth);
            return cbm_type_unknown();
        }
        if (cf_equal(cfv_str(entry->json, "kind"), "alias")) {
            type->kind = CBM_TYPE_ALIAS;
            type->data.alias.alias_qn = entry->qn;
            type->data.alias.underlying =
                cf_project_type(facts, cf_id(entry->json, "underlying"), depth + 1);
        } else {
            CFValue args = cfv_get(entry->json, "args");
            size_t count = cfv_size(args);
            if (count) {
                type->kind = CBM_TYPE_TEMPLATE;
                type->data.template_type.template_name = entry->qn;
                type->data.template_type.template_args = cf_project_refs(facts, args, depth);
                type->data.template_type.arg_count = (int)count;
            } else {
                type->kind = CBM_TYPE_NAMED;
                type->data.named.qualified_name = entry->qn;
            }
        }
        value = type;
    } else {
        value = cf_project_shape(facts, entry, depth);
        if (entry->external && entry->qn &&
            !(facts->proof_index && cbm_type_is_unknown(value))) {
            CBMType *type = cf_type_alloc(facts, sizeof(*type));
            if (type) {
                type->kind = CBM_TYPE_ALIAS;
                type->data.alias.alias_qn = entry->qn;
                type->data.alias.underlying = value;
                value = type;
            }
        }
    }
    entry->active = false;
    state->active_frames &= ~(UINT64_C(1) << depth);
    if (cf_arena_bytes(facts) + facts->auxiliary_bytes > facts->type_budget)
        facts->projection_failed = true;
    if (facts->projection_failed)
        return cbm_type_unknown();
    if (epoch == state->cut_epoch) {
        memo->value = value;
        memo->height = state->frame_heights[depth];
    } else {
        CFContextMemo *context = memo->context;
        if (!context) {
            context = cf_type_alloc(facts, sizeof(*context));
            if (!context)
                return cbm_type_unknown();
            memo->context = context;
            state->context_count++;
        } else {
            state->context_replacements++;
        }
        context->value = value;
        context->active_mask = state->active_frames;
        context->depth = depth;
        context->height = state->frame_heights[depth];
        for (unsigned i = 0; i < CF_TYPE_DEPTH; i++)
            if (context->active_mask & (UINT64_C(1) << i))
                context->active_ids[i] = state->frame_ids[i];
    }
    if (root)
        entry->value = value;
    cf_projection_child_height(state, depth, state->frame_heights[depth]);
    return value;
}

static bool cf_symbol_is_type(const CFSymbol *symbol) {
    const char *kind = cfv_str(symbol->json, "kind");
    return cf_equal(kind, "type") || cf_equal(kind, "ClassDeclaration") ||
           cf_equal(kind, "InterfaceDeclaration") || cf_equal(kind, "TypeAliasDeclaration");
}

static int cf_binding_compare(const void *left, const void *right) {
    const CFBinding *a = left, *b = right;
    int result = strcmp(a->path, b->path);
    if (!result)
        result = strcmp(a->symbol->qn, b->symbol->qn);
    return result ? result : (int)a->is_type - (int)b->is_type;
}

static CFValue cf_binding_shape(const CBMCompilerFacts *facts, size_t id);

static bool cf_type_equal_at(const CBMType *a, const CBMType *b, unsigned depth, size_t *budget);

static bool cf_type_vectors_equal(const CBMType *const *a, const CBMType *const *b, unsigned depth,
                                  size_t *budget) {
    if (a == b)
        return true;
    for (size_t i = 0;; i++) {
        const CBMType *x = a ? a[i] : NULL, *y = b ? b[i] : NULL;
        if (!x || !y)
            return x == y;
        if (!cf_type_equal_at(x, y, depth + 1, budget))
            return false;
    }
}

static bool cf_name_vectors_equal(const char *const *a, const char *const *b, size_t *budget) {
    if (a == b)
        return true;
    for (size_t i = 0;; i++) {
        const char *x = a ? a[i] : NULL, *y = b ? b[i] : NULL;
        if (!x || !y)
            return x == y;
        if (!*budget || !cf_equal(x, y))
            return false;
        --*budget;
    }
}

/* Shared type equality intentionally uses pointer identity for structural
 * types. Compiler variants need their shapes compared, with a conservative
 * false result when recursion or work exceeds the projection limits. */
static bool cf_type_equal_at(const CBMType *a, const CBMType *b, unsigned depth, size_t *budget) {
    if (a == b)
        return true;
    if (!a || !b || a->kind != b->kind || depth >= CF_TYPE_DEPTH || !*budget)
        return false;
    --*budget;
    switch (a->kind) {
    case CBM_TYPE_UNKNOWN:
        return true;
    case CBM_TYPE_NAMED:
        return cf_equal(a->data.named.qualified_name, b->data.named.qualified_name);
    case CBM_TYPE_BUILTIN:
        return cf_equal(a->data.builtin.name, b->data.builtin.name);
    case CBM_TYPE_TYPE_PARAM:
        return cf_equal(a->data.type_param.name, b->data.type_param.name);
    case CBM_TYPE_POINTER:
        return cf_type_equal_at(a->data.pointer.elem, b->data.pointer.elem, depth + 1, budget);
    case CBM_TYPE_SLICE:
        return cf_type_equal_at(a->data.slice.elem, b->data.slice.elem, depth + 1, budget);
    case CBM_TYPE_MAP:
        return cf_type_equal_at(a->data.map.key, b->data.map.key, depth + 1, budget) &&
               cf_type_equal_at(a->data.map.value, b->data.map.value, depth + 1, budget);
    case CBM_TYPE_CHANNEL:
        return a->data.channel.direction == b->data.channel.direction &&
               cf_type_equal_at(a->data.channel.elem, b->data.channel.elem, depth + 1, budget);
    case CBM_TYPE_FUNC:
        return cf_name_vectors_equal(a->data.func.param_names, b->data.func.param_names, budget) &&
               cf_type_vectors_equal(a->data.func.param_types, b->data.func.param_types, depth,
                                     budget) &&
               cf_type_vectors_equal(a->data.func.return_types, b->data.func.return_types, depth,
                                     budget);
    case CBM_TYPE_TUPLE:
        return a->data.tuple.count == b->data.tuple.count &&
               cf_type_vectors_equal(a->data.tuple.elems, b->data.tuple.elems, depth, budget);
    case CBM_TYPE_TEMPLATE:
        return cf_equal(a->data.template_type.template_name, b->data.template_type.template_name) &&
               a->data.template_type.arg_count == b->data.template_type.arg_count &&
               cf_type_vectors_equal(a->data.template_type.template_args,
                                     b->data.template_type.template_args, depth, budget);
    case CBM_TYPE_ALIAS:
        return cf_equal(a->data.alias.alias_qn, b->data.alias.alias_qn) &&
               cf_type_equal_at(a->data.alias.underlying, b->data.alias.underlying, depth + 1,
                                budget);
    case CBM_TYPE_UNION:
    case CBM_TYPE_INTERSECTION:
        return a->data.union_type.count == b->data.union_type.count &&
               cf_type_vectors_equal(a->data.union_type.members, b->data.union_type.members, depth,
                                     budget);
    case CBM_TYPE_STRUCT:
        return cf_name_vectors_equal(a->data.struct_type.field_names,
                                     b->data.struct_type.field_names, budget) &&
               cf_type_vectors_equal(a->data.struct_type.field_types,
                                     b->data.struct_type.field_types, depth, budget) &&
               cf_type_vectors_equal(a->data.struct_type.embedded_types,
                                     b->data.struct_type.embedded_types, depth, budget);
    case CBM_TYPE_INTERFACE:
        return cf_name_vectors_equal(a->data.interface_type.method_names,
                                     b->data.interface_type.method_names, budget) &&
               cf_type_vectors_equal(a->data.interface_type.method_sigs,
                                     b->data.interface_type.method_sigs, depth, budget);
    case CBM_TYPE_OBJECT_LIT:
        return cf_name_vectors_equal(a->data.object_lit.prop_names, b->data.object_lit.prop_names,
                                     budget) &&
               cf_type_vectors_equal(a->data.object_lit.prop_types, b->data.object_lit.prop_types,
                                     depth, budget) &&
               cf_type_equal_at(a->data.object_lit.call_signature,
                                b->data.object_lit.call_signature, depth + 1, budget) &&
               cf_type_equal_at(a->data.object_lit.index_value, b->data.object_lit.index_value,
                                depth + 1, budget);
    default:
        return false;
    }
}

static bool cf_types_equal(const CBMType *a, const CBMType *b) {
    size_t budget = CF_MAX_IDENTITIES;
    return cf_type_equal_at(a, b, 0, &budget);
}

static const CBMType *cf_binding_compare_type(CBMCompilerFacts *facts, const CFBinding *binding) {
    if (!binding->is_type)
        return cbm_compiler_facts_type(facts, binding->type_id);
    CFValue json = cf_binding_shape(facts, binding->type_id);
    if (!json.raw)
        return cbm_type_unknown();
    CFType *type = &facts->types[cf_id(json, "id") - 1];
    if (!type->shape_value)
        type->shape_value = cf_project_shape(facts, type, 0);
    return type->shape_value;
}

static const char *cf_project_types(CBMCompilerFacts *facts, CFValue array, bool go,
                                    const CFGraph *graph) {
    cbm_arena_init_lazy(&facts->arena, CBM_ARENA_DEFAULT_BLOCK_SIZE);
    facts->type_count = cfv_size(array);
    if (!cf_charge_auxiliary(facts, facts->symbol_count, sizeof(*facts->bindings)))
        return "aggregate package projection budget exceeded";
    facts->bindings =
        facts->symbol_count ? calloc(facts->symbol_count, sizeof(*facts->bindings)) : NULL;
    if ((facts->type_count && !facts->types) || (facts->symbol_count && !facts->bindings))
        return "type projection allocation failed";
    size_t i, count;
    CFValue json;
    cfv_foreach(array, i, count, json) {
        CFType *type = &facts->types[i];
        type->json = json;
        if (go) {
            size_t origin = cf_id(type->json, "origin_symbol");
            if (!origin)
                continue;
            const CFSymbol *symbol = &facts->symbols[origin - 1];
            const char *kind = cfv_str(type->json, "kind");
            if (!(cf_equal(kind, "named") || cf_equal(kind, "alias")) ||
                !cf_equal(cfv_str(symbol->json, "kind"), "type") ||
                !cf_equal(cfv_str(type->json, "name"), cfv_str(symbol->json, "name")) ||
                !cf_equal(cfv_str(type->json, "package"), symbol->package))
                return "type origin does not name its declaration";
            type->external = symbol->external;
            type->qn = symbol->external
                           ? cbm_arena_sprintf(&facts->arena, "@compiler.go:%s.%s", symbol->package,
                                               cfv_str(symbol->json, "name"))
                           : symbol->qn;
            if (symbol->external && !type->qn)
                return "type identity allocation failed";
        } else {
            CFValue decl = cfv_get(type->json, "declaration");
            const char *role = cfv_str(type->json, "nominal_role");
            if (facts->proof_index && cf_equal(role, "value"))
                type->static_type = true;
            type->external = cfv_is_true(cfv_get(decl, "external"));
            if (type->external) {
                type->qn = cbm_arena_sprintf(&facts->arena, "@compiler.ts:%s:%llu:%llu",
                                             cfv_str(decl, "path"),
                                             (unsigned long long)cf_id(decl, "name_start"),
                                             (unsigned long long)cf_id(decl, "name_end"));
                if (!type->qn)
                    return "type identity allocation failed";
            } else if (decl.raw && !cfv_is_true(cfv_get(decl, "excluded"))) {
                const CFDeclaration *match = cf_graph_declaration(facts, graph, decl);
                const char *qn = match && !match->logical_length &&
                                         (!facts->proof_index ||
                                          (cf_equal(role, "instance") && match->nominal_type))
                                     ? match->qn : NULL;
                type->qn = qn ? cbm_arena_strdup(&facts->arena, qn) : NULL;
                if (qn && !type->qn)
                    return "type identity allocation failed";
            }
        }
        if (cf_arena_bytes(facts) + facts->auxiliary_bytes > facts->type_budget)
            return "aggregate package projection budget exceeded";
    }
    for (size_t i = 0; i < facts->symbol_count; i++) {
        const CFSymbol *symbol = &facts->symbols[i];
        size_t type_id = cf_id(symbol->json, "type");
        size_t declared = cf_id(symbol->json, "declared_type");
        if (!go && declared != type_id && type_id &&
            cf_equal(cfv_str(symbol->json, "kind"), "ClassDeclaration"))
            facts->types[type_id - 1].static_type = true;
        if (!symbol->qn || symbol->cgo_native || cfv_is_true(cfv_get(symbol->json, "ambiguous")) ||
            (!symbol->callable && !cf_symbol_is_type(symbol)))
            continue;
        facts->bindings[facts->binding_count++] =
            (CFBinding){.path = cfv_str(cfv_get(symbol->json, "declaration"), "path"),
                        .symbol = symbol,
                        .type_id = cf_symbol_is_type(symbol) && !go ? declared : type_id,
                        .is_type = cf_symbol_is_type(symbol)};
    }
    if (!go) {
        const char **nominal =
            facts->binding_count ? malloc(facts->binding_count * sizeof(*nominal)) : NULL;
        if (facts->binding_count && !nominal)
            return "type identity allocation failed";
        size_t count = 0;
        for (size_t i = 0; i < facts->binding_count; i++) {
            if (facts->bindings[i].is_type)
                nominal[count++] = facts->bindings[i].symbol->qn;
        }
        if (count > 1)
            qsort(nominal, count, sizeof(*nominal), cf_string_compare);
        for (size_t i = 0; i < facts->type_count; i++) {
            CFType *type = &facts->types[i];
            if (type->qn && !type->external &&
                !(facts->proof_index &&
                  cf_equal(cfv_str(type->json, "nominal_role"), "instance")) &&
                (!count ||
                 !bsearch(&type->qn, nominal, count, sizeof(*nominal), cf_string_compare)))
                type->qn = NULL;
        }
        free(nominal);
    }
    for (size_t i = 0; i < facts->type_count; i++)
        (void)cf_project_type(facts, i + 1, 0);
    if (facts->projection_failed)
        return "type projection budget or allocation failed";
    if (facts->binding_count > 1)
        qsort(facts->bindings, facts->binding_count, sizeof(*facts->bindings), cf_binding_compare);
    /* Multiple variants may describe the same declaration. Conflicting type
     * shapes must not overwrite a native entry with an arbitrary variant. */
    for (size_t i = 0; i < facts->binding_count;) {
        size_t end = i + 1;
        bool ambiguous = false;
        while (end < facts->binding_count &&
               cf_binding_compare(&facts->bindings[i], &facts->bindings[end]) == 0) {
            if (!cf_types_equal(cf_binding_compare_type(facts, &facts->bindings[i]),
                                cf_binding_compare_type(facts, &facts->bindings[end])))
                ambiguous = true;
            end++;
        }
        for (size_t j = i; j < end; j++)
            facts->bindings[j].ambiguous = ambiguous;
        i = end;
    }
    return facts->projection_failed ? "type projection budget or allocation failed" : NULL;
}

static bool cf_dispatch(const char *dispatch) {
    static const char *const values[] = {"static",  "external", "interface", "function_value",
                                         "dynamic", "unknown",  "builtin",   "conversion"};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        if (cf_equal(dispatch, values[i]))
            return true;
    }
    return false;
}

static int cf_row_compare(const void *a, const void *b) {
    const CBMCompilerSite *x = &((const CFRow *)a)->site, *y = &((const CFRow *)b)->site;
    int result = strcmp(x->path, y->path);
    if (result)
        return result;
    if (x->start_byte != y->start_byte)
        return x->start_byte < y->start_byte ? -1 : 1;
    return x->end_byte == y->end_byte ? 0 : x->end_byte < y->end_byte ? -1 : 1;
}

static bool cf_same_target(const CFRow *a, const CFRow *b) {
    if (!cf_equal(a->site.dispatch, b->site.dispatch) ||
        !cf_equal(a->site.target_qn, b->site.target_qn) ||
        !cf_equal(a->site.target_package, b->site.target_package) ||
        !cf_equal(a->site.symbol_name, b->site.symbol_name) ||
        a->site.external_symbol != b->site.external_symbol ||
        a->site.proof_partial != b->site.proof_partial ||
        a->site.target_authoritative != b->site.target_authoritative ||
        a->site.types_authoritative != b->site.types_authoritative ||
        a->site.callee_start_byte != b->site.callee_start_byte ||
        a->site.callee_end_byte != b->site.callee_end_byte ||
        !cf_types_equal(a->site.type, b->site.type) ||
        !cf_types_equal(a->site.signature, b->site.signature) ||
        !cf_types_equal(a->site.receiver, b->site.receiver) ||
        a->site.contextual_param_count != b->site.contextual_param_count)
        return false;
    for (size_t i = 0; i < a->site.contextual_param_count; i++) {
        const CBMCompilerContextParams *x = &a->site.contextual_params[i];
        const CBMCompilerContextParams *y = &b->site.contextual_params[i];
        if (x->argument != y->argument || x->parameter_count != y->parameter_count)
            return false;
        for (size_t j = 0; j < x->parameter_count; j++) {
            if (!cf_equal(x->param_names[j], y->param_names[j]) ||
                !cf_types_equal(x->param_types[j], y->param_types[j]))
                return false;
        }
    }
    if (a->symbol == b->symbol)
        return true;
    if (!a->symbol || !b->symbol)
        return false;
    CFValue x = a->symbol->json, y = b->symbol->json;
    if (!cf_equal(cfv_str(x, "name"), cfv_str(y, "name")) ||
        !cf_equal(cfv_str(x, "kind"), cfv_str(y, "kind")))
        return false;
    x = cfv_get(x, "declaration");
    y = cfv_get(y, "declaration");
    if (!x.raw || !y.raw)
        return x.raw == y.raw;
    return cf_equal(cfv_str(x, "path"), cfv_str(y, "path")) &&
           cf_equal(cfv_str(x, "sha256"), cfv_str(y, "sha256")) &&
           cfv_get_uint(cfv_get(x, "name_start")) ==
               cfv_get_uint(cfv_get(y, "name_start")) &&
           cfv_get_uint(cfv_get(x, "name_end")) ==
               cfv_get_uint(cfv_get(y, "name_end"));
}

/* These byte anchors identify the same declaration used by gen-ts-lib.mjs.
 * shortcut: another Playwright version keeps its structural projection until
 * its declaration can be matched to the bundled library. */
static bool cf_ts_playwright_declaration(CFValue decl) {
    const char *path = cfv_str(decl, "path");
    static const char suffix[] = "/node_modules/playwright-core/types/types.d.ts";
    size_t length = path ? strlen(path) : 0;
    return length >= sizeof(suffix) - 1 &&
           strcmp(path + length - (sizeof(suffix) - 1), suffix) == 0 &&
           cfv_is_true(cfv_get(decl, "external")) &&
           !cfv_is_true(cfv_get(decl, "excluded")) &&
           cf_equal(cfv_str(decl, "sha256"),
                    "6c688250f2b7061cec3a17ab8797671137b653f8c4e81a6df3190cb112a7579a");
}

static bool cf_ts_playwright_route_callback(const CBMCompilerFacts *facts,
                                             const CBMCompilerSite *site, CFValue json) {
    size_t target = cf_id(json, "target_symbol");
    if (!facts->proof_index || !site->target_authoritative || !site->types_authoritative ||
        !cf_equal(site->dispatch, "external") || !target || target > facts->symbol_count)
        return false;
    CFValue symbol = facts->symbols[target - 1].json;
    CFValue decl = cfv_get(symbol, "declaration");
    return cf_equal(cfv_str(symbol, "kind"), "MethodSignature") &&
           cf_equal(cfv_str(symbol, "name"), "route") && cf_ts_playwright_declaration(decl) &&
           cf_id(decl, "name_start") == 198417 && cf_id(decl, "name_end") == 198422;
}

static const char *cf_ts_playwright_callback_qn(CFValue type, size_t position) {
    CFValue decl = cfv_get(type, "declaration");
    if (!cf_equal(cfv_str(type, "kind"), "object") ||
        !cf_equal(cfv_str(type, "nominal_role"), "instance") || !cf_ts_playwright_declaration(decl))
        return NULL;
    const size_t start = cf_id(decl, "name_start"), end = cf_id(decl, "name_end");
    if (position == 0 && start == 970337 && end == 970342)
        return "__cbm_lib.playwright.Route";
    if (position == 1 && start == 955528 && end == 955535)
        return "__cbm_lib.playwright.Request";
    return NULL;
}

static bool cf_project_contexts(CBMCompilerFacts *facts, CBMCompilerSite *site, CFValue json) {
    CFValue contexts = cfv_get(json, "contextual_params");
    size_t count = cfv_size(contexts);
    if (!count)
        return true;
    CBMCompilerContextParams *out = cf_type_alloc(facts, count * sizeof(*out));
    if (!out)
        return false;
    bool playwright_route = cf_ts_playwright_route_callback(facts, site, json);
    size_t i, context_count;
    CFValue context;
    cfv_foreach(contexts, i, context_count, context) {
        CFValue params = cfv_get(context, "parameters");
        out[i].argument = cf_id(context, "argument");
        out[i].parameter_count = cfv_size(params);
        if (!cf_project_members(facts, params, 0, &out[i].param_names, &out[i].param_types))
            return false;
        if (playwright_route && out[i].argument == 1) {
            for (size_t j = 0; j < out[i].parameter_count && j < 2; j++) {
                size_t id = cf_id(cfv_at(params, j), "type");
                const char *qn = id && id <= facts->type_count
                    ? cf_ts_playwright_callback_qn(facts->types[id - 1].json, j) : NULL;
                if (qn) {
                    CBMType *type = cf_type_alloc(facts, sizeof(*type));
                    if (!type)
                        return false;
                    type->kind = CBM_TYPE_NAMED;
                    type->data.named.qualified_name = qn;
                    out[i].param_types[j] = type;
                }
            }
        }
    }
    site->contextual_params = out;
    site->contextual_param_count = count;
    return true;
}

static bool cf_cgo_call(const char *root, const CFFile *file, const CFSymbol *symbol,
                        uint32_t start, uint32_t end) {
    const char *name = cfv_str(symbol->json, "name");
    if (!root || !*root || !name || end - start != strlen(name) + 2 ||
        !cf_equal(strrchr(file->path, '.'), ".go"))
        return false;
    if (!symbol->external) {
        const char *header = cfv_str(cfv_get(symbol->json, "declaration"), "path");
        bool preamble = cf_equal(cfv_str(symbol->json, "location_status"), "cgo_preamble");
        if (preamble && !cf_equal(file->path, header))
            return false;
        const char *slash = strrchr(file->path, '/'), *header_slash = strrchr(header, '/');
        size_t directory = slash ? (size_t)(slash - file->path) + 1 : 0;
        size_t header_directory = header_slash ? (size_t)(header_slash - header) + 1 : 0;
        if (directory != header_directory || memcmp(file->path, header, directory) != 0)
            return false;
    }
    char joined[CF_PATH_SIZE], actual[CF_PATH_SIZE];
    cbm_path_info_t info;
    int n = snprintf(joined, sizeof(joined), "%s%s%s", root,
                     root[strlen(root) - 1] == '/' ? "" : "/", file->path);
    if (n < 0 || (size_t)n >= sizeof(joined) ||
        !cbm_canonical_path(joined, actual, sizeof(actual)) || !cf_path_equal(joined, actual) ||
        cbm_path_info_utf8(actual, &info) != CBM_PATH_INFO_OK || !info.is_regular ||
        info.size < 0 || (uint64_t)info.size != file->length)
        return false;
    FILE *source = cbm_fopen(actual, "rb");
    if (!source)
        return false;
    bool valid = fseek(source, (long)start, SEEK_SET) == 0 &&
                 fgetc(source) == 'C' && fgetc(source) == '.';
    for (const unsigned char *p = (const unsigned char *)name; valid && *p; p++)
        valid = fgetc(source) == *p;
    fclose(source);
    return valid;
}

static const char *cf_sites(CBMCompilerFacts *facts, CFValue sites, size_t type_count,
                             bool go, bool project_contexts, const char *cgo_root) {
    size_t count = cfv_size(sites);
    if (facts->chunk_fragment &&
        !cf_charge_auxiliary(facts, count, sizeof(*facts->rows)))
        return "chunk site projection budget exceeded";
    facts->rows = count ? calloc(count, sizeof(*facts->rows)) : NULL;
    /* Chunk consensus builds the complete alias index from all fragment rows. */
    facts->matches =
        count && !facts->chunk_fragment ? malloc(count * 2 * sizeof(*facts->matches)) : NULL;
    if (count && (!facts->rows || (!facts->chunk_fragment && !facts->matches)))
        return "out of memory";
    facts->match_count = facts->chunk_fragment ? 0 : count * 2;
    size_t i, site_count;
    CFValue site;
    cfv_foreach(sites, i, site_count, site) {
        CFRow *row = &facts->rows[i];
        const CFFile *file = cf_file(facts, cfv_str(site, "path"));
        const CFPackage *package = cf_package(facts, cfv_str(site, "package_id"));
        uint64_t start, end, cs, ce;
        if (!file || !package || package->external ||
            !cf_equal(cfv_str(site, "sha256"), file->sha256) || !cfv_uint(site, "start", &start) ||
            !cfv_uint(site, "end", &end) || !cfv_uint(site, "callee_start", &cs) ||
            !cfv_uint(site, "callee_end", &ce) || start > cs || cs >= ce || ce > end ||
            end > file->length || !cf_dispatch(cfv_str(site, "dispatch")) ||
            !cf_ref(site, "target_symbol", facts->symbol_count) ||
            !cf_ref(site, "type", type_count) || !cf_ref(site, "signature", type_count) ||
            !cf_ref(site, "receiver", type_count) || !cf_refs(site, "args", type_count) ||
            !cf_refs(site, "arguments", type_count) || !cf_contextual_params(site, type_count))
            return "invalid call site or reference";
        row->site =
            (CBMCompilerSite){.path = file->path,
                              .sha256 = file->sha256,
                              .start_byte = (uint32_t)start,
                              .end_byte = (uint32_t)end,
                              .callee_start_byte = (uint32_t)cs,
                              .callee_end_byte = (uint32_t)ce,
                              .dispatch = cfv_str(site, "dispatch"),
                              .target_package = cfv_str(site, "target_package"),
                              .reason = cfv_str(site, "reason"),
                               .proof_partial = facts->proof_index,
                               .target_authoritative = facts->proof_index &&
                                   cf_equal(cf_str(yyjson_obj_get(cfv_get(site, "proof").raw,
                                                                 "target"), "status"), "available"),
                               .types_authoritative = facts->proof_index &&
                                   cf_equal(cf_str(yyjson_obj_get(cfv_get(site, "proof").raw,
                                                                 "types"), "status"), "available"),
                              .type = cbm_compiler_facts_type(facts, cf_id(site, "type")),
                              .signature = cbm_compiler_facts_type(facts, cf_id(site, "signature")),
                              .receiver = cbm_compiler_facts_type(facts, cf_id(site, "receiver"))};
        if (project_contexts && !cf_project_contexts(facts, &row->site, site))
            return "contextual type projection failed";
        uint64_t target = cfv_get_uint(cfv_get(site, "target_symbol"));
        if (target) {
            row->symbol = &facts->symbols[target - 1];
            const CFSymbol *symbol = row->symbol;
            if (symbol->cgo_native &&
                (!cf_equal(row->site.dispatch, "static") ||
                 (!symbol->external && !cf_equal(package->id, cfv_str(symbol->json, "package_id"))) ||
                 !cf_cgo_call(cgo_root, file, symbol, (uint32_t)cs, (uint32_t)ce)))
                return "invalid cgo native call";
            const char *authority = cfv_str(cfv_get(cfv_get(site, "proof"), "target"), "reason");
            if (cf_equal(cfv_str(symbol->json, "kind"), "ConstFunction") &&
                (!row->site.target_authoritative ||
                 !(cf_equal(authority, "lexical_target") || cf_equal(authority, "browser_page_context"))))
                return "invalid TypeScript const function proof authority";
            if (row->site.target_package && *row->site.target_package &&
                !cf_equal(row->site.target_package, symbol->package))
                return "call target package differs";
            row->site.target_package = symbol->package;
            row->site.symbol_name =
                symbol->external_name ? symbol->external_name : cfv_str(symbol->json, "name");
            row->site.external_symbol = symbol->external && !symbol->excluded;
            if (symbol->external && cf_equal(cfv_str(symbol->json, "kind"), "method") &&
                !symbol->external_name) {
                row->site.dispatch = "unknown";
                row->site.reason = "external_receiver_not_admitted";
                row->site.external_symbol = false;
                row->site.symbol_name = NULL;
            }
            if (cf_equal(row->site.dispatch, "static") && !symbol->external) {
                if (!symbol->callable)
                    return "static target is not callable";
                if (symbol->qn)
                    row->site.target_qn = symbol->qn;
                else {
                    row->site.dispatch = "unknown";
                    row->site.reason = "declaration_not_unique";
                }
            }
        } else if (cf_equal(row->site.dispatch, "static") ||
                   cf_equal(row->site.dispatch, "external")) {
            return "static call has no target";
        }
        if (cf_equal(row->site.dispatch, "external") && !row->site.external_symbol)
            return "external call has internal target";
        if (row->symbol && row->symbol->excluded) {
            row->site.dispatch = "unknown";
            row->site.reason = "declaration_not_admitted";
            row->site.target_qn = NULL;
        }
        CFValue handler = cfv_get(site, "handler_symbol");
        if (handler.raw) {
            uint64_t id = cfv_get_uint(handler);
            if (!go || !cfv_is_uint(handler) || !id || id > facts->symbol_count ||
                !row->site.external_symbol || !cf_equal(row->site.dispatch, "static") ||
                !cf_equal(row->site.target_package, "net/http") ||
                !(cf_equal(row->site.symbol_name, "HandleFunc") ||
                  cf_equal(row->site.symbol_name, "ServeMux.HandleFunc")))
                return "invalid route handler proof";
            const CFSymbol *callback = &facts->symbols[id - 1];
            if (!callback->callable || callback->external || callback->excluded ||
                callback->cgo_native)
                return "route handler is not an internal callable";
            row->site.route_handler_qn = callback->qn;
        }
    }
    if (count > 1)
        qsort(facts->rows, count, sizeof(*facts->rows), cf_row_compare);
    for (size_t i = 0; i < count;) {
        CFRow *row = &facts->rows[i];
        size_t next = i + 1;
        bool conflict = false;
        while (next < count && cf_row_compare(row, &facts->rows[next]) == 0) {
            if (!cf_same_target(row, &facts->rows[next]))
                conflict = true;
            if (!cf_equal(row->site.route_handler_qn, facts->rows[next].site.route_handler_qn))
                row->site.route_handler_qn = NULL;
            next++;
        }
        if (conflict) {
            row->site.dispatch = "unknown";
            row->site.reason = "variant_conflict";
            row->site.target_qn = NULL;
            row->site.external_symbol = false;
            row->site.target_package = NULL;
            row->site.symbol_name = NULL;
            row->site.route_handler_qn = NULL;
            row->site.type = cbm_type_unknown();
            row->site.signature = cbm_type_unknown();
            row->site.receiver = cbm_type_unknown();
            row->site.contextual_params = NULL;
            row->site.contextual_param_count = 0;
            row->site.types_authoritative = false;
        }
        for (size_t j = i; !facts->chunk_fragment && j < next; j++) {
            const CBMCompilerSite *site = &facts->rows[j].site;
            facts->matches[j * 2] = (CFMatch){site->path, site->sha256, site->start_byte,
                                              site->end_byte, facts->row_count};
            facts->matches[j * 2 + 1] = (CFMatch){site->path, site->sha256, site->callee_start_byte,
                                                  site->callee_end_byte, facts->row_count};
        }
        facts->rows[facts->row_count++] = *row;
        i = next;
    }
    return NULL;
}

static int cf_match_compare(const void *a, const void *b) {
    const CFMatch *x = a, *y = b;
    int result = strcmp(x->path, y->path);
    if (!result)
        result = strcmp(x->sha256, y->sha256);
    if (result)
        return result;
    if (x->start != y->start)
        return x->start < y->start ? -1 : 1;
    return x->end == y->end ? 0 : x->end < y->end ? -1 : 1;
}

static const char *cf_matches(CBMCompilerFacts *facts, size_t conflict_budget_bytes) {
    size_t count = facts->match_count, conflict_count = 0;
    facts->match_count = 0;
    if (count > 1)
        qsort(facts->matches, count, sizeof(*facts->matches), cf_match_compare);
    for (size_t i = 0; i < count;) {
        CFMatch match = facts->matches[i];
        size_t next = i + 1;
        while (next < count && cf_match_compare(&match, &facts->matches[next]) == 0) {
            if (match.site != facts->matches[next].site)
                match.site = SIZE_MAX;
            next++;
        }
        if (match.site == SIZE_MAX)
            conflict_count++;
        facts->matches[facts->match_count++] = match;
        i = next;
    }
    if (conflict_count > conflict_budget_bytes / sizeof(*facts->conflicts))
        return "chunk conflict projection budget exceeded";
    facts->conflicts = conflict_count ? calloc(conflict_count, sizeof(*facts->conflicts)) : NULL;
    if (conflict_count && !facts->conflicts)
        return "out of memory";
    conflict_count = 0;
    for (size_t i = 0; i < facts->match_count; i++) {
        CFMatch *match = &facts->matches[i];
        if (match->site != SIZE_MAX)
            continue;
        facts->conflicts[conflict_count] = (CBMCompilerSite){.path = match->path,
                                                             .sha256 = match->sha256,
                                                             .start_byte = match->start,
                                                             .end_byte = match->end,
                                                             .callee_start_byte = match->start,
                                                             .callee_end_byte = match->end,
                                                             .dispatch = "unknown",
                                                              .reason = "site_span_conflict",
                                                              .proof_partial = facts->proof_index};
        match->site = facts->row_count + conflict_count++;
    }
    return NULL;
}

static bool cf_local_member(yyjson_val *array, const char *text) {
    size_t low = 0, high = yyjson_arr_size(array);
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        int order = strcmp(cf_string(yyjson_arr_get(array, middle)), text);
        if (order < 0)
            low = middle + 1;
        else
            high = middle;
    }
    return low < yyjson_arr_size(array) &&
           cf_equal(cf_string(yyjson_arr_get(array, low)), text);
}

static bool cf_local_contexts(yyjson_val *projects, yyjson_val *contexts, const char *path) {
    if (!yyjson_is_arr(contexts) || !yyjson_arr_size(contexts))
        return false;
    size_t applicable = 0;
    for (size_t p = 0; p < yyjson_arr_size(projects); p++) {
        yyjson_val *project = yyjson_arr_get(projects, p);
        if (!cf_local_member(yyjson_obj_get(project, "analyzed_files"), path))
            continue;
        size_t matches = 0;
        for (size_t c = 0; c < yyjson_arr_size(contexts); c++)
            matches += cf_equal(cf_string(yyjson_arr_get(contexts, c)), cf_str(project, "id"));
        if (matches != 1)
            return false;
        applicable++;
    }
    return applicable && applicable == yyjson_arr_size(contexts);
}

static bool cf_local_diagnostic(const CBMCompilerFacts *facts, yyjson_val *item,
                                const char *root, const char *context) {
    uint64_t code, start, end;
    const char *path = cf_str(item, "path"), *message = cf_str(item, "message");
    size_t root_length = strlen(root);
    const CFFile *file = path && strlen(path) > root_length &&
                                 strncmp(path, root, root_length) == 0 &&
                                 path[root_length] == '/'
                             ? cf_file(facts, path + root_length + 1)
                             : NULL;
    return file && cf_uint(item, "code", &code) && code && code <= UINT32_MAX &&
           cf_equal(cf_str(item, "category"), "Error") && message && *message &&
           cf_equal(cf_str(item, "context"), context) && cf_uint(item, "start", &start) &&
           cf_uint(item, "end", &end) && start <= end && end <= file->length;
}

static const char *cf_local_envelope(CBMCompilerFacts *facts, yyjson_val *root,
                                    const char *canonical) {
    yyjson_val *summary = yyjson_obj_get(root, "summary");
    yyjson_val *diagnostics = yyjson_obj_get(root, "diagnostics");
    yyjson_val *projects = yyjson_obj_get(yyjson_obj_get(root, "context"), "projects");
    uint64_t observed, accepted, diagnostic_count;
    if (!cf_equal(cf_str(root, "profile"), "lexical_target_v1") ||
        !cf_equal(cf_str(root, "status"), "partial") ||
        !yyjson_is_false(yyjson_obj_get(root, "complete")) || !cf_empty_array(root, "errors") ||
        !yyjson_is_arr(diagnostics) || !yyjson_arr_size(diagnostics) ||
        !cf_uint(summary, "observed_calls", &observed) || observed > UINT32_MAX ||
        !cf_uint(summary, "accepted_calls", &accepted) ||
        accepted != yyjson_arr_size(yyjson_obj_get(root, "sites")) || observed < accepted ||
        accepted > 100000 || yyjson_arr_size(yyjson_obj_get(root, "symbols")) > 20000 ||
        !cf_uint(summary, "diagnostic_count", &diagnostic_count) ||
        diagnostic_count != yyjson_arr_size(diagnostics) ||
        !yyjson_is_arr(yyjson_obj_get(root, "types")) ||
        yyjson_arr_size(yyjson_obj_get(root, "types")))
        return "invalid TypeScript local target summary or profile";
    const char **ids = malloc(yyjson_arr_size(projects) * sizeof(*ids));
    if (!ids)
        return "out of memory";
    const char *reason = NULL;
    size_t seen = 0;
    for (size_t p = 0; p < yyjson_arr_size(projects); p++) {
        yyjson_val *project = yyjson_arr_get(projects, p);
        yyjson_val *paths = yyjson_obj_get(project, "analyzed_files");
        yyjson_val *errors = yyjson_obj_get(project, "diagnostics");
        ids[p] = cf_str(project, "id");
        if (!ids[p] || !*ids[p] || !yyjson_is_arr(paths) || !yyjson_is_arr(errors)) {
            reason = "invalid TypeScript local target project";
            break;
        }
        const char *previous = NULL;
        for (size_t f = 0; f < yyjson_arr_size(paths); f++) {
            const char *path = cf_string(yyjson_arr_get(paths, f));
            if (!path || !cf_file(facts, path) || (previous && strcmp(previous, path) >= 0)) {
                reason = "invalid TypeScript local target membership";
                break;
            }
            previous = path;
        }
        if (reason)
            break;
        for (size_t d = 0; d < yyjson_arr_size(errors); d++) {
            yyjson_val *item = yyjson_arr_get(errors, d);
            if (seen >= diagnostic_count ||
                !cf_local_diagnostic(facts, item, canonical, ids[p]) ||
                !cf_local_member(paths, cf_str(item, "path") + strlen(canonical) + 1) ||
                !yyjson_equals(item, yyjson_arr_get(diagnostics, seen++))) {
                reason = "TypeScript local target diagnostics differ";
                break;
            }
        }
        if (reason)
            break;
    }
    if (!reason) {
        qsort(ids, yyjson_arr_size(projects), sizeof(*ids), cf_string_compare);
        for (size_t p = 1; p < yyjson_arr_size(projects); p++)
            if (cf_equal(ids[p - 1], ids[p]))
                reason = "duplicate TypeScript local target context";
        if (seen != diagnostic_count)
            reason = "TypeScript local target diagnostics differ";
    }
    free(ids);
    return reason;
}

typedef struct {
    const CFFile *file;
    yyjson_val *site, *symbol, *proof;
} CFLocalProof;

static int cf_local_proof_compare(const void *left, const void *right) {
    const CFLocalProof *a = left, *b = right;
    int result = strcmp(a->file->path, b->file->path);
    if (result)
        return result;
    size_t x = cf_raw_id(a->site, "start"), y = cf_raw_id(b->site, "start");
    return x == y ? 0 : x < y ? -1 : 1;
}

static bool cf_local_function(TSNode node) {
    const char *kind = ts_node_type(node);
    return cf_equal(kind, "function_declaration") ||
           cf_equal(kind, "generator_function_declaration") ||
           cf_equal(kind, "function_expression") || cf_equal(kind, "generator_function") ||
           cf_equal(kind, "arrow_function") || cf_equal(kind, "method_definition");
}

static TSNode cf_local_node(TSNode root, size_t start, size_t end, const char *kind) {
    TSNode node = ts_node_descendant_for_byte_range(root, (uint32_t)start, (uint32_t)end);
    if (ts_node_start_byte(node) != start || ts_node_end_byte(node) != end ||
        !cf_equal(ts_node_type(node), kind))
        return (TSNode){0};
    return node;
}

static bool cf_local_blocked(TSNode node) {
    const char *kind = ts_node_type(node);
    if (cf_equal(kind, "internal_module") || cf_equal(kind, "module") ||
        cf_equal(kind, "ambient_declaration") || cf_equal(kind, "formal_parameters") ||
        cf_equal(kind, "required_parameter") ||
        cf_equal(kind, "optional_parameter") || cf_equal(kind, "rest_pattern") ||
        cf_equal(kind, "interface_declaration") ||
        cf_equal(kind, "enum_declaration") || strstr(kind, "abstract") ||
        (strstr(kind, "type") && !cf_equal(kind, "type_assertion")))
        return true;
    if (cf_equal(kind, "class_declaration") || cf_equal(kind, "class") ||
        cf_equal(kind, "method_definition") || cf_equal(kind, "public_field_definition")) {
        for (uint32_t i = 0; i < ts_node_child_count(node); i++)
            if (cf_equal(ts_node_type(ts_node_child(node, i)), "abstract"))
                return true;
    }
    return false;
}

typedef struct {
    const char *name;
    unsigned bindings;
    bool written;
    bool scoped_const;
    uint32_t first_scope, last_scope;
    uint32_t previous_end;
} CFLocalName;

static int cf_local_name_compare(const void *left, const void *right) {
    return strcmp(((const CFLocalName *)left)->name, ((const CFLocalName *)right)->name);
}

static CFLocalName *cf_local_name(CFLocalName *names, size_t count, const char *text,
                                size_t length) {
    size_t low = 0, high = count;
    while (low < high) {
        size_t middle = low + (high - low) / 2, size = strlen(names[middle].name);
        int order = memcmp(names[middle].name, text, size < length ? size : length);
        if (!order)
            order = size == length ? 0 : size < length ? -1 : 1;
        if (!order)
            return &names[middle];
        if (order < 0)
            low = middle + 1;
        else
            high = middle;
    }
    return NULL;
}

static bool cf_local_module_export(TSTreeCursor *cursor) {
    if (!ts_tree_cursor_goto_first_child(cursor))
        return false;
    bool module = false;
    do {
        TSNode token = ts_tree_cursor_current_node(cursor);
        const char *kind = ts_node_type(token);
        if (!ts_node_is_extra(token) && !cf_equal(kind, "export")) {
            /* TypeScript's UMD namespace declaration is not a module marker. */
            module = !cf_equal(kind, "as");
            break;
        }
    } while (ts_tree_cursor_goto_next_sibling(cursor));
    ts_tree_cursor_goto_parent(cursor);
    return module;
}

static bool cf_local_binding(TSNode parent, const char *field, TSNode node) {
    const char *kind = ts_node_type(parent);
    if (cf_equal(field, "name"))
        return cf_equal(kind, "variable_declarator") || cf_equal(kind, "function_declaration") ||
               cf_equal(kind, "generator_function_declaration") ||
               cf_equal(kind, "function_expression") || cf_equal(kind, "generator_function") ||
               cf_equal(kind, "function_signature") || cf_equal(kind, "class_declaration") ||
               cf_equal(kind, "abstract_class_declaration") || cf_equal(kind, "class") ||
               cf_equal(kind, "interface_declaration") || cf_equal(kind, "type_alias_declaration") ||
               cf_equal(kind, "type_parameter") || cf_equal(kind, "enum_declaration") ||
               cf_equal(kind, "internal_module") || cf_equal(kind, "module") ||
               cf_equal(kind, "import_alias") || cf_equal(kind, "required_parameter") ||
               cf_equal(kind, "optional_parameter") ||
               (cf_equal(kind, "import_specifier") &&
                ts_node_is_null(ts_node_child_by_field_name(parent, "alias", 5)));
    if (cf_equal(field, "alias") && cf_equal(kind, "import_specifier"))
        return true;
    if ((cf_equal(field, "pattern") || cf_equal(field, "name")) &&
        (cf_equal(kind, "required_parameter") || cf_equal(kind, "optional_parameter")))
        return true;
    if (cf_equal(field, "parameter") &&
        (cf_equal(kind, "catch_clause") || cf_equal(kind, "arrow_function")))
        return true;
    if (cf_equal(kind, "formal_parameters"))
        return cf_equal(ts_node_type(node), "identifier") ||
               cf_equal(ts_node_type(node), "object_pattern") ||
               cf_equal(ts_node_type(node), "array_pattern") ||
               cf_equal(ts_node_type(node), "assignment_pattern") ||
               cf_equal(ts_node_type(node), "rest_pattern");
    if (cf_equal(field, "left") && cf_equal(kind, "for_in_statement"))
        return !ts_node_is_null(ts_node_child_by_field_name(parent, "kind", 4));
    return cf_equal(ts_node_type(node), "identifier") &&
           (cf_equal(kind, "import_clause") || cf_equal(kind, "namespace_import") ||
            cf_equal(kind, "import_require_clause") || cf_equal(kind, "import_alias")) &&
           ts_node_eq(ts_node_named_child(parent, 0), node);
}

/* Require the same declaration shape for every repeated binding. */
static TSNode cf_local_const_body(TSNode declarator) {
    if (ts_node_is_null(declarator) || !cf_equal(ts_node_type(declarator), "variable_declarator"))
        return (TSNode){0};
    TSNode statement = ts_node_parent(declarator);
    if (ts_node_is_null(statement) || !cf_equal(ts_node_type(statement), "lexical_declaration"))
        return (TSNode){0};
    TSNode kind = ts_node_child_by_field_name(statement, "kind", 4);
    TSNode value = ts_node_child_by_field_name(declarator, "value", 5);
    if (ts_node_is_null(kind) || ts_node_is_null(value) || !cf_equal(ts_node_type(kind), "const") ||
        (!cf_equal(ts_node_type(value), "arrow_function") &&
         !cf_equal(ts_node_type(value), "function_expression")))
        return (TSNode){0};
    TSNode body = ts_node_parent(statement);
    if (ts_node_is_null(body) || !cf_equal(ts_node_type(body), "statement_block"))
        return (TSNode){0};
    TSNode function = ts_node_parent(body);
    if (ts_node_is_null(function) || !cf_local_function(function) ||
        !ts_node_eq(ts_node_child_by_field_name(function, "body", 4), body))
        return (TSNode){0};
    return body;
}

static bool cf_local_unrelated_parameter(TSNode name, const CFLocalName *proof) {
    if (!cf_equal(ts_node_type(name), "identifier"))
        return false;
    TSNode parent = ts_node_parent(name);
    const char *kind = ts_node_type(parent);
    if (cf_equal(kind, "required_parameter") || cf_equal(kind, "optional_parameter")) {
        TSNode pattern = ts_node_child_by_field_name(parent, "pattern", 7);
        if (ts_node_is_null(pattern))
            pattern = ts_node_child_by_field_name(parent, "name", 4);
        if (!ts_node_eq(pattern, name) ||
            !ts_node_is_null(ts_node_child_by_field_name(parent, "value", 5)))
            return false;
        parent = ts_node_parent(parent);
    }
    TSNode owner = {0};
    if (cf_equal(ts_node_type(parent), "formal_parameters"))
        owner = ts_node_parent(parent);
    else if (cf_equal(ts_node_type(parent), "arrow_function") &&
             ts_node_eq(ts_node_child_by_field_name(parent, "parameter", 9), name))
        owner = parent;
    if (ts_node_is_null(owner))
        return false;
    const char *owner_kind = ts_node_type(owner);
    return (cf_equal(owner_kind, "arrow_function") || cf_equal(owner_kind, "function_declaration") ||
            cf_equal(owner_kind, "function_expression") ||
            cf_equal(owner_kind, "generator_function_declaration") || cf_equal(owner_kind, "generator_function")) &&
           (ts_node_end_byte(owner) <= proof->first_scope ||
            ts_node_start_byte(owner) >= proof->last_scope);
}

static bool cf_local_indirect_eval(TSNode identifier, const char *source) {
    TSNode sequence = ts_node_parent(identifier);
    if (ts_node_is_null(sequence) || !cf_equal(ts_node_type(sequence), "sequence_expression"))
        return false;
    TSNode number = ts_node_prev_named_sibling(identifier);
    while (!ts_node_is_null(number) && ts_node_is_extra(number))
        number = ts_node_prev_named_sibling(number);
    if (ts_node_is_null(number) || !cf_equal(ts_node_type(number), "number") ||
        ts_node_end_byte(number) - ts_node_start_byte(number) != 1 ||
        source[ts_node_start_byte(number)] != '0')
        return false;
    TSNode previous = ts_node_prev_named_sibling(number);
    while (!ts_node_is_null(previous) && ts_node_is_extra(previous))
        previous = ts_node_prev_named_sibling(previous);
    TSNode next = ts_node_next_named_sibling(identifier);
    while (!ts_node_is_null(next) && ts_node_is_extra(next))
        next = ts_node_next_named_sibling(next);
    if (!ts_node_is_null(previous) || !ts_node_is_null(next))
        return false;
    TSNode paren = ts_node_parent(sequence);
    if (ts_node_is_null(paren) || !cf_equal(ts_node_type(paren), "parenthesized_expression"))
        return false;
    TSNode call = ts_node_parent(paren);
    if (ts_node_is_null(call) || !cf_equal(ts_node_type(call), "call_expression") ||
        !ts_node_eq(paren, ts_node_child_by_field_name(call, "function", 8)))
        return false;
    TSNode arguments = ts_node_next_sibling(paren);
    while (!ts_node_is_null(arguments) && ts_node_is_extra(arguments))
        arguments = ts_node_next_sibling(arguments);
    return !ts_node_is_null(arguments) && cf_equal(ts_node_type(arguments), "arguments");
}

/* A source is scanned once for all candidate names; modes follow binding/write
 * subtrees, including destructuring, without walking ancestors per identifier. */
static bool cf_local_inventory(TSNode root, const char *source, CFLocalProof *entries,
                               size_t count, uint64_t *nodes, bool *module, unsigned bindings) {
    typedef struct {
        TSNode node;
        bool binding, writing;
    } Frame;
    CFLocalName *names = calloc(count, sizeof(*names));
    Frame *frames = malloc(CF_MAX_LOCAL_AST_DEPTH * sizeof(*frames));
    if (!names || !frames) {
        free(names);
        free(frames);
        return false;
    }
    for (size_t i = 0; i < count; i++) {
        names[i].name = cf_str(entries[i].symbol, "name");
        names[i].scoped_const = module && cf_equal(cf_str(entries[i].symbol, "kind"), "ConstFunction");
        names[i].first_scope = (uint32_t)cf_raw_id(entries[i].proof, "scope_start");
        names[i].last_scope = (uint32_t)cf_raw_id(entries[i].proof, "scope_end");
    }
    qsort(names, count, sizeof(*names), cf_local_name_compare);
    size_t unique = 0;
    for (size_t i = 0; i < count; i++) {
        if (!unique || !cf_equal(names[unique - 1].name, names[i].name))
            names[unique++] = names[i];
        else {
            CFLocalName *merged = &names[unique - 1];
            merged->scoped_const &= names[i].scoped_const;
            if (names[i].first_scope < merged->first_scope)
                merged->first_scope = names[i].first_scope;
            if (names[i].last_scope > merged->last_scope)
                merged->last_scope = names[i].last_scope;
        }
    }
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    size_t depth = 0;
    bool valid = true, finished = false;
    while (valid && !finished) {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        const char *kind = ts_node_type(node);
        Frame frame = {.node = node};
        if (++*nodes > CF_MAX_LOCAL_AST_NODES || cf_equal(kind, "with_statement")) {
            valid = false;
            break;
        }
        if (depth == 1 && module && !*module)
            *module = cf_equal(kind, "import_statement") ||
                      (cf_equal(kind, "export_statement") && cf_local_module_export(&cursor));
        if (depth) {
            Frame *parent = &frames[depth - 1];
            const char *parent_kind = ts_node_type(parent->node);
            const char *field = ts_tree_cursor_current_field_name(&cursor);
            frame.binding = parent->binding;
            if ((cf_equal(parent_kind, "pair_pattern") && cf_equal(field, "key")) ||
                ((cf_equal(parent_kind, "assignment_pattern") ||
                  cf_equal(parent_kind, "object_assignment_pattern")) &&
                 cf_equal(field, "right")))
                frame.binding = false;
            frame.binding |= cf_local_binding(parent->node, field, node);
            frame.writing = parent->writing ||
                (cf_equal(field, "left") &&
                 (cf_equal(parent_kind, "assignment_expression") ||
                  cf_equal(parent_kind, "augmented_assignment_expression") ||
                  (cf_equal(parent_kind, "for_in_statement") &&
                   ts_node_is_null(ts_node_child_by_field_name(parent->node, "kind", 4))))) ||
                (cf_equal(field, "argument") && cf_equal(parent_kind, "update_expression"));
        }
        frames[depth] = frame;
        if (strstr(kind, "identifier")) {
            const char *text = source + ts_node_start_byte(node);
            size_t length = ts_node_end_byte(node) - ts_node_start_byte(node);
            /* Escaped spellings can alias a candidate or eval after binding.
             * Reject them until identifier decoding is independently verified. */
            if (memchr(text, '\\', length) || (length == 4 && memcmp(text, "eval", 4) == 0 &&
                (!module || !cf_local_indirect_eval(node, source)))) {
                valid = false;
                break;
            }
            CFLocalName *name = cf_local_name(names, unique, text, length);
            if (name) {
                if (frame.binding &&
                    !(name->scoped_const && cf_local_unrelated_parameter(node, name))) {
                    if (name->bindings < 2)
                        name->bindings++;
                    if (name->scoped_const) {
                        TSNode decl = ts_node_parent(node);
                        TSNode body = cf_local_const_body(decl);
                        name->scoped_const = !ts_node_is_null(body) && cf_equal(kind, "identifier") &&
                            ts_node_eq(ts_node_child_by_field_name(decl, "name", 4), node) &&
                            name->previous_end <= ts_node_start_byte(body);
                        if (name->scoped_const)
                            name->previous_end = ts_node_end_byte(body);
                    }
                }
                name->written |= frame.writing;
            }
        }
        if (ts_tree_cursor_goto_first_child(&cursor)) {
            if (++depth >= CF_MAX_LOCAL_AST_DEPTH)
                valid = false;
            continue;
        }
        while (!ts_tree_cursor_goto_next_sibling(&cursor)) {
            if (!depth) {
                finished = true;
                break;
            }
            ts_tree_cursor_goto_parent(&cursor);
            depth--;
        }
    }
    for (size_t i = 0; valid && i < unique; i++)
        valid = (names[i].bindings == bindings || (names[i].bindings > bindings && names[i].scoped_const)) &&
                !names[i].written;
    ts_tree_cursor_delete(&cursor);
    free(frames);
    free(names);
    return valid;
}

enum { CF_LOCAL_CLOSURE_LIMIT = 32, CF_LOCAL_CLOSURE_BLOCK_BYTES = 16384 };

typedef struct {
    TSNode functions[CF_LOCAL_CLOSURE_LIMIT];
    size_t count;
} CFLocalClosures;

static bool cf_local_boundary(TSNode node) {
    const char *kind = ts_node_type(node);
    return cf_local_function(node) || cf_equal(kind, "class") ||
           cf_equal(kind, "class_declaration") || cf_equal(kind, "abstract_class_declaration");
}

static bool cf_local_immediately_invoked_arrow(TSNode node) {
    if (!cf_equal(ts_node_type(node), "arrow_function"))
        return false;
    TSNode parent = ts_node_parent(node);
    while (cf_equal(ts_node_type(parent), "parenthesized_expression")) {
        node = parent;
        parent = ts_node_parent(node);
    }
    if (!cf_equal(ts_node_type(parent), "call_expression"))
        return false;
    TSNode args = ts_node_child_by_field_name(parent, "arguments", 9);
    return !ts_node_is_null(args) && cf_equal(ts_node_type(args), "arguments") &&
           ts_node_eq(ts_node_child_by_field_name(parent, "function", 8), node) &&
           ts_node_is_null(ts_node_child_by_field_name(parent, "optional_chain", 14));
}

static bool cf_local_closure_refs(TSNode block, TSNode name, TSNode statement,
                                  const char *source) {
    uint32_t name_start = ts_node_start_byte(name);
    uint32_t name_length = ts_node_end_byte(name) - name_start;
    uint32_t after_declaration = ts_node_end_byte(statement);
    TSTreeCursor cursor = ts_tree_cursor_new(block);
    bool valid = true, used = false;
    size_t depth = 0, blocked = 0;
    do {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        const char *kind = ts_node_type(node);
        if (depth && !blocked && cf_local_blocked(node))
            blocked = depth;
        if (strstr(kind, "identifier") && !ts_node_eq(node, name)) {
            uint32_t start = ts_node_start_byte(node), length = ts_node_end_byte(node) - start;
            if (length == 9 && memcmp(source + start, "arguments", 9) == 0) {
                valid = false;
                break;
            }
            if (length == name_length && memcmp(source + name_start, source + start, length) == 0) {
                TSNode call = ts_node_parent(node);
                valid = !blocked && start >= after_declaration && cf_equal(kind, "identifier") &&
                        !ts_node_is_null(call) && cf_equal(ts_node_type(call), "call_expression") &&
                        ts_node_eq(ts_node_child_by_field_name(call, "function", 8), node) &&
                        ts_node_is_null(ts_node_child_by_field_name(call, "optional_chain", 14));
                if (valid) {
                    TSNode next = ts_node_next_sibling(node);
                    while (!ts_node_is_null(next) && ts_node_is_extra(next))
                        next = ts_node_next_sibling(next);
                    valid = !ts_node_is_null(next) &&
                            (cf_equal(ts_node_type(next), "arguments") ||
                             cf_equal(ts_node_type(next), "type_arguments"));
                }
                used = true;
            }
        }
        if (!valid)
            break;
        if (ts_tree_cursor_goto_first_child(&cursor)) {
            depth++;
            continue;
        }
        while (depth) {
            if (blocked == depth)
                blocked = 0;
            if (ts_tree_cursor_goto_next_sibling(&cursor))
                break;
            ts_tree_cursor_goto_parent(&cursor);
            depth--;
        }
    } while (depth);
    ts_tree_cursor_delete(&cursor);
    return valid && used;
}

static bool cf_local_closure(TSNode function, TSNode call, TSNode scope, TSNode target_statement,
                              const char *source, CFLocalClosures *closures) {
    const char *kind = ts_node_type(function);
    if (!cf_equal(kind, "arrow_function") &&
        !(cf_equal(kind, "function_expression") &&
          ts_node_is_null(ts_node_child_by_field_name(function, "name", 4))))
        return false;
    TSNode body = ts_node_child_by_field_name(function, "body", 4);
    if (ts_node_is_null(body) || ts_node_start_byte(call) < ts_node_start_byte(body) ||
        ts_node_end_byte(call) > ts_node_end_byte(body))
        return false;
    TSNode decl = ts_node_parent(function);
    if (ts_node_is_null(decl) || !cf_equal(ts_node_type(decl), "variable_declarator") ||
        !ts_node_eq(function, ts_node_child_by_field_name(decl, "value", 5)))
        return false;
    TSNode statement = ts_node_parent(decl);
    if (ts_node_is_null(statement) || !cf_equal(ts_node_type(statement), "lexical_declaration") ||
        ts_node_start_byte(statement) < ts_node_end_byte(target_statement))
        return false;
    TSNode name = ts_node_child_by_field_name(decl, "name", 4);
    TSNode token = ts_node_child_by_field_name(statement, "kind", 4);
    TSNode block = ts_node_parent(statement);
    if (ts_node_is_null(name) || !cf_equal(ts_node_type(name), "identifier") ||
        ts_node_is_null(token) || !cf_equal(ts_node_type(token), "const") ||
        ts_node_is_null(block) || !cf_equal(ts_node_type(block), "statement_block") ||
        ts_node_end_byte(block) - ts_node_start_byte(block) > CF_LOCAL_CLOSURE_BLOCK_BYTES ||
        ts_node_start_byte(block) < ts_node_start_byte(scope) ||
        ts_node_end_byte(block) > ts_node_end_byte(scope))
        return false;
    for (size_t i = 0; i < closures->count; i++)
        if (ts_node_eq(function, closures->functions[i]))
            return true;
    if (closures->count >= CF_LOCAL_CLOSURE_LIMIT ||
        !cf_local_closure_refs(block, name, statement, source))
        return false;
    closures->functions[closures->count++] = function;
    return true;
}

static TSNode cf_local_field(TSNode node, const char *field) {
    return ts_node_is_null(node) ? (TSNode){0} : ts_node_child_by_field_name(node, field, (uint32_t)strlen(field));
}

static TSNode cf_local_child(TSNode node, uint32_t index, uint32_t *count) {
    TSNode selected = {0};
    uint32_t position = 0;
    if (!ts_node_is_null(node)) {
        for (uint32_t i = 0; i < ts_node_named_child_count(node); i++) {
            TSNode child = ts_node_named_child(node, i);
            if (ts_node_is_extra(child)) continue;
            if (position++ == index) selected = child;
        }
    }
    if (count) *count = position;
    return selected;
}

static bool cf_local_same_text(const char *source, TSNode left, TSNode right) {
    if (ts_node_is_null(left) || ts_node_is_null(right)) return false;
    uint32_t size = ts_node_end_byte(left) - ts_node_start_byte(left);
    return size == ts_node_end_byte(right) - ts_node_start_byte(right) &&
           memcmp(source + ts_node_start_byte(left), source + ts_node_start_byte(right), size) == 0;
}

static bool cf_local_text(const char *source, TSNode node, const char *text) {
    size_t size = strlen(text);
    return !ts_node_is_null(node) && size == ts_node_end_byte(node) - ts_node_start_byte(node) &&
           memcmp(source + ts_node_start_byte(node), text, size) == 0;
}

static bool cf_local_children_are(TSNode node, const char *kind, bool equal) {
    if (ts_node_is_null(node)) return false;
    for (uint32_t i = 0; i < ts_node_named_child_count(node); i++) {
        TSNode child = ts_node_named_child(node, i);
        if (!ts_node_is_extra(child) && cf_equal(ts_node_type(child), kind) != equal) return false;
    }
    return true;
}

static bool cf_local_plain_call(TSNode node) {
    return !ts_node_is_null(node) && cf_equal(ts_node_type(node), "call_expression") &&
           ts_node_is_null(cf_local_field(node, "optional_chain")) &&
           cf_local_children_are(cf_local_field(node, "arguments"), "spread_element", false);
}

static bool cf_local_direct_callee(TSNode node) {
    if (!cf_equal(ts_node_type(node), "identifier")) return false;
    TSNode call = ts_node_parent(node);
    return cf_local_plain_call(call) && ts_node_eq(cf_local_field(call, "function"), node);
}

static TSNode cf_local_function_owner(TSNode node) {
    for (; !ts_node_is_null(node); node = ts_node_parent(node)) {
        if (cf_local_boundary(node)) return node;
    }
    return node;
}

/* Inventory only the binding spellings used by this shape, including shorthand aliases. */
static bool cf_local_closed_uses(TSNode scope, const char *source, TSNode binding, TSNode use,
                                 bool allow_direct_calls, uint64_t *nodes) {
    TSTreeCursor cursor = ts_tree_cursor_new(scope);
    bool valid = true;
    for (;;) {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        const char *kind = ts_node_type(node);
        bool reference = cf_equal(kind, "identifier") || cf_equal(kind, "shorthand_property_identifier") ||
                         cf_equal(kind, "shorthand_property_identifier_pattern");
        if (++*nodes > CF_MAX_LOCAL_AST_NODES || (reference &&
            (cf_local_text(source, node, "eval") || cf_local_text(source, node, "arguments") ||
             (cf_local_same_text(source, node, binding) && !ts_node_eq(node, binding) && !ts_node_eq(node, use) &&
              !(allow_direct_calls && cf_local_direct_callee(node)))))) {
            valid = false;
            break;
        }
        if (ts_tree_cursor_goto_first_child(&cursor)) continue;
        while (!ts_tree_cursor_goto_next_sibling(&cursor)) {
            if (!ts_tree_cursor_goto_parent(&cursor)) goto done;
        }
    }
done:
    ts_tree_cursor_delete(&cursor);
    return valid;
}

static bool cf_local_node_test(TSNode root, const char *source, TSNode factory_call,
                               bool multiple_tests, uint64_t *nodes) {
    TSNode registration = ts_node_parent(ts_node_parent(factory_call));
    TSNode route = cf_local_field(registration, "function");
    uint32_t route_count, test_count;
    TSNode handler = cf_local_child(cf_local_field(registration, "arguments"), 1, &route_count);
    if (!cf_local_plain_call(registration) || !cf_equal(ts_node_type(route), "member_expression") ||
        !ts_node_is_null(cf_local_field(route, "optional_chain")) ||
        !cf_local_text(source, cf_local_field(route, "property"), "route") ||
        route_count != 2 || !ts_node_eq(handler, factory_call))
        return false;
    TSNode awaited = ts_node_parent(registration), statement = ts_node_parent(awaited);
    TSNode body = ts_node_parent(statement), test = ts_node_parent(body);
    if (!cf_equal(ts_node_type(awaited), "await_expression") || !cf_equal(ts_node_type(statement), "expression_statement") ||
        ts_node_is_null(test) || !cf_equal(ts_node_type(test), "arrow_function") ||
        !ts_node_eq(cf_local_field(test, "body"), body)) return false;
    TSNode test_call = ts_node_parent(ts_node_parent(test));
    TSNode callee = cf_local_field(test_call, "function");
    TSNode callback = cf_local_child(cf_local_field(test_call, "arguments"), 1, &test_count);
    if (!ts_node_is_null(cf_local_function_owner(test_call)) || ts_node_is_null(callee) ||
        !cf_local_direct_callee(callee) || test_count != 2 || !ts_node_eq(callback, test))
        return false;

    for (uint32_t i = 0; i < ts_node_named_child_count(root); i++) {
        TSNode statement = ts_node_named_child(root, i);
        if (!cf_equal(ts_node_type(statement), "lexical_declaration") ||
            !cf_equal(ts_node_type(cf_local_field(statement, "kind")), "const")) continue;
        TSNode declaration = cf_local_child(statement, 0, NULL);
        TSNode name = cf_local_field(declaration, "name");
        uint32_t bindings, inputs;
        TSNode import = cf_local_child(name, 0, &bindings);
        if (!cf_equal(ts_node_type(name), "object_pattern") || bindings != 1 ||
            !cf_equal(ts_node_type(import), "shorthand_property_identifier_pattern") ||
            !cf_local_text(source, import, "test") || !cf_local_same_text(source, import, callee)) continue;
        TSNode call = cf_local_field(declaration, "value"), loader = cf_local_field(call, "function");
        TSNode input = cf_local_child(cf_local_field(call, "arguments"), 0, &inputs);
        return cf_local_direct_callee(loader) && cf_local_text(source, loader, "require") &&
               inputs == 1 && cf_equal(ts_node_type(input), "string") &&
               cf_local_text(source, cf_local_child(input, 0, NULL), "node:test") &&
               cf_local_closed_uses(root, source, loader, (TSNode){0}, true, nodes) &&
               cf_local_closed_uses(root, source, import, callee, multiple_tests, nodes);
    }
    return false;
}

static bool cf_local_forwarding(TSNode root, const char *source, const CFLocalProof *entry,
                               TSNode scope, TSNode target, TSNode call, uint64_t *nodes) {
    yyjson_val *proof = yyjson_obj_get(entry->proof, "forwarding");
    uint64_t factory_start, factory_end, transfer_start, transfer_end, factory_slot, target_slot;
    const char *extension = strrchr(entry->file->path, '.');
    if (!cf_equal(extension, ".cjs") || entry->file->length > 16384 || yyjson_obj_size(proof) != 6 ||
        !cf_uint(proof, "factory_start", &factory_start) || !cf_uint(proof, "factory_end", &factory_end) ||
        !cf_uint(proof, "transfer_start", &transfer_start) || !cf_uint(proof, "transfer_end", &transfer_end) ||
        !cf_uint(proof, "factory_slot", &factory_slot) || !cf_uint(proof, "target_slot", &target_slot) ||
        factory_start >= factory_end || factory_end > entry->file->length ||
        transfer_start >= transfer_end || transfer_end > entry->file->length ||
        factory_slot > UINT32_MAX || target_slot > UINT32_MAX ||
        !ts_node_eq(cf_local_const_body(target), scope) ||
        !cf_equal(ts_node_type(cf_local_field(target, "value")), "arrow_function")) return false;
    TSNode factory = cf_local_node(root, factory_start, factory_end, "function_declaration");
    TSNode factory_name = cf_local_field(factory, "name"), factory_body = cf_local_field(factory, "body");
    TSNode handler = ts_node_parent(scope), returned = ts_node_parent(handler);
    if (ts_node_is_null(factory) || !ts_node_eq(ts_node_parent(factory), root) ||
        !cf_equal(ts_node_type(handler), "arrow_function") || !cf_equal(ts_node_type(returned), "return_statement") ||
        !ts_node_eq(ts_node_parent(returned), factory_body)) return false;
    for (uint32_t i = 0; i < ts_node_named_child_count(factory_body); i++) {
        TSNode node = ts_node_named_child(factory_body, i);
        if (cf_equal(ts_node_type(node), "return_statement") && !ts_node_eq(node, returned)) return false;
    }
    TSNode consumer = cf_local_function_owner(call);
    if (!cf_equal(ts_node_type(consumer), "arrow_function") ||
        !cf_equal(ts_node_type(cf_local_field(consumer, "body")), "statement_block")) return false;
    TSNode factory_call = ts_node_parent(ts_node_parent(consumer));
    TSNode factory_callee = cf_local_field(factory_call, "function"), factory_args = cf_local_field(factory_call, "arguments");
    TSNode factory_params = cf_local_field(factory, "parameters");
    uint32_t factory_arg_count, factory_param_count;
    TSNode callback = cf_local_child(factory_args, (uint32_t)factory_slot, &factory_arg_count);
    TSNode forwarded = cf_local_child(factory_params, (uint32_t)factory_slot, &factory_param_count);
    if (!cf_local_direct_callee(factory_callee) || !cf_local_same_text(source, factory_callee, factory_name) ||
        !ts_node_eq(consumer, callback) ||
        !cf_local_children_are(factory_params, "identifier", true) ||
        factory_arg_count != factory_param_count) return false;

    TSNode transfer = cf_local_node(scope, transfer_start, transfer_end, "call_expression");
    TSNode transfer_callee = cf_local_field(transfer, "function"), transfer_args = cf_local_field(transfer, "arguments");
    TSNode consumer_params = cf_local_field(consumer, "parameters");
    uint32_t transfer_count, consumer_count;
    TSNode argument = cf_local_child(transfer_args, (uint32_t)target_slot, &transfer_count);
    TSNode parameter = cf_local_child(consumer_params, (uint32_t)target_slot, &consumer_count);
    TSNode name = cf_local_field(target, "name"), callee = cf_local_field(call, "function");
    return cf_local_direct_callee(callee) && cf_local_direct_callee(transfer_callee) &&
           ts_node_eq(cf_local_function_owner(transfer), handler) && cf_local_same_text(source, transfer_callee, forwarded) &&
           ts_node_end_byte(target) < transfer_start && cf_equal(ts_node_type(argument), "identifier") &&
           cf_local_same_text(source, argument, name) && cf_local_same_text(source, parameter, callee) &&
           cf_local_children_are(consumer_params, "identifier", true) &&
           transfer_count == consumer_count &&
           cf_local_node_test(root, source, factory_call, false, nodes) &&
           cf_local_closed_uses(root, source, factory_name, factory_callee, false, nodes) &&
           cf_local_closed_uses(factory, source, forwarded, transfer_callee, false, nodes) &&
           cf_local_closed_uses(scope, source, name, argument, true, nodes) &&
           cf_local_closed_uses(consumer, source, parameter, (TSNode){0}, true, nodes);
}

static bool cf_local_promise_resolve(TSNode call, const char *source) {
    TSNode callee = cf_local_field(call, "function");
    uint32_t arguments;
    cf_local_child(cf_local_field(call, "arguments"), 0, &arguments);
    return cf_local_plain_call(call) && !arguments && cf_equal(ts_node_type(callee), "member_expression") &&
           ts_node_is_null(cf_local_field(callee, "optional_chain")) &&
           cf_equal(ts_node_type(cf_local_field(callee, "object")), "identifier") &&
           cf_local_text(source, cf_local_field(callee, "object"), "Promise") &&
           cf_local_text(source, cf_local_field(callee, "property"), "resolve");
}

static bool cf_local_promise_parameter(TSNode root, const char *source, TSNode scope, TSNode receiver,
                                       uint64_t factory_slot, uint64_t *nodes) {
    TSNode handler = ts_node_parent(scope), returned = ts_node_parent(handler);
    TSNode body = ts_node_parent(returned), factory = ts_node_parent(body);
    TSNode name = cf_local_field(factory, "name"), params = cf_local_field(factory, "parameters");
    uint32_t parameter_count;
    TSNode parameter = cf_local_child(params, (uint32_t)factory_slot, &parameter_count);
    if (factory_slot > UINT32_MAX || !cf_equal(ts_node_type(receiver), "identifier") ||
        !cf_equal(ts_node_type(handler), "arrow_function") || !cf_equal(ts_node_type(returned), "return_statement") ||
        !cf_equal(ts_node_type(factory), "function_declaration") || !ts_node_eq(ts_node_parent(factory), root) ||
        cf_equal(ts_node_type(ts_node_child(factory, 0)), "async") ||
        !cf_equal(ts_node_type(name), "identifier") || !cf_local_children_are(params, "identifier", true) ||
        !cf_local_same_text(source, receiver, parameter) ||
        !cf_local_closed_uses(factory, source, parameter, receiver, false, nodes)) return false;
    for (uint32_t i = 0; i < ts_node_named_child_count(body); i++) {
        TSNode statement = ts_node_named_child(body, i);
        if (cf_equal(ts_node_type(statement), "return_statement") && !ts_node_eq(statement, returned)) return false;
    }
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    unsigned calls = 0;
    bool valid = true;
    for (;;) {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        if (++*nodes > CF_MAX_LOCAL_AST_NODES) {
            valid = false;
            break;
        }
        const char *kind = ts_node_type(node);
        if ((cf_equal(kind, "identifier") || cf_equal(kind, "shorthand_property_identifier") ||
             cf_equal(kind, "shorthand_property_identifier_pattern")) && !ts_node_eq(node, name) &&
            cf_local_same_text(source, node, name)) {
            TSNode call = ts_node_parent(node);
            uint32_t arguments, executor_args;
            TSNode input = cf_local_child(cf_local_field(call, "arguments"), (uint32_t)factory_slot, &arguments);
            TSNode executor = cf_local_child(cf_local_field(input, "arguments"), 0, &executor_args);
            TSNode constructor = cf_local_field(input, "constructor");
            bool fresh = !ts_node_is_null(input) && cf_equal(ts_node_type(input), "new_expression") && executor_args == 1 &&
                         cf_equal(ts_node_type(executor), "arrow_function") &&
                         !ts_node_is_null(constructor) && cf_equal(ts_node_type(constructor), "identifier") &&
                         cf_local_text(source, constructor, "Promise");
            if (++calls > 8 || !cf_local_direct_callee(node) || arguments != parameter_count ||
                (!fresh && !cf_local_promise_resolve(input, source)) || !cf_local_node_test(root, source, call, true, nodes)) {
                valid = false;
                break;
            }
        }
        if (ts_tree_cursor_goto_first_child(&cursor)) continue;
        while (!ts_tree_cursor_goto_next_sibling(&cursor))
            if (!ts_tree_cursor_goto_parent(&cursor)) goto done;
    }
done:
    ts_tree_cursor_delete(&cursor);
    return valid && calls > 0;
}

static bool cf_local_deferred_host_uses(TSNode root, const char *source, bool parameter, uint64_t *nodes) {
    static const char *const blocked[] = {"arguments", "eval", "Function", "globalThis", "global", "self",
        "constructor", "__proto__", "getPrototypeOf", "setPrototypeOf", "defineProperty", "defineProperties", "Reflect"};
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    bool valid = true;
    for (;;) {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        if (++*nodes > CF_MAX_LOCAL_AST_NODES || cf_equal(ts_node_type(node), "this")) {
            valid = false;
            break;
        }
        if (parameter && cf_equal(ts_node_type(node), "subscript_expression")) {
            TSNode key = cf_local_field(node, "index");
            TSNode fragment = cf_local_child(key, 0, NULL);
            if (cf_equal(ts_node_type(key), "string") && (cf_local_text(source, fragment, "prototype") ||
                cf_local_text(source, fragment, "__proto__") || cf_local_text(source, fragment, "constructor"))) {
                valid = false;
                break;
            }
        }
        if (strstr(ts_node_type(node), "identifier")) {
            for (size_t i = 0; i < sizeof(blocked) / sizeof(*blocked); i++)
                valid &= !cf_local_text(source, node, blocked[i]);
            TSNode parent = ts_node_parent(node);
            if (parameter) valid &= !cf_local_text(source, node, "Object") && !cf_local_text(source, node, "Proxy");
            if (cf_local_text(source, node, "setTimeout"))
                valid &= cf_local_direct_callee(node);
            if (cf_local_text(source, node, "Promise"))
                valid &= (cf_equal(ts_node_type(parent), "new_expression") &&
                          ts_node_eq(cf_local_field(parent, "constructor"), node)) ||
                         (parameter && cf_local_promise_resolve(ts_node_parent(parent), source));
            if (cf_local_text(source, node, "then")) {
                TSNode call = ts_node_parent(parent);
                valid &= cf_equal(ts_node_type(parent), "member_expression") &&
                         ts_node_eq(cf_local_field(parent, "property"), node) &&
                         cf_equal(ts_node_type(call), "call_expression") &&
                         ts_node_eq(cf_local_field(call, "function"), parent);
            }
            if (!valid) break;
        }
        if (ts_tree_cursor_goto_first_child(&cursor)) continue;
        while (!ts_tree_cursor_goto_next_sibling(&cursor))
            if (!ts_tree_cursor_goto_parent(&cursor)) goto done;
    }
done:
    ts_tree_cursor_delete(&cursor);
    return valid;
}

static bool cf_local_deferred(TSNode root, const char *source, TSNode scope, TSNode target_statement,
                              TSNode closure, yyjson_val *deferred, uint64_t *nodes) {
    const char *kind = cf_str(deferred, "kind");
    bool parameter = cf_equal(kind, "promise_parameter");
    if (!cf_equal(ts_node_type(closure), "arrow_function") ||
        ts_node_start_byte(closure) < ts_node_end_byte(target_statement)) return false;
    TSNode arguments = ts_node_parent(closure), wrapper = ts_node_parent(arguments);
    TSNode callee = cf_local_field(wrapper, "function");
    if (!cf_local_plain_call(wrapper) || !ts_node_eq(cf_local_field(wrapper, "arguments"), arguments) ||
        !ts_node_eq(cf_local_child(arguments, 0, NULL), closure) ||
        !ts_node_eq(cf_local_function_owner(wrapper), ts_node_parent(scope))) return false;
    if (cf_equal(kind, "timer")) {
        if (!cf_local_direct_callee(callee) || !cf_local_text(source, callee, "setTimeout")) return false;
    } else if (cf_equal(kind, "promise") || parameter) {
        TSNode created = cf_local_field(callee, "object");
        TSNode constructor = cf_local_field(created, "constructor");
        if (!cf_equal(ts_node_type(callee), "member_expression") || !ts_node_is_null(cf_local_field(callee, "optional_chain")) ||
            !cf_local_text(source, cf_local_field(callee, "property"), "then")) return false;
        if (parameter) {
            uint32_t count;
            uint64_t slot;
            cf_local_child(arguments, 0, &count);
            if (count != 1 || !cf_uint(deferred, "factory_slot", &slot) ||
                !cf_local_promise_parameter(root, source, scope, created, slot, nodes)) return false;
        } else if (!cf_equal(ts_node_type(created), "new_expression") || !cf_equal(ts_node_type(constructor), "identifier") ||
                   !cf_local_text(source, constructor, "Promise") ||
                   !cf_local_children_are(cf_local_field(created, "arguments"), "spread_element", false)) return false;
    } else return false;
    return cf_local_deferred_host_uses(root, source, parameter, nodes);
}

static bool cf_local_ast(TSNode root, const char *source, const CFLocalProof *entry, bool module,
                          CFLocalClosures *closures, uint64_t *nodes) {
    yyjson_val *site = entry->site, *decl = yyjson_obj_get(entry->symbol, "declaration");
    yyjson_val *proof = entry->proof;
    size_t start = cf_raw_id(proof, "scope_start"), end = cf_raw_id(proof, "scope_end");
    bool module_scope = module && start == 0 && end == entry->file->length;
    bool const_function = cf_equal(cf_str(entry->symbol, "kind"), "ConstFunction");
    TSNode scope = module_scope ? root : cf_local_node(root, start, end, "statement_block");
    TSNode target = cf_local_node(root, cf_raw_id(decl, "start"), cf_raw_id(decl, "end"),
                                  const_function ? "variable_declarator" : "function_declaration");
    TSNode call = cf_local_node(root, cf_raw_id(site, "start"), cf_raw_id(site, "end"), "call_expression");
    if (ts_node_is_null(scope) || ts_node_is_null(target) || ts_node_is_null(call))
        return false;
    TSNode name = cf_local_field(target, "name"), callee = cf_local_field(call, "function");
    const char *spelling = cf_str(proof, "name");
    if (!cf_equal(ts_node_type(name), "identifier") || !cf_equal(ts_node_type(callee), "identifier") ||
        ts_node_start_byte(name) != cf_raw_id(decl, "name_start") || ts_node_end_byte(name) != cf_raw_id(decl, "name_end") ||
        ts_node_start_byte(callee) != cf_raw_id(site, "callee_start") || ts_node_end_byte(callee) != cf_raw_id(site, "callee_end") ||
        !cf_local_text(source, name, spelling) || !cf_local_text(source, callee, spelling)) return false;
    if (yyjson_obj_get(proof, "forwarding"))
        return const_function && cf_local_forwarding(root, source, entry, scope, target, call, nodes);
    TSNode target_statement = ts_node_parent(target);
    TSNode parent = target_statement;
    if (const_function) {
        if (module_scope || ts_node_start_byte(call) < ts_node_end_byte(parent))
            return false;
        parent = cf_local_const_body(target);
    }
    if (!ts_node_eq(parent, scope))
        return false;
    if (!module_scope) {
        TSNode owner = ts_node_parent(scope);
        if (!cf_local_function(owner) ||
            !ts_node_eq(ts_node_child_by_field_name(owner, "body", 4), scope))
            return false;
    }
    bool contained = false, invoked = false;
    TSNode closure = {0};
    for (TSNode node = call; !ts_node_is_null(node); node = ts_node_parent(node)) {
        if (cf_local_blocked(node))
            return false;
        contained |= ts_node_eq(node, scope);
        if (const_function && !contained && cf_local_boundary(node)) {
            if (!ts_node_is_null(closure))
                return false;
            if (cf_local_immediately_invoked_arrow(node))
                invoked = true;
            else if (invoked)
                return false;
            else
                closure = node;
        }
    }
    for (TSNode node = target; !ts_node_is_null(node); node = ts_node_parent(node))
        if (cf_local_blocked(node))
            return false;
    yyjson_val *deferred = yyjson_obj_get(proof, "deferred");
    if (deferred)
        return contained && !invoked && cf_local_deferred(root, source, scope, target_statement, closure,
                                                         deferred, nodes);
    return contained && (ts_node_is_null(closure) || cf_local_closure(closure, call, scope, target_statement,
                                                                     source, closures));
}

static bool cf_ts_context_dependency(yyjson_val *root, yyjson_val *contexts, const char *path, const char *sha256);

static bool cf_local_path_suffix(const char *path, const char *suffix) {
    if (!path) return false;
    size_t length = strlen(path), tail = strlen(suffix);
    return length >= tail && cf_equal(path + length - tail, suffix);
}

static bool cf_local_deferred_dependencies(yyjson_val *root, yyjson_val *site, yyjson_val *deferred) {
    const char *kind = cf_str(deferred, "kind");
    bool timer = cf_equal(kind, "timer");
    bool parameter = cf_equal(kind, "promise_parameter");
    yyjson_val *deps = yyjson_obj_get(deferred, "declarations");
    if (yyjson_obj_size(deferred) != (parameter ? 3 : 2) || (!timer && !parameter && !cf_equal(kind, "promise")) ||
        yyjson_arr_size(deps) != (timer ? 1 : parameter ? 4 : 2)) return false;
    const char *const suffixes[] = {"/lib.es5.d.ts", "/lib.es2015.promise.d.ts",
                                    "/playwright-core/types/types.d.ts", "/@types/node/test.d.ts"};
    for (size_t i = 0; i < yyjson_arr_size(deps); i++) {
        yyjson_val *decl = yyjson_arr_get(deps, i);
        const char *path = cf_str(decl, "path"), *sha256 = cf_str(decl, "sha256");
        bool expected_path = timer ? cf_local_path_suffix(path, "/@types/node/timers.d.ts") ||
                                      cf_local_path_suffix(path, "/@types/node/web-globals/timers.d.ts")
                                   : cf_local_path_suffix(path, suffixes[i]);
        if (!expected_path || yyjson_obj_size(decl) != 2 || !sha256 ||
            !cf_ts_context_dependency(root, yyjson_obj_get(site, "contexts"), path, sha256)) return false;
    }
    return true;
}

static const char *cf_local_proofs(CBMCompilerFacts *facts, yyjson_val *root,
                                  const char *canonical) {
    yyjson_val *sites = yyjson_obj_get(root, "sites");
    yyjson_val *metadata = facts->proof_index ? facts->proof_root : root;
    yyjson_val *projects = yyjson_obj_get(yyjson_obj_get(metadata, "context"), "projects");
    size_t site_count = yyjson_arr_size(sites), count = 0;
    CFLocalProof *entries = site_count ? calloc(site_count, sizeof(*entries)) : NULL;
    bool *used = facts->symbol_count ? calloc(facts->symbol_count, sizeof(*used)) : NULL;
    if ((site_count && !entries) || (facts->symbol_count && !used)) {
        free(entries);
        free(used);
        return "out of memory";
    }
    const char *reason = "invalid TypeScript local target proof";
    uint64_t ast_bytes = 0, ast_nodes = 0;
    size_t i, n;
    yyjson_val *site;
    yyjson_arr_foreach(sites, i, n, site) {
        yyjson_val *proof = yyjson_obj_get(site, "proof");
        if (facts->proof_index) {
            yyjson_val *target = yyjson_obj_get(proof, "target");
            if (!cf_equal(cf_str(target, "status"), "available") ||
                !cf_equal(cf_str(target, "reason"), "lexical_target"))
                continue;
            proof = yyjson_obj_get(proof, "lexical");
        }
        yyjson_val *flags = yyjson_obj_get(site, "type_flags");
        uint64_t target, start, end, type, signature, receiver;
        if (!cf_uint(site, "target_symbol", &target) || !target || target > facts->symbol_count ||
            !cf_uint(proof, "scope_start", &start) || !cf_uint(proof, "scope_end", &end) ||
            (!facts->proof_index &&
             !cf_equal(cf_str(proof, "profile"), "lexical_target_v1")) ||
            !cf_str(proof, "name") || !*cf_str(proof, "name") ||
            cf_equal(cf_str(proof, "name"), "arguments") ||
            !cf_equal(cf_str(site, "dispatch"), "static") ||
            !cf_uint(site, "type", &type) || type ||
            !cf_uint(site, "signature", &signature) || signature ||
            !cf_uint(site, "receiver", &receiver) || receiver ||
            !yyjson_is_false(yyjson_obj_get(flags, "any")) ||
            !yyjson_is_true(yyjson_obj_get(flags, "unknown")))
            goto done;
        const char *arrays[] = {"args", "arguments", "contextual_params"};
        for (size_t a = 0; a < sizeof(arrays) / sizeof(*arrays); a++)
            if (!yyjson_is_arr(yyjson_obj_get(site, arrays[a])) ||
                yyjson_arr_size(yyjson_obj_get(site, arrays[a])))
                goto done;
        yyjson_val *symbol = facts->symbols[target - 1].json.raw;
        yyjson_val *decl = yyjson_obj_get(symbol, "declaration");
        const CFFile *file = cf_file(facts, cf_str(site, "path"));
        yyjson_val *deferred = yyjson_obj_get(proof, "deferred");
        if (deferred && (!file || !facts->proof_index || !cf_equal(cf_str(symbol, "kind"), "ConstFunction") ||
                         yyjson_obj_get(proof, "forwarding") || file->length > 16384 ||
                         !cf_local_path_suffix(file->path, ".cjs") ||
                         !cf_local_deferred_dependencies(metadata, site, deferred))) goto done;
        if (!file || end > file->length || start >= end ||
            start > cf_raw_id(decl, "start") || cf_raw_id(decl, "end") > end ||
             ((start > cf_raw_id(site, "start") || cf_raw_id(site, "end") > end) &&
              (!facts->proof_index || !yyjson_is_obj(yyjson_obj_get(proof, "forwarding")))) ||
            (!cf_equal(cf_str(symbol, "kind"), "FunctionDeclaration") &&
             !(facts->proof_index && cf_equal(cf_str(symbol, "kind"), "ConstFunction"))) ||
            !cf_uint(symbol, "type", &type) || type ||
            yyjson_is_true(yyjson_obj_get(symbol, "ambiguous")) ||
            facts->symbols[target - 1].external || facts->symbols[target - 1].excluded ||
            !cf_equal(cf_str(decl, "path"), file->path) ||
            !cf_equal(cf_str(decl, "sha256"), file->sha256) ||
            !cf_equal(cf_str(site, "target_package"), facts->symbols[target - 1].package) ||
            !cf_equal(cf_str(symbol, "name"), cf_str(proof, "name")) ||
            (!facts->proof_index &&
             (!cf_local_contexts(projects, yyjson_obj_get(site, "contexts"), file->path) ||
              !cf_local_contexts(projects, yyjson_obj_get(symbol, "contexts"), file->path))))
            goto done;
        entries[count++] = (CFLocalProof){file, site, symbol, proof};
        used[target - 1] = true;
    }
    for (size_t i = 0; i < facts->symbol_count; i++)
        if (!facts->proof_index && !used[i])
            goto done;
    if (count > 1)
        qsort(entries, count, sizeof(*entries), cf_local_proof_compare);
    for (size_t i = 0; i < count;) {
        const CFFile *file = entries[i].file;
        if (file->length > 8U * 1024U * 1024U ||
            file->length > CF_MAX_LOCAL_AST_BYTES - ast_bytes)
            goto done;
        size_t path_length = strlen(file->path);
        char tail[7] = {0};
        size_t tail_length = path_length < 6 ? path_length : 6;
        for (size_t t = 0; t < tail_length; t++)
            tail[t] = (char)tolower((unsigned char)file->path[path_length - tail_length + t]);
        if ((tail_length >= 5 && cf_equal(tail + tail_length - 5, ".d.ts")) ||
            cf_equal(tail, ".d.mts") || cf_equal(tail, ".d.cts"))
            goto done;
        ast_bytes += file->length;
        char path[CF_PATH_SIZE], hash[65];
        int written = snprintf(path, sizeof(path), "%s/%s", canonical, file->path);
        if (written < 0 || (size_t)written >= sizeof(path))
            goto done;
        FILE *input = cbm_fopen(path, "rb");
        char *source = input ? malloc((size_t)file->length + 1) : NULL;
        bool valid = source && fread(source, 1, (size_t)file->length, input) == file->length &&
                     fgetc(input) == EOF && !ferror(input);
        if (input)
            valid = fclose(input) == 0 && valid;
        if (valid)
            cbm_sha256_hex(source, (size_t)file->length, hash);
        valid = valid && cf_equal(hash, file->sha256);
        TSParser *parser = valid ? ts_parser_new() : NULL;
        const char *extension = strrchr(file->path, '.');
        char suffix[5] = {0};
        if (extension && strlen(extension) < sizeof(suffix))
            for (size_t s = 0; extension[s]; s++)
                suffix[s] = (char)tolower((unsigned char)extension[s]);
        const TSLanguage *language =
            cf_equal(suffix, ".tsx") ? tree_sitter_tsx()
            : cf_equal(suffix, ".js") || cf_equal(suffix, ".mjs") || cf_equal(suffix, ".cjs")
                ? tree_sitter_javascript()
            : cf_equal(suffix, ".ts") || cf_equal(suffix, ".mts") || cf_equal(suffix, ".cts")
                ? tree_sitter_typescript()
                : NULL;
        TSTree *tree = parser && language && ts_parser_set_language(parser, language)
                           ? ts_parser_parse_string(parser, NULL, source, (uint32_t)file->length)
                           : NULL;
        TSNode syntax = tree ? ts_tree_root_node(tree) : (TSNode){0};
        valid = tree && !ts_node_has_error(syntax);
        bool module = false;
        size_t first = i, limit = i + 1;
        while (limit < count && entries[limit].file == file)
            limit++;
        valid = valid && cf_local_inventory(syntax, source, entries + first, limit - first,
                                            &ast_nodes, facts->proof_index ? &module : NULL, 1);
        CFLocalClosures closures = {0};
        do {
            if (i && cf_local_proof_compare(&entries[i - 1], &entries[i]) == 0)
                valid = false;
            valid = valid && cf_local_ast(syntax, source, &entries[i], module, &closures, &ast_nodes);
            i++;
        } while (i < count && entries[i].file == file);
        if (tree)
            ts_tree_delete(tree);
        if (parser)
            ts_parser_delete(parser);
        free(source);
        if (!valid)
            goto done;
    }
    reason = NULL;
done:
    free(entries);
    free(used);
    return reason;
}

CBMCompilerFacts *cbm_compiler_facts_parse(const char *json, size_t length, const char *root,
                                           const char *language, const CBMCompilerInput *inputs,
                                           size_t input_count, const cbm_gbuf_t *gbuf, char *error,
                                           size_t error_size) {
    if (error && error_size)
        error[0] = '\0';
    const char *reason = "invalid compiler facts arguments";
    char snapshot_reason[256];
    CBMCompilerFacts *facts = NULL;
    CFGraph graph = {0};
    bool go = cf_equal(language, "go");
    if (!json || !length || length > CF_MAX_JSON || !root || !inputs || !input_count ||
        input_count > CF_MAX_FILES || !gbuf || (!go && !cf_equal(language, "typescript")))
        goto reject;
    char canonical[CF_PATH_SIZE];
    if (cf_temporary(root) || !cbm_canonical_path(root, canonical, sizeof(canonical)) ||
        cf_temporary(canonical)) {
        reason = "invalid canonical discovery root";
        goto reject;
    }
    cf_slashes(canonical);
    facts = calloc(1, sizeof(*facts));
    if (!facts) {
        reason = "out of memory";
        goto reject;
    }
    facts->type_budget = CF_MAX_TYPE_BYTES;
    facts->doc = yyjson_read(json, length, 0);
    yyjson_val *value = facts->doc ? yyjson_doc_get_root(facts->doc) : NULL;
    uint64_t schema = 0;
    if (!yyjson_is_obj(value) || !cf_json_shape(value, 0) || !cf_uint(value, "schema", &schema) ||
        (schema != 1 &&
         (go || schema != 2 ||
          !cf_equal(cf_str(value, "kind"), "typescript_local_target_index"))) ||
        !cf_equal(cf_str(value, "language"), language) ||
        !cf_equal(cf_str(value, "helper_version"), go ? "go-package-facts-2" : "1.1.0")) {
        reason = "unsupported or incomplete compiler snapshot";
        goto reject;
    }
    facts->local_target_index = !go && schema == 2;
    if (!facts->local_target_index &&
        (!cf_equal(cf_str(value, "status"), "ok") ||
         !yyjson_is_true(yyjson_obj_get(value, "complete")) || !cf_empty_array(value, "errors") ||
         !cf_empty_array(value, "diagnostics"))) {
        char status[32], detail[176];
        const char *message =
            go ? cf_string(yyjson_arr_get(yyjson_obj_get(value, "errors"), 0)) : NULL;
        if (!message || !*message)
            message = cf_str(value, "message");
        cf_diagnostic_text(status, sizeof(status), cf_str(value, "status"));
        cf_diagnostic_text(detail, sizeof(detail), message);
        snprintf(snapshot_reason, sizeof(snapshot_reason),
                 "unsupported or incomplete compiler snapshot%s%s%s%s", status[0] ? ": " : "",
                 status, detail[0] ? ": " : "", detail);
        reason = snapshot_reason;
        goto reject;
    }
    const char *reported_root = cf_str(value, "root");
    if (!reported_root || !cf_path_equal(reported_root, canonical) || cf_temporary(reported_root)) {
        reason = "compiler snapshot root differs";
        goto reject;
    }
    if ((reason = cf_context(value, go, false, inputs, input_count)) ||
        (reason = cf_files(facts, value, canonical, inputs, input_count)) ||
        (reason = cf_packages(facts, value, go)))
        goto reject;
    if (facts->local_target_index && (reason = cf_local_envelope(facts, value, canonical)))
        goto reject;
    if (go) {
        yyjson_val *cache = yyjson_obj_get(value, "cache");
        yyjson_val *keys = yyjson_obj_get(cache, "package_keys");
        if (!cbm_compiler_facts_go_package_manifest_valid(cache, inputs, input_count) ||
            yyjson_obj_size(keys) != facts->package_count) {
            reason = "invalid Go package manifest";
            goto reject;
        }
        for (size_t i = 0; i < facts->package_count; i++) {
            if (!yyjson_obj_get(keys, facts->packages[i].id)) {
                reason = "Go package manifest differs";
                goto reject;
            }
        }
    }
    yyjson_val *types = yyjson_obj_get(value, "types");
    yyjson_val *symbols = yyjson_obj_get(value, "symbols");
    yyjson_val *sites = yyjson_obj_get(value, "sites");
    /* Go omits empty collections; TypeScript emits them as empty arrays. */
    if ((types && !yyjson_is_arr(types)) || (symbols && !yyjson_is_arr(symbols)) ||
        (sites && !yyjson_is_arr(sites)) || (!go && (!types || !symbols || !sites)) ||
        yyjson_arr_size(types) + yyjson_arr_size(symbols) > CF_MAX_IDENTITIES ||
        yyjson_arr_size(sites) > CF_MAX_SITES) {
        reason = "compiler collection budget exceeded";
        goto reject;
    }
    if ((reason = cf_types(facts, cf_value(types), yyjson_arr_size(symbols), go)))
        goto reject;
    graph.facts = facts;
    cbm_gbuf_foreach_node(gbuf, cf_graph_node, &graph);
    if (graph.failed) {
        reason = "declaration index budget or allocation failed";
        goto reject;
    }
    if (graph.count > 1)
        qsort(graph.items, graph.count, sizeof(*graph.items), cf_declaration_compare);
    if ((reason = cf_symbols(facts, cf_value(symbols), yyjson_arr_size(types), go, &graph)) ||
        (reason = cf_project_types(facts, cf_value(types), go, &graph)) ||
        (reason = cf_sites(facts, cf_value(sites), yyjson_arr_size(types), go, true, NULL)))
        goto reject;
    if (facts->local_target_index && (reason = cf_local_proofs(facts, value, canonical)))
        goto reject;
    if ((reason = cf_matches(facts, SIZE_MAX)))
        goto reject;
    free(graph.items);
    return facts;

reject:
    free(graph.items);
    cbm_compiler_facts_free(facts);
    if (error && error_size)
        cf_diagnostic_text(error, error_size, reason ? reason : "invalid compiler facts");
    return NULL;
}

struct CFIndexPackage {
    const char *id;
    const char *path;
    const char *key;
    yyjson_val *json;
    yyjson_val *files;
    CBMCompilerFacts *facts;
    bool complete;
};

typedef struct {
    const CFRow *row;
    size_t package;
} CFIndexRow;

static int cf_index_package_compare(const void *a, const void *b) {
    return strcmp(((const CFIndexPackage *)a)->id, ((const CFIndexPackage *)b)->id);
}

static CFIndexPackage *cf_index_package(CFIndexPackage *packages, size_t count, const char *id) {
    if (!id || !count)
        return NULL;
    CFIndexPackage key = {.id = id};
    return bsearch(&key, packages, count, sizeof(*packages), cf_index_package_compare);
}

static bool cf_sorted_strings(yyjson_val *array, bool paths) {
    if (!yyjson_is_arr(array))
        return false;
    const char *previous = NULL;
    for (size_t i = 0; i < yyjson_arr_size(array); i++) {
        const char *value = cf_string(yyjson_arr_get(array, i));
        if (!value || !*value || strlen(value) >= CF_PATH_SIZE ||
            (paths && !cf_relative(value)) || (previous && strcmp(previous, value) >= 0))
            return false;
        previous = value;
    }
    return true;
}

static bool cf_string_member(yyjson_val *array, const char *value) {
    size_t low = 0, high = yyjson_arr_size(array);
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        int delta = strcmp(cf_string(yyjson_arr_get(array, middle)), value);
        if (delta < 0)
            low = middle + 1;
        else
            high = middle;
    }
    return low < yyjson_arr_size(array) &&
           cf_equal(cf_string(yyjson_arr_get(array, low)), value);
}

static bool cf_same_strings(yyjson_val *a, yyjson_val *b) {
    if (!yyjson_is_arr(a) || !yyjson_is_arr(b) || yyjson_arr_size(a) != yyjson_arr_size(b))
        return false;
    for (size_t i = 0; i < yyjson_arr_size(a); i++) {
        if (!cf_equal(cf_string(yyjson_arr_get(a, i)), cf_string(yyjson_arr_get(b, i))))
            return false;
    }
    return true;
}

static const char *cf_optional_string(yyjson_val *object, const char *key) {
    yyjson_val *value = yyjson_obj_get(object, key);
    return value ? yyjson_get_str(value) : "";
}

static void cf_digest_finish(cbm_sha256_ctx *hash, char hex[CBM_SHA256_HEX_LEN + 1]) {
    uint8_t bytes[CBM_SHA256_DIGEST_LEN];
    cbm_sha256_final(hash, bytes);
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(bytes); i++) {
        hex[i * 2] = digits[bytes[i] >> 4];
        hex[i * 2 + 1] = digits[bytes[i] & 15];
    }
    hex[CBM_SHA256_HEX_LEN] = '\0';
}

/* packageCache is written by encoding/json in this fixed field order. Hash
 * the original suffix so Go's escaping, omitted fields and nil arrays survive. */
static bool cf_fragment_payload(const char *data, size_t length, yyjson_val *value) {
    const char *key = cf_str(value, "Key"), *helper = cf_str(value, "HelperSHA256");
    const char *payload = cf_str(value, "PayloadSHA256");
    if (!cf_hash(key) || !cf_hash(helper) || !cf_hash(payload))
        return false;
    char prefix[288];
    int n = snprintf(prefix, sizeof(prefix),
                     "{\"Key\":\"%s\",\"HelperSHA256\":\"%s\",\"PayloadSHA256\":\"%s\"",
                     key, helper, payload);
    if (n < 0 || (size_t)n >= sizeof(prefix) || (size_t)n >= length ||
        memcmp(data, prefix, (size_t)n) != 0 || data[n] != ',')
        return false;
    static const char empty[] = "{\"Key\":\"\",\"HelperSHA256\":\"\",\"PayloadSHA256\":\"\"";
    cbm_sha256_ctx hash;
    cbm_sha256_init(&hash);
    cbm_sha256_update(&hash, empty, sizeof(empty) - 1);
    cbm_sha256_update(&hash, data + n, length - (size_t)n);
    char actual[CBM_SHA256_HEX_LEN + 1];
    cf_digest_finish(&hash, actual);
    return cf_equal(payload, actual);
}

static char *cf_fragment_read(const char *directory, const char *name, size_t length,
                              const char *sha256) {
    char joined[CF_PATH_SIZE], actual[CF_PATH_SIZE];
    cbm_path_info_t before, after;
    int n = snprintf(joined, sizeof(joined), "%s/%s", directory, name);
    if (n < 0 || (size_t)n >= sizeof(joined) ||
        !cbm_canonical_path(joined, actual, sizeof(actual)) || !cf_path_equal(joined, actual) ||
        cbm_path_info_utf8(joined, &before) != CBM_PATH_INFO_OK || !before.is_regular ||
        before.is_symlink || before.size < 0 || (uint64_t)before.size != length)
        return NULL;
    FILE *file = cbm_fopen(actual, "rb");
    char *data = file ? malloc(length + 1) : NULL;
    if (!data) {
        if (file)
            fclose(file);
        return NULL;
    }
    bool valid = fread(data, 1, length, file) == length && fgetc(file) == EOF && !ferror(file);
    fclose(file);
    data[length] = '\0';
    char hash[CBM_SHA256_HEX_LEN + 1];
    cbm_sha256_hex(data, length, hash);
    if (!valid || !cf_equal(hash, sha256) ||
        !cbm_canonical_path(joined, actual, sizeof(actual)) || !cf_path_equal(joined, actual) ||
        cbm_path_info_utf8(joined, &after) != CBM_PATH_INFO_OK || !after.is_regular ||
        after.is_symlink || after.size != before.size || after.mtime_ns != before.mtime_ns) {
        free(data);
        return NULL;
    }
    return data;
}

static bool cf_fragment_collections(yyjson_val *value, const char *key) {
    yyjson_val *array = yyjson_obj_get(value, key);
    return array && (yyjson_is_arr(array) || yyjson_is_null(array));
}

static const char *cf_index_fragment(CBMCompilerFacts *parent, CFIndexPackage *package,
                                     const CFGraph *graph, size_t *json_bytes,
                                     size_t *sites, size_t *projection_bytes) {
    yyjson_val *descriptor = yyjson_obj_get(package->json, "fragment");
    uint64_t bytes, type_count, symbol_count, site_count;
    char basename[96];
    snprintf(basename, sizeof(basename), "package-%s.json", package->key);
    if (!yyjson_is_obj(descriptor) || !cf_equal(cf_str(descriptor, "file"), basename) ||
        !cf_hash(cf_str(descriptor, "sha256")) || !cf_uint(descriptor, "byte_length", &bytes) ||
        !bytes || bytes > CF_MAX_JSON - *json_bytes ||
        !cf_uint(descriptor, "types", &type_count) ||
        !cf_uint(descriptor, "symbols", &symbol_count) ||
        type_count > CF_MAX_IDENTITIES || symbol_count > CF_MAX_IDENTITIES - type_count ||
        !cf_uint(descriptor, "sites", &site_count) || site_count > CF_MAX_SITES - *sites)
        return "invalid package fragment descriptor or aggregate budget";
    char *data = cf_fragment_read(parent->fragment_directory, basename, (size_t)bytes,
                                  cf_str(descriptor, "sha256"));
    if (!data)
        return "package fragment path, length or digest differs";
    CBMCompilerFacts *child = calloc(1, sizeof(*child));
    if (!child) {
        free(data);
        return "out of memory";
    }
    parent->children[parent->child_count++] = child;
    child->borrowed_tables = true;
    child->package_fragment = true;
    child->files = parent->files;
    child->file_count = parent->file_count;
    child->packages = parent->packages;
    child->package_count = parent->package_count;
    child->type_budget = CF_MAX_TYPE_BYTES - *projection_bytes;
    child->doc = yyjson_read(data, (size_t)bytes, 0);
    yyjson_val *value = child->doc ? yyjson_doc_get_root(child->doc) : NULL;
    yyjson_val *meta = yyjson_obj_get(value, "Package");
    yyjson_val *context = yyjson_obj_get(cbm_compiler_facts_json(parent), "context");
    bool valid =
        yyjson_is_obj(value) && yyjson_obj_size(value) == 7 && cf_json_shape(value, 0) &&
        cf_fragment_payload(data, (size_t)bytes, value) &&
        cf_equal(cf_str(value, "Key"), package->key) &&
        cf_equal(cf_str(value, "HelperSHA256"), cf_str(context, "helper_sha256")) &&
        cf_equal(cf_str(meta, "id"), package->id) &&
        cf_equal(cf_str(meta, "path"), package->path) &&
        cf_equal(cf_str(meta, "dir"), cf_str(package->json, "dir")) &&
        cf_equal(cf_str(meta, "name"), cf_str(package->json, "name")) &&
        cf_equal(cf_optional_string(meta, "for_test"),
                 cf_optional_string(package->json, "for_test")) &&
        yyjson_is_false(yyjson_obj_get(meta, "ill_typed")) && cf_empty_array(meta, "errors") &&
        cf_fragment_collections(value, "Types") && cf_fragment_collections(value, "Symbols") &&
        cf_fragment_collections(value, "Sites");
    free(data);
    if (!valid)
        return "invalid package fragment identity or payload";
    yyjson_val *types = yyjson_obj_get(value, "Types");
    yyjson_val *symbols = yyjson_obj_get(value, "Symbols");
    yyjson_val *calls = yyjson_obj_get(value, "Sites");
    if (yyjson_arr_size(types) != type_count || yyjson_arr_size(symbols) != symbol_count ||
        yyjson_arr_size(calls) != site_count)
        return "package fragment counts differ";
    size_t i, count;
    yyjson_val *site;
    yyjson_arr_foreach(calls, i, count, site) {
        const char *path = cf_str(site, "path");
        if (!cf_equal(cf_str(site, "package_id"), package->id) || !cf_relative(path) ||
            !cf_string_member(package->files, path))
            return "package fragment site membership differs";
    }
    const char *reason;
    if ((reason = cf_types(child, cf_value(types), (size_t)symbol_count, true)) ||
        (reason = cf_symbols(child, cf_value(symbols), (size_t)type_count, true, graph)) ||
        (reason = cf_project_types(child, cf_value(types), true, graph)) ||
        (reason = cf_sites(child, cf_value(calls), (size_t)type_count, true, true,
                           cf_str(cbm_compiler_facts_json(parent), "root"))))
        return reason;
    if (child->row_count != site_count)
        return "duplicate package fragment occurrence";
    size_t used = cf_arena_bytes(child) + child->auxiliary_bytes;
    if (used > CF_MAX_TYPE_BYTES - *projection_bytes)
        return "aggregate package projection budget exceeded";
    *json_bytes += (size_t)bytes;
    *sites += (size_t)site_count;
    *projection_bytes += used;
    package->facts = child;
    return NULL;
}

static int cf_index_row_compare(const void *a, const void *b) {
    return cf_row_compare(((const CFIndexRow *)a)->row, ((const CFIndexRow *)b)->row);
}

static void cf_unknown_row(CFRow *row, const char *reason) {
    row->site.dispatch = "unknown";
    row->site.reason = reason;
    row->site.target_qn = NULL;
    row->site.target_package = NULL;
    row->site.symbol_name = NULL;
    row->site.route_handler_qn = NULL;
    row->site.external_symbol = false;
    row->site.type = cbm_type_unknown();
    row->site.signature = cbm_type_unknown();
    row->site.receiver = cbm_type_unknown();
    row->site.contextual_params = NULL;
    row->site.contextual_param_count = 0;
    row->symbol = NULL;
}

static const char *cf_index_rows(CBMCompilerFacts *facts, CFIndexPackage *packages,
                                 size_t package_count, const bool *eligible,
                                 const size_t *members, size_t count,
                                 size_t projection_budget_bytes) {
    /* Sorting scratch is released before the final alias index is allocated. */
    size_t index_width = sizeof(CFIndexRow) > sizeof(*facts->matches) * 2
                             ? sizeof(CFIndexRow) : sizeof(*facts->matches) * 2;
    if (count > projection_budget_bytes / index_width)
        return "chunk consensus projection budget exceeded";
    projection_budget_bytes -= count * index_width;
    CFIndexRow *rows = count ? malloc(count * sizeof(*rows)) : NULL;
    if (count && !rows)
        return "out of memory";
    size_t size = 0;
    for (size_t i = 0; i < package_count; i++) {
        const CBMCompilerFacts *child = packages[i].facts;
        for (size_t j = 0; child && j < child->row_count; j++) {
            const CFRow *row = &child->rows[j];
            const CFFile *file = cf_file(facts, row->site.path);
            if (eligible[file - facts->files])
                rows[size++] = (CFIndexRow){row, i};
        }
    }
    if (size > 1)
        qsort(rows, size, sizeof(*rows), cf_index_row_compare);
    size_t unique = 0;
    for (size_t i = 0; i < size; i++)
        unique += !i || cf_row_compare(rows[i - 1].row, rows[i].row) != 0;
    /* Variants share consensus rows; every original alias still needs a match. */
    if (unique > projection_budget_bytes / sizeof(*facts->rows)) {
        free(rows);
        return "chunk consensus projection budget exceeded";
    }
    projection_budget_bytes -= unique * sizeof(*facts->rows);
    facts->rows = unique ? calloc(unique, sizeof(*facts->rows)) : NULL;
    if (unique && !facts->rows) {
        free(rows);
        return "out of memory";
    }
    for (size_t i = 0; i < size;) {
        const CFRow *first = rows[i].row;
        size_t next = i + 1;
        bool conflict = false;
        CFRow result = *first;
        while (next < size && cf_row_compare(first, rows[next].row) == 0) {
            if (!cf_same_target(first, rows[next].row))
                conflict = true;
            if (!cf_equal(result.site.route_handler_qn, rows[next].row->site.route_handler_qn))
                result.site.route_handler_qn = NULL;
            next++;
        }
        const CFFile *file = cf_file(facts, first->site.path);
        if (next - i != members[file - facts->files])
            cf_unknown_row(&result, "variant_site_missing");
        else if (conflict)
            cf_unknown_row(&result, "variant_conflict");
        facts->rows[facts->row_count++] = result;
        i = next;
    }
    free(rows);
    facts->matches = count ? malloc(count * 2 * sizeof(*facts->matches)) : NULL;
    if (count && !facts->matches)
        return "out of memory";
    /* Revisit the retained children to preserve every original variant alias. */
    for (size_t i = 0; i < package_count; i++) {
        const CBMCompilerFacts *child = packages[i].facts;
        for (size_t j = 0; child && j < child->row_count; j++) {
            const CFRow *original = &child->rows[j];
            const CFFile *file = cf_file(facts, original->site.path);
            if (!eligible[file - facts->files])
                continue;
            const CFRow *consensus = bsearch(original, facts->rows, facts->row_count,
                                             sizeof(*facts->rows), cf_row_compare);
            if (!consensus)
                return "chunk consensus occurrence missing";
            size_t index = (size_t)(consensus - facts->rows);
            const CBMCompilerSite *site = &original->site;
            facts->matches[facts->match_count++] =
                (CFMatch){site->path, site->sha256, site->start_byte, site->end_byte, index};
            facts->matches[facts->match_count++] =
                (CFMatch){site->path, site->sha256, site->callee_start_byte,
                           site->callee_end_byte, index};
        }
    }
    return cf_matches(facts, projection_budget_bytes);
}

static bool cf_index_summary(yyjson_val *value, size_t files, size_t selected, size_t packages,
                             size_t failed, size_t unprocessed, size_t authoritative) {
    static const char *const names[] = {
        "manifest_files", "selected_files", "not_selected_files", "selected_packages",
        "complete_packages", "failed_packages", "unprocessed_packages", "authoritative_files",
        "variant_blocked_files"};
    size_t counts[] = {files, selected, files - selected, packages, packages - failed,
                       failed - unprocessed, unprocessed, authoritative, selected - authoritative};
    yyjson_val *summary = yyjson_obj_get(value, "summary");
    if (!yyjson_is_obj(summary))
        return false;
    yyjson_obj_iter iter = yyjson_obj_iter_with(summary);
    yyjson_val *key;
    while ((key = yyjson_obj_iter_next(&iter))) {
        bool known = false;
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
            known = known || cf_equal(cf_string(key), names[i]);
        if (!known)
            return false;
    }
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        yyjson_val *count = yyjson_obj_get(summary, names[i]);
        if ((!count && (counts[i] != 0 || i == 0 || i == 3)) ||
            (count && (!yyjson_is_uint(count) || yyjson_get_uint(count) != counts[i])))
            return false;
    }
    return true;
}

static bool cf_object_fields(yyjson_val *value, const char *const *names, size_t count) {
    if (!yyjson_is_obj(value) || yyjson_obj_size(value) != count)
        return false;
    for (size_t i = 0; i < count; i++) {
        if (!yyjson_obj_get(value, names[i]))
            return false;
    }
    return true;
}

enum {
    CFV_TEXT = -1, CFV_UINT = -2, CFV_INT = -3, CFV_BOOL = -4,
    CFV_TEXTS = -5, CFV_REFS = -6, CFV_MEMBERS = -7,
    CFV_TYPES = -8, CFV_SYMBOLS = -9, CFV_SITES = -10
};

static const int8_t cf_compact_kinds[][19] = {
    {1, CFV_TYPES, CFV_SYMBOLS, CFV_SITES},
    {CFV_TEXT, CFV_TEXT, CFV_TEXT, CFV_TEXT, CFV_TEXT, CFV_BOOL, CFV_TEXTS},
    {CFV_UINT, CFV_TEXT, CFV_TEXT, CFV_TEXT, CFV_UINT, CFV_UINT, CFV_UINT, CFV_UINT,
     CFV_INT, CFV_INT, CFV_UINT, CFV_BOOL, CFV_REFS, CFV_REFS, CFV_REFS, CFV_REFS,
     CFV_MEMBERS, CFV_MEMBERS, CFV_REFS},
    {CFV_TEXT, CFV_UINT, CFV_TEXT, CFV_BOOL},
    {CFV_UINT, CFV_TEXT, CFV_TEXT, CFV_TEXT, CFV_TEXT, CFV_BOOL, CFV_UINT, CFV_UINT,
     5, CFV_TEXT},
    {CFV_TEXT, CFV_TEXT, CFV_UINT, CFV_UINT, CFV_UINT, CFV_UINT},
    {CFV_TEXT, CFV_TEXT, CFV_TEXT, CFV_UINT, CFV_UINT, CFV_UINT, CFV_UINT, CFV_TEXT,
     CFV_TEXT, CFV_UINT, CFV_TEXT, CFV_UINT, CFV_UINT, CFV_REFS, CFV_REFS, CFV_UINT},
};

static bool cf_compact_walk(CFValue value, CFCompact *codec, int kind, unsigned depth) {
    if (!value.raw || depth > 64)
        return false;
    if (kind == CFV_TEXT) {
        if (!cfv_string(value))
            return false;
        size_t index = (size_t)(-(yyjson_get_sint(value.raw) + 1));
        if (index > codec->next_string)
            return false;
        if (index == codec->next_string)
            codec->next_string++;
        return true;
    }
    if (kind == CFV_UINT)
        return cfv_is_uint(value);
    if (kind == CFV_BOOL)
        return cfv_is_bool(value);
    if (kind == CFV_INT) {
        if (cfv_is_uint(value))
            return cfv_get_uint(value) <= INT64_MAX;
        yyjson_val *tag = yyjson_arr_get_first(value.raw);
        yyjson_val *number = yyjson_arr_get(value.raw, 1);
        return yyjson_arr_size(value.raw) == 2 && yyjson_is_sint(tag) &&
               yyjson_get_sint(tag) == -2 && yyjson_is_sint(number) &&
               yyjson_get_sint(number) < 0;
    }
    if (kind < 0) {
        if (kind <= CFV_TYPES && cfv_is_null(value))
            return true;
        if (!cfv_is_arr(value))
            return false;
        int element = kind == CFV_TEXTS ? CFV_TEXT : kind == CFV_REFS ? CFV_UINT
                      : kind == CFV_MEMBERS ? 3 : kind == CFV_TYPES ? 2
                      : kind == CFV_SYMBOLS ? 4 : 6;
        size_t i, count;
        CFValue item;
        cfv_foreach(value, i, count, item) {
            if (!cf_compact_walk(item, codec, element, depth + 1))
                return false;
        }
        return true;
    }
    if (!cfv_is_obj(value))
        return false;
    uint64_t index = yyjson_get_uint(yyjson_arr_get_first(value.raw));
    if (index >= codec->schema_count || index > codec->next_schema)
        return false;
    if (index == codec->next_schema)
        codec->next_schema++;
    const CFCompactSchema *schema = &codec->schemas[index];
    if (schema->family != kind)
        return false;
    yyjson_arr_iter iter = yyjson_arr_iter_with(value.raw);
    yyjson_arr_iter_next(&iter);
    size_t fields = 0;
    for (size_t slot = 0; slot < 19; slot++) {
        if (!(schema->slots & (UINT32_C(1) << slot)))
            continue;
        CFValue field = {yyjson_arr_iter_next(&iter), codec};
        if (!cf_compact_walk(field, codec, cf_compact_kinds[kind][slot], depth + 1))
            return false;
        fields++;
    }
    return yyjson_arr_size(value.raw) == fields + 1;
}

static int cf_compact_key_compare(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left, b = *(const uint64_t *)right;
    return a == b ? 0 : a < b ? -1 : 1;
}

static bool cf_compact_numbers(const char *data, size_t length) {
    bool quoted = false;
    for (size_t i = 0; i < length; i++) {
        if (data[i] == '"')
            quoted = !quoted;
        else if (quoted && data[i] == '\\')
            i++;
        else if (!quoted && data[i] == '-' && i + 1 < length && data[i + 1] == '0')
            return false;
    }
    return true;
}

static bool cf_compact_payload(const char *data, size_t length, yyjson_val *value) {
    static const char *const names[] = {
        "Key", "HelperSHA256", "PayloadSHA256", "Strings", "Schemas", "Root"};
    if (!cf_object_fields(value, names, sizeof(names) / sizeof(*names)) ||
        !cf_fragment_payload(data, length, value) || !cf_compact_numbers(data, length))
        return false;
    yyjson_obj_iter iter = yyjson_obj_iter_with(value);
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++) {
        if (!cf_equal(cf_string(yyjson_obj_iter_next(&iter)), names[i]))
            return false;
    }
    char prefix[304];
    int n = snprintf(prefix, sizeof(prefix),
                     "{\"Key\":\"%s\",\"HelperSHA256\":\"%s\",\"PayloadSHA256\":\"%s\","
                     "\"Strings\":",
                     cf_str(value, "Key"), cf_str(value, "HelperSHA256"),
                     cf_str(value, "PayloadSHA256"));
    return n > 0 && (size_t)n < sizeof(prefix) && (size_t)n < length &&
           memcmp(data, prefix, (size_t)n) == 0;
}

static bool cf_compact_open(CBMCompilerFacts *facts) {
    static const uint8_t widths[] = {4, 7, 19, 4, 10, 6, 16};
    static const uint32_t required[] = {15, 47, 3, 3, 637, 63, 255};
    yyjson_val *root = yyjson_doc_get_root(facts->doc);
    yyjson_val *strings = yyjson_obj_get(root, "Strings");
    yyjson_val *schemas = yyjson_obj_get(root, "Schemas");
    size_t texts = yyjson_arr_size(strings), shapes = yyjson_arr_size(schemas);
    if (!yyjson_is_arr(strings) || !yyjson_is_arr(schemas) || !shapes ||
        !cf_charge_auxiliary(facts, 1, sizeof(*facts->compact)) ||
        !cf_charge_auxiliary(facts, texts, sizeof(const char *)) ||
        !cf_charge_auxiliary(facts, shapes, sizeof(CFCompactSchema)))
        return false;
    CFCompact *codec = calloc(1, sizeof(*codec));
    facts->compact = codec;
    if (!codec)
        return false;
    codec->string_count = texts;
    codec->schema_count = shapes;
    codec->strings = texts ? calloc(texts, sizeof(*codec->strings)) : NULL;
    codec->schemas = calloc(shapes, sizeof(*codec->schemas));
    if ((texts && !codec->strings) || !codec->schemas ||
        !cf_charge_auxiliary(facts, texts, sizeof(const char *)) ||
        !cf_charge_auxiliary(facts, shapes, sizeof(uint64_t)))
        return false;
    const char **ordered = texts ? malloc(texts * sizeof(*ordered)) : NULL;
    uint64_t *signatures = malloc(shapes * sizeof(*signatures));
    bool valid = (!texts || ordered) && signatures;
    size_t i, count;
    yyjson_val *item;
    if (valid) {
        yyjson_arr_foreach(strings, i, count, item) {
            const char *text = cf_string(item);
            if (!text) {
                valid = false;
                break;
            }
            codec->strings[i] = ordered[i] = text;
        }
    }
    if (valid && texts > 1) {
        qsort(ordered, texts, sizeof(*ordered), cf_string_compare);
        for (i = 1; i < texts; i++) {
            if (strcmp(ordered[i - 1], ordered[i]) == 0)
                valid = false;
        }
    }
    if (valid) {
        yyjson_arr_foreach(schemas, i, count, item) {
            yyjson_val *family = yyjson_arr_get_first(item);
            uint64_t f = yyjson_get_uint(family);
            if (!yyjson_is_arr(item) || !yyjson_is_uint(family) || f >= 7 ||
                yyjson_arr_size(item) > (size_t)widths[f] + 1) {
                valid = false;
                break;
            }
            CFCompactSchema *schema = &codec->schemas[i];
            schema->family = (uint8_t)f;
            yyjson_arr_iter iter = yyjson_arr_iter_with(item);
            yyjson_arr_iter_next(&iter);
            yyjson_val *slot;
            size_t position = 0, previous = 0;
            while ((slot = yyjson_arr_iter_next(&iter))) {
                uint64_t n = yyjson_get_uint(slot);
                if (!yyjson_is_uint(slot) || n >= widths[f] ||
                    (position && n <= previous)) {
                    valid = false;
                    break;
                }
                schema->slots |= UINT32_C(1) << n;
                schema->positions[n] = (uint8_t)++position;
                previous = (size_t)n;
            }
            if (!valid || (schema->slots & required[f]) != required[f]) {
                valid = false;
                break;
            }
            signatures[i] = (f << 32) | schema->slots;
        }
    }
    if (valid && shapes > 1) {
        qsort(signatures, shapes, sizeof(*signatures), cf_compact_key_compare);
        for (i = 1; i < shapes; i++) {
            if (signatures[i - 1] == signatures[i])
                valid = false;
        }
    }
    free(ordered);
    free(signatures);
    facts->auxiliary_bytes -= texts * sizeof(const char *) + shapes * sizeof(uint64_t);
    return valid && cf_compact_walk(cf_fact_root(facts), codec, 0, 0) &&
           codec->next_string == texts && codec->next_schema == shapes;
}

static bool cf_chunk_descriptor(yyjson_val *chunk, yyjson_val *descriptor,
                                 const CFIndexPackage *package) {
    static const char *const names[] = {
        "package_id", "key", "file", "sha256", "byte_length",
        "raw_sha256", "raw_byte_length", "types", "symbols", "sites"};
    uint64_t bytes, raw_bytes, types, symbols, sites;
    char basename[96], identity[130], hash[CBM_SHA256_HEX_LEN + 1];
    int n = snprintf(identity, sizeof(identity), "%s:%s", cf_str(chunk, "key"), package->key);
    if (n != 129)
        return false;
    cbm_sha256_hex(identity, (size_t)n, hash);
    n = snprintf(basename, sizeof(basename), "chunk-%s.json.gz", hash);
    return n > 0 && (size_t)n < sizeof(basename) &&
           yyjson_is_false(yyjson_obj_get(package->json, "ill_typed")) &&
           cf_object_fields(descriptor, names, sizeof(names) / sizeof(*names)) &&
           cf_equal(cf_str(descriptor, "package_id"), package->id) &&
           cf_equal(cf_str(descriptor, "key"), package->key) &&
           cf_equal(cf_str(descriptor, "file"), basename) &&
           cf_hash(cf_str(descriptor, "sha256")) &&
           cf_hash(cf_str(descriptor, "raw_sha256")) &&
           cf_uint(descriptor, "byte_length", &bytes) && bytes && bytes <= CF_MAX_JSON &&
           cf_uint(descriptor, "raw_byte_length", &raw_bytes) &&
           raw_bytes && raw_bytes <= CF_MAX_JSON &&
           cf_uint(descriptor, "types", &types) && types <= CF_CHUNK_MAX_IDENTITIES &&
           cf_uint(descriptor, "symbols", &symbols) && symbols <= CF_CHUNK_MAX_IDENTITIES &&
           cf_uint(descriptor, "sites", &sites) && sites <= CF_CHUNK_MAX_SITES;
}

static char *cf_chunk_inflate(const char *compressed, size_t length, size_t raw_length,
                               const char *sha256) {
    char *raw = malloc(raw_length + 1);
    if (!raw)
        return NULL;
    z_stream stream = {0};
    stream.next_in = (Bytef *)compressed;
    stream.avail_in = (uInt)length;
    stream.next_out = (Bytef *)raw;
    stream.avail_out = (uInt)(raw_length + 1);
    bool valid = false;
    if (inflateInit2(&stream, 16 + MAX_WBITS) == Z_OK) {
        int result = inflate(&stream, Z_FINISH);
        /* inflate stops at the first member: trailing bytes and a second
         * member are rejected along with truncated or oversized streams. */
        valid = result == Z_STREAM_END && stream.total_out == raw_length &&
                stream.total_in == length && stream.avail_in == 0;
        inflateEnd(&stream);
    }
    char actual[CBM_SHA256_HEX_LEN + 1];
    if (valid) {
        raw[raw_length] = '\0';
        cbm_sha256_hex(raw, raw_length, actual);
        valid = cf_equal(actual, sha256);
    }
    if (!valid) {
        free(raw);
        return NULL;
    }
    return raw;
}

static const char *cf_chunk_fragment(CBMCompilerFacts *parent, CBMCompilerFacts *view,
                                      CFIndexPackage *package, yyjson_val *chunk,
                                      yyjson_val *descriptor, const CFGraph *graph,
                                      size_t *sites, size_t *projection_bytes) {
    size_t bytes = (size_t)yyjson_get_uint(yyjson_obj_get(descriptor, "byte_length"));
    size_t raw_bytes = (size_t)yyjson_get_uint(yyjson_obj_get(descriptor, "raw_byte_length"));
    char *compressed = cf_fragment_read(parent->fragment_directory, cf_str(descriptor, "file"),
                                         bytes, cf_str(descriptor, "sha256"));
    char *data = compressed ? cf_chunk_inflate(compressed, bytes, raw_bytes,
                                               cf_str(descriptor, "raw_sha256")) : NULL;
    free(compressed);
    if (!data)
        return "chunk fragment path, gzip length or digest differs";
    CBMCompilerFacts *child = calloc(1, sizeof(*child));
    if (!child) {
        free(data);
        return "out of memory";
    }
    view->children[view->child_count++] = child;
    child->borrowed_tables = true;
    child->package_fragment = true;
    child->chunk_fragment = true;
    child->files = parent->files;
    child->file_count = parent->file_count;
    child->packages = parent->packages;
    child->package_count = parent->package_count;
    child->type_budget = CF_MAX_TYPE_BYTES - *projection_bytes;
    child->doc = yyjson_read(data, raw_bytes, 0);
    yyjson_val *value = child->doc ? yyjson_doc_get_root(child->doc) : NULL;
    yyjson_val *context = yyjson_obj_get(cbm_compiler_facts_json(parent), "context");
    bool valid = yyjson_is_obj(value) && cf_json_shape(value, 0);
    if (valid && parent->compact_index)
        valid = cf_compact_payload(data, raw_bytes, value) && cf_compact_open(child);
    else if (valid)
        valid = yyjson_obj_size(value) == 7 && cf_fragment_payload(data, raw_bytes, value);
    if (!valid) {
        free(data);
        return "invalid chunk fragment codec or payload";
    }
    CFValue logical = cf_fact_root(child);
    CFValue meta = cfv_get(logical, "Package");
    CFValue types = cfv_get(logical, "Types");
    CFValue symbols = cfv_get(logical, "Symbols");
    CFValue calls = cfv_get(logical, "Sites");
    valid = valid &&
        cf_equal(cf_str(value, "Key"), package->key) &&
        cf_equal(cf_str(value, "HelperSHA256"), cf_str(context, "helper_sha256")) &&
        cf_equal(cfv_str(meta, "id"), package->id) &&
        cf_equal(cfv_str(meta, "path"), package->path) &&
        cf_equal(cfv_str(meta, "dir"), cf_str(package->json, "dir")) &&
        cf_equal(cfv_str(meta, "name"), cf_str(package->json, "name")) &&
        cf_equal(cfv_optional_string(meta, "for_test"),
                 cf_optional_string(package->json, "for_test")) &&
        cfv_is_false(cfv_get(meta, "ill_typed")) && cfv_empty_array(meta, "errors") &&
        types.raw && (cfv_is_arr(types) || cfv_is_null(types)) &&
        symbols.raw && (cfv_is_arr(symbols) || cfv_is_null(symbols)) &&
        calls.raw && (cfv_is_arr(calls) || cfv_is_null(calls));
    free(data);
    if (!valid)
        return "invalid chunk fragment identity or payload";
    size_t type_count = cfv_size(types), symbol_count = cfv_size(symbols);
    size_t site_count = cfv_size(calls);
    if (type_count != yyjson_get_uint(yyjson_obj_get(descriptor, "types")) ||
        symbol_count != yyjson_get_uint(yyjson_obj_get(descriptor, "symbols")) ||
        site_count != yyjson_get_uint(yyjson_obj_get(descriptor, "sites")) ||
        site_count > CF_CHUNK_MAX_SITES - *sites)
        return "chunk fragment counts differ";
    yyjson_val *paths = yyjson_obj_get(chunk, "files");
    size_t i, count;
    CFValue site;
    cfv_foreach(calls, i, count, site) {
        const char *path = cfv_str(site, "path");
        if (!cf_equal(cfv_str(site, "package_id"), package->id) || !cf_relative(path) ||
            !cf_string_member(paths, path))
            return "chunk fragment site membership differs";
    }
    const char *reason;
    if ((reason = cf_types(child, types, symbol_count, true)) ||
        (reason = cf_symbols(child, symbols, type_count, true, graph)) ||
        (reason = cf_project_types(child, types, true, graph)) ||
        (reason = cf_sites(child, calls, type_count, true, true,
                           cf_str(cbm_compiler_facts_json(parent), "root"))))
        return reason;
    if (child->row_count != site_count)
        return "duplicate chunk fragment occurrence";
    size_t used = cf_arena_bytes(child) + child->auxiliary_bytes;
    if (used > CF_MAX_TYPE_BYTES - *projection_bytes)
        return "chunk projection budget exceeded";
    *projection_bytes += used;
    *sites += site_count;
    package->facts = child;
    return NULL;
}

static const char *cf_chunk_load(CBMCompilerFacts *facts, yyjson_val *chunk,
                                  CBMCompilerFacts **result) {
    *result = NULL;
    if (!cf_equal(cf_str(chunk, "status"), "complete"))
        return NULL;
    CBMCompilerFacts *view = calloc(1, sizeof(*view));
    if (!view)
        return "out of memory";
    view->borrowed_tables = true;
    view->files = facts->files;
    view->file_count = facts->file_count;
    view->packages = facts->packages;
    view->package_count = facts->package_count;
    yyjson_val *fragments = yyjson_obj_get(chunk, "fragments");
    size_t count = yyjson_arr_size(fragments);
    view->children = count ? calloc(count, sizeof(*view->children)) : NULL;
    const char *reason = count && !view->children ? "out of memory" : NULL;
    CFGraph graph = {.facts = facts, .items = facts->declarations,
                     .count = facts->declaration_count};
    size_t sites = 0, projection_bytes = facts->catalogue_bytes;
    size_t fixed_bytes = sizeof(*view) + count * (sizeof(*view->children) + sizeof(*view));
    if (fixed_bytes > CF_MAX_TYPE_BYTES - projection_bytes)
        reason = "chunk consensus projection budget exceeded";
    else
        projection_bytes += fixed_bytes;
    for (size_t i = 0; !reason && i < count; i++) {
        yyjson_val *descriptor = yyjson_arr_get(fragments, i);
        CFIndexPackage *package = cf_index_package(facts->index_packages, facts->package_count,
                                                    cf_str(descriptor, "package_id"));
        reason = cf_chunk_fragment(facts, view, package, chunk, descriptor, &graph,
                                     &sites, &projection_bytes);
    }
    if (!reason)
        reason = cf_index_rows(view, facts->index_packages, facts->package_count,
                                  facts->file_eligible, facts->file_members, sites,
                                  CF_MAX_TYPE_BYTES - projection_bytes);
    for (size_t i = 0; i < facts->package_count; i++)
        facts->index_packages[i].facts = NULL;
    if (reason)
        cbm_compiler_facts_free(view);
    else
        *result = view;
    return reason;
}

static bool cf_chunk_source_current(const CBMCompilerFacts *facts, const CFFile *file) {
    const char *root = cf_str(cbm_compiler_facts_json(facts), "root");
    char joined[CF_PATH_SIZE], actual[CF_PATH_SIZE];
    int n = file ? snprintf(joined, sizeof(joined), "%s%s%s", root,
                             root[strlen(root) - 1] == '/' ? "" : "/", file->path) : -1;
    CBMCompilerInput input = file
        ? (CBMCompilerInput){file->path, file->sha256, file->length} : (CBMCompilerInput){0};
    return n > 0 && (size_t)n < sizeof(joined) &&
           cbm_canonical_path(joined, actual, sizeof(actual)) &&
           cf_path_equal(joined, actual) && cf_source_current(actual, &input);
}

static const char *cf_chunk_sources(const CBMCompilerFacts *facts, yyjson_val *paths) {
    for (size_t i = 0; i < yyjson_arr_size(paths); i++) {
        const CFFile *file = cf_file(facts, cf_string(yyjson_arr_get(paths, i)));
        if (!cf_chunk_source_current(facts, file))
            return "chunk source hash, length or path changed";
    }
    return NULL;
}

static const char *cf_chunk_budgets(CBMCompilerFacts *facts, size_t selected_files,
                                     size_t compressed_bytes, size_t expanded_bytes,
                                     size_t completed_chunks) {
    static const char *const names[] = {
        "max_chunk_raw_bytes", "max_chunk_sites", "max_referenced_compressed_bytes",
        "max_expanded_bytes", "max_encoded_bytes", "max_export_attempts",
        "referenced_compressed_bytes", "expanded_bytes", "encoded_bytes", "export_attempts"};
    uint64_t expected[] = {CF_MAX_JSON, CF_CHUNK_MAX_SITES, CF_MAX_JSON,
                           CF_CHUNK_MAX_EXPANDED, CF_CHUNK_MAX_ENCODED,
                           selected_files * 2, compressed_bytes, expanded_bytes};
    yyjson_val *budgets = yyjson_obj_get(cbm_compiler_facts_json(facts), "budgets");
    if (!cf_object_fields(budgets, names, sizeof(names) / sizeof(*names)))
        return "invalid chunk budget ledger";
    uint64_t value;
    for (size_t i = 0; i < sizeof(expected) / sizeof(*expected); i++) {
        if (!cf_uint(budgets, names[i], &value) || value != expected[i])
            return "chunk budget ledger differs";
    }
    uint64_t encoded, attempts;
    if (!cf_uint(budgets, "encoded_bytes", &encoded) || encoded < expanded_bytes ||
        encoded > CF_CHUNK_MAX_ENCODED ||
        !cf_uint(budgets, "export_attempts", &attempts) || attempts < completed_chunks ||
        attempts > selected_files * 2)
        return "chunk encoding or export work budget exceeded";
    return NULL;
}

static const char *cf_own_declarations(CBMCompilerFacts *facts, CFGraph *graph, size_t arrays) {
    if (arrays > CF_MAX_TYPE_BYTES)
        return "owned chunk catalogue budget exceeded";
    size_t string_bytes = 0;
    for (size_t i = 0; i < graph->count; i++) {
        const char *strings[] = {graph->items[i].qn, graph->items[i].name};
        for (size_t j = 0; j < sizeof(strings) / sizeof(strings[0]); j++) {
            if (!strings[j])
                continue;
            size_t length = strlen(strings[j]);
            if (length >= CF_MAX_TYPE_BYTES)
                return "owned chunk catalogue budget exceeded";
            size_t aligned = (length + 8) & ~(size_t)7;
            if (aligned > CF_MAX_TYPE_BYTES - arrays - string_bytes)
                return "owned chunk catalogue budget exceeded";
            string_bytes += aligned;
        }
    }
    size_t capacity = string_bytes && string_bytes < CBM_ARENA_DEFAULT_BLOCK_SIZE
                          ? CBM_ARENA_DEFAULT_BLOCK_SIZE : string_bytes;
    if (capacity > CF_MAX_TYPE_BYTES - arrays)
        return "owned chunk catalogue budget exceeded";
    if (capacity) {
        cbm_arena_init_exact(&facts->declaration_arena, capacity);
        if (cbm_arena_capacity(&facts->declaration_arena) != capacity)
            return "out of memory";
    }
    for (size_t i = 0; i < graph->count; i++) {
        CFDeclaration *entry = &graph->items[i];
        bool has_name = entry->name != NULL;
        entry->qn = cbm_arena_strdup(&facts->declaration_arena, entry->qn);
        entry->name = has_name ? cbm_arena_strdup(&facts->declaration_arena, entry->name) : NULL;
        if (!entry->qn || (has_name && !entry->name))
            return "out of memory";
    }
    if (cbm_arena_capacity(&facts->declaration_arena) != capacity)
        return "owned chunk catalogue budget exceeded";
    facts->catalogue_bytes = arrays + cbm_arena_capacity(&facts->declaration_arena);
    if (facts->catalogue_bytes >= CF_MAX_TYPE_BYTES)
        return "owned chunk catalogue budget exceeded";
    facts->declarations = graph->items;
    facts->declaration_count = graph->count;
    graph->items = NULL;
    graph->count = graph->capacity = 0;
    return NULL;
}

static const char *cf_chunk_catalogue(CBMCompilerFacts *facts, CFGraph *graph,
                                       size_t selected_files) {
    yyjson_val *value = cbm_compiler_facts_json(facts);
    yyjson_val *chunks = yyjson_obj_get(value, "chunks");
    size_t count = yyjson_arr_size(chunks), compressed_bytes = 0, expanded_bytes = 0;
    size_t completed_chunks = 0;
    if (!yyjson_is_arr(chunks) || count > selected_files || (selected_files && !count))
        return "invalid chunk inventory";
    const char **keys = count ? malloc(count * sizeof(*keys)) : NULL;
    bool *package_complete = facts->package_count ? calloc(facts->package_count, sizeof(bool)) : NULL;
    if ((count && !keys) || (facts->package_count && !package_complete)) {
        free(keys);
        free(package_complete);
        return "out of memory";
    }
    const char *reason = NULL;
    for (size_t i = 0; i < facts->file_count; i++)
        facts->file_chunks[i] = SIZE_MAX;
    for (size_t i = 0; i < facts->package_count; i++)
        package_complete[i] = !yyjson_is_true(
            yyjson_obj_get(facts->index_packages[i].json, "ill_typed"));
    for (size_t i = 0; !reason && i < count; i++) {
        yyjson_val *chunk = yyjson_arr_get(chunks, i);
        yyjson_val *paths = yyjson_obj_get(chunk, "files");
        yyjson_val *ids = yyjson_obj_get(chunk, "package_ids");
        yyjson_val *fragments = yyjson_obj_get(chunk, "fragments");
        bool complete = cf_equal(cf_str(chunk, "status"), "complete");
        const char *status = cf_str(chunk, "status");
        static const char *const names[] = {
            "key", "files", "package_ids", "status", "fragments", "reason"};
        if (!cf_object_fields(chunk, names, complete ? 5 : 6) ||
            !cf_hash(cf_str(chunk, "key")) ||
            !cf_sorted_strings(paths, true) || !yyjson_arr_size(paths) ||
            !cf_sorted_strings(ids, false) || !yyjson_arr_size(ids) ||
            !yyjson_is_arr(fragments) ||
            (complete && yyjson_arr_size(fragments) != yyjson_arr_size(ids)) ||
            (!complete &&
             (!(cf_equal(status, "ill_typed") || cf_equal(status, "budget") ||
                cf_equal(status, "unprocessed")) || yyjson_arr_size(fragments) ||
              !cf_str(chunk, "reason") || !*cf_str(chunk, "reason")))) {
            reason = "invalid chunk entry";
            break;
        }
        keys[i] = cf_str(chunk, "key");
        completed_chunks += complete;
        for (size_t j = 0; j < yyjson_arr_size(paths); j++) {
            const CFFile *file = cf_file(facts, cf_string(yyjson_arr_get(paths, j)));
            size_t index = file ? (size_t)(file - facts->files) : SIZE_MAX;
            if (!file || !facts->file_members[index] || facts->file_chunks[index] != SIZE_MAX ||
                !cf_same_strings(ids, facts->file_package_ids[index])) {
                reason = "chunk file membership differs";
                break;
            }
            facts->file_chunks[index] = i;
        }
        size_t raw_bytes = 0, sites = 0;
        for (size_t j = 0; !reason && j < yyjson_arr_size(ids); j++) {
            CFIndexPackage *package = cf_index_package(facts->index_packages, facts->package_count,
                                                       cf_string(yyjson_arr_get(ids, j)));
            if (!package) {
                reason = "unknown chunk package variant";
                break;
            }
            package_complete[package - facts->index_packages] =
                package_complete[package - facts->index_packages] && complete;
            if (!complete)
                continue;
            yyjson_val *descriptor = yyjson_arr_get(fragments, j);
            if (!cf_chunk_descriptor(chunk, descriptor, package)) {
                reason = "invalid compressed chunk descriptor";
                break;
            }
            size_t bytes = (size_t)yyjson_get_uint(yyjson_obj_get(descriptor, "byte_length"));
            size_t raw = (size_t)yyjson_get_uint(yyjson_obj_get(descriptor, "raw_byte_length"));
            size_t calls = (size_t)yyjson_get_uint(yyjson_obj_get(descriptor, "sites"));
            if (bytes > CF_MAX_JSON - compressed_bytes ||
                raw > CF_MAX_JSON - raw_bytes ||
                raw > CF_CHUNK_MAX_EXPANDED - expanded_bytes ||
                calls > CF_CHUNK_MAX_SITES - sites) {
                reason = "compressed or expanded chunk aggregate budget exceeded";
                break;
            }
            compressed_bytes += bytes;
            expanded_bytes += raw;
            raw_bytes += raw;
            sites += calls;
        }
    }
    if (!reason && count > 1) {
        qsort(keys, count, sizeof(*keys), cf_string_compare);
        for (size_t i = 1; i < count; i++) {
            if (cf_equal(keys[i - 1], keys[i])) {
                reason = "duplicate chunk key";
                break;
            }
        }
    }
    for (size_t i = 0; !reason && i < facts->file_count; i++) {
        if ((facts->file_members[i] != 0) != (facts->file_chunks[i] != SIZE_MAX))
            reason = "incomplete chunk file inventory";
    }
    for (size_t i = 0; !reason && i < facts->package_count; i++) {
        if (package_complete[i] != facts->index_packages[i].complete)
            reason = "chunk and package completion differ";
    }
    free(keys);
    free(package_complete);
    if (!reason)
        reason = cf_chunk_budgets(facts, selected_files, compressed_bytes, expanded_bytes,
                                     completed_chunks);
    if (reason)
        return reason;
    size_t arrays = graph->capacity * sizeof(*graph->items) +
                    facts->file_count * (sizeof(CFFile) + sizeof(bool) +
                                         (facts->go_unselected ? sizeof(bool) : 0) + sizeof(size_t) * 2 +
                                         sizeof(yyjson_val *)) +
                    facts->package_count * (sizeof(CFPackage) + sizeof(CFIndexPackage));
    if ((reason = cf_own_declarations(facts, graph, arrays)))
        return reason;
    for (size_t i = 0; i < count; i++) {
        CBMCompilerFacts *view = NULL;
        reason = cf_chunk_load(facts, yyjson_arr_get(chunks, i), &view);
        if (reason)
            return reason;
        if (view && view->row_count > SIZE_MAX - facts->verified_sites) {
            cbm_compiler_facts_free(view);
            return "chunk consensus site count overflow";
        }
        facts->verified_sites += view ? view->row_count : 0;
        cbm_compiler_facts_free(view);
    }
    return NULL;
}

static CBMCompilerFacts *cf_parse_index(
    const char *json, size_t length, const char *root, const CBMCompilerInput *inputs,
    size_t input_count, const cbm_gbuf_t *gbuf, const char *fragment_directory, char *error,
    size_t error_size, bool chunks, bool compact) {
    if (error && error_size)
        error[0] = '\0';
    const char *reason = "invalid compiler package index arguments";
    CBMCompilerFacts *facts = NULL;
    CFIndexPackage *packages = NULL;
    bool *eligible = NULL;
    size_t *members = NULL;
    const char **keys = NULL;
    CFGraph graph = {0};
    if (!json || !length || length > CF_MAX_JSON || !root || !inputs || !input_count ||
        input_count > CF_MAX_FILES || !gbuf || !fragment_directory)
        goto reject;
    char canonical[CF_PATH_SIZE], directory[CF_PATH_SIZE];
    if (cf_temporary(root) || !cbm_canonical_path(root, canonical, sizeof(canonical)) ||
        cf_temporary(canonical) || cf_temporary(fragment_directory) ||
        !cbm_canonical_path(fragment_directory, directory, sizeof(directory)) ||
        cf_temporary(directory)) {
        reason = "invalid canonical index root or fragment directory";
        goto reject;
    }
    cf_slashes(canonical);
    cf_slashes(directory);
    facts = calloc(1, sizeof(*facts));
    if (!facts) {
        reason = "out of memory";
        goto reject;
    }
    facts->package_index = true;
    facts->chunk_index = chunks;
    facts->compact_index = compact;
    facts->active_chunk = SIZE_MAX;
    facts->fragment_directory = malloc(strlen(directory) + 1);
    if (!facts->fragment_directory) {
        reason = "out of memory";
        goto reject;
    }
    strcpy(facts->fragment_directory, directory);
    facts->doc = yyjson_read(json, length, 0);
    yyjson_val *value = facts->doc ? yyjson_doc_get_root(facts->doc) : NULL;
    uint64_t schema;
    bool complete = yyjson_is_true(yyjson_obj_get(value, "complete"));
    if (!yyjson_is_obj(value) || !cf_json_shape(value, 0) || !cf_uint(value, "schema", &schema) ||
        schema != (compact ? 4U : chunks ? 3U : 2U) ||
        !cf_equal(cf_str(value, "kind"), chunks ? "go_chunk_index" : "go_package_index") ||
        !cf_equal(cf_str(value, "language"), "go") ||
        !cf_equal(cf_str(value, "helper_version"),
                    compact ? "go-package-facts-5" : chunks ? "go-package-facts-4"
                                                            : "go-package-facts-3") ||
        (chunks && !cf_equal(cf_str(value, "profile"),
                            compact ? "chunk_index_v2" : "chunk_index_v1")) ||
        !yyjson_is_bool(yyjson_obj_get(value, "complete")) ||
        !cf_equal(cf_str(value, "status"), complete ? "ok" : "partial") ||
        !yyjson_is_true(yyjson_obj_get(value, "inventory_complete")) ||
        !yyjson_is_true(yyjson_obj_get(value, "input_snapshot_stable"))) {
        reason = "unsupported or incomplete compiler package inventory";
        goto reject;
    }
    if (!cf_path_equal(cf_str(value, "root"), canonical) ||
        cf_temporary(cf_str(value, "root"))) {
        reason = "compiler package index root differs";
        goto reject;
    }
    if ((reason = cf_context(value, true, true, inputs, input_count)) ||
        (reason = cf_files(facts, value, canonical, inputs, input_count)))
        goto reject;
    yyjson_val *package_array = yyjson_obj_get(value, "packages");
    yyjson_val *cache = yyjson_obj_get(value, "cache");
    yyjson_val *cache_keys = yyjson_obj_get(cache, "package_keys");
    yyjson_val *cache_files = yyjson_obj_get(cache, "package_files");
    size_t package_count = yyjson_arr_size(package_array);
    if (!yyjson_is_arr(package_array) || package_count > CF_MAX_FILES ||
        !yyjson_is_obj(cache_keys) || !yyjson_is_obj(cache_files) ||
        yyjson_obj_size(cache_keys) != package_count ||
        yyjson_obj_size(cache_files) != package_count ||
        (chunks && !yyjson_is_false(yyjson_obj_get(cache, "hit"))) ||
        (package_count &&
         !cbm_compiler_facts_go_package_manifest_valid(cache, inputs, input_count))) {
        reason = "invalid Go package index membership";
        goto reject;
    }
    packages = package_count ? calloc(package_count, sizeof(*packages)) : NULL;
    facts->packages = package_count ? calloc(package_count, sizeof(*facts->packages)) : NULL;
    facts->children = package_count && !chunks
        ? calloc(package_count, sizeof(*facts->children)) : NULL;
    keys = package_count ? malloc(package_count * sizeof(*keys)) : NULL;
    eligible = calloc(input_count, sizeof(*eligible));
    members = calloc(input_count, sizeof(*members));
    if (chunks) {
        facts->file_chunks = malloc(input_count * sizeof(*facts->file_chunks));
        facts->file_package_ids = malloc(input_count * sizeof(*facts->file_package_ids));
    }
    if ((package_count && (!packages || !facts->packages || (!chunks && !facts->children) || !keys)) ||
        (chunks && (!facts->file_chunks || !facts->file_package_ids)) ||
        !eligible || !members) {
        reason = "out of memory";
        goto reject;
    }
    facts->package_count = package_count;
    size_t package_members = 0, failed = 0, unprocessed = 0;
    for (size_t i = 0; i < package_count; i++) {
        yyjson_val *entry = yyjson_arr_get(package_array, i);
        CFIndexPackage *package = &packages[i];
        package->json = entry;
        package->id = cf_str(entry, "id");
        package->path = cf_str(entry, "path");
        package->key = cf_str(entry, "key");
        package->files = yyjson_obj_get(entry, "files");
        package->complete = cf_equal(cf_str(entry, "status"), "complete");
        yyjson_val *descriptor = yyjson_obj_get(entry, "fragment");
        const char *status = cf_str(entry, "status");
        if (!package->id || !*package->id || strlen(package->id) >= CF_PATH_SIZE ||
            !package->path || !*package->path || strlen(package->path) >= CF_PATH_SIZE ||
            !cf_absolute(cf_str(entry, "dir")) || !cf_str(entry, "name") ||
            !*cf_str(entry, "name") || !cf_str(entry, "for_test") || !cf_hash(package->key) ||
            !cf_sorted_strings(package->files, true) || !yyjson_arr_size(package->files) ||
            yyjson_arr_size(package->files) > CF_MAX_PACKAGE_FILES - package_members ||
            !yyjson_is_bool(yyjson_obj_get(entry, "ill_typed")) ||
            !cf_equal(package->key, cf_str(cache_keys, package->id)) ||
            !cf_same_strings(package->files, yyjson_obj_get(cache_files, package->id)) ||
            (chunks && descriptor) ||
            (package->complete &&
             ((!chunks && !yyjson_is_obj(descriptor)) ||
              !yyjson_is_false(yyjson_obj_get(entry, "ill_typed")) ||
              !cf_empty_array(entry, "errors"))) ||
            (!package->complete &&
             (!(cf_equal(status, "ill_typed") || cf_equal(status, "budget") ||
                cf_equal(status, "unprocessed")) ||
              (descriptor && !yyjson_is_null(descriptor)) || !cf_str(entry, "reason") ||
              !*cf_str(entry, "reason")))) {
            reason = "invalid Go package index entry";
            goto reject;
        }
        package_members += yyjson_arr_size(package->files);
        failed += !package->complete;
        unprocessed += cf_equal(status, "unprocessed");
        facts->packages[i] = (CFPackage){package->id, package->path, false};
        keys[i] = package->key;
    }
    if (complete != (failed == 0)) {
        reason = "package index completion differs from package states";
        goto reject;
    }
    if (package_count > 1) {
        qsort(packages, package_count, sizeof(*packages), cf_index_package_compare);
        qsort(facts->packages, package_count, sizeof(*facts->packages), cf_package_compare);
        qsort(keys, package_count, sizeof(*keys), cf_string_compare);
    }
    for (size_t i = 1; i < package_count; i++) {
        if (cf_equal(packages[i - 1].id, packages[i].id) || cf_equal(keys[i - 1], keys[i])) {
            reason = "duplicate package identity or fragment key";
            goto reject;
        }
    }
    yyjson_val *files = yyjson_obj_get(value, "files");
    size_t file_members = 0, selected_files = 0, authoritative_files = 0;
    for (size_t i = 0; i < input_count; i++) {
        yyjson_val *entry = yyjson_arr_get(files, i);
        const CFFile *file = cf_file(facts, cf_str(entry, "path"));
        yyjson_val *ids = yyjson_obj_get(entry, "package_ids");
        yyjson_val *verification = yyjson_obj_get(entry, "selection_verified");
        uint64_t bytes;
        bool selected = cf_equal(cf_str(entry, "selection"), "selected");
        if (!file || !cf_uint(entry, "byte_length", &bytes) || bytes != file->length ||
            (verification && (selected || !yyjson_is_true(verification) ||
                              !cf_equal(strrchr(file->path, '.'), ".go"))) ||
            !cf_sorted_strings(ids, false) ||
            yyjson_arr_size(ids) > CF_MAX_PACKAGE_FILES - file_members ||
            (selected && !yyjson_arr_size(ids)) ||
            (!selected &&
             (!cf_equal(cf_str(entry, "selection"), "not_selected") ||
              yyjson_arr_size(ids) != 0 ||
              !cf_equal(cf_str(entry, "reason"), "not_selected_by_go_list")))) {
            reason = "invalid Go file selection";
            goto reject;
        }
        size_t index = (size_t)(file - facts->files);
        if (complete && verification) {
            if (!facts->go_unselected)
                facts->go_unselected = calloc(input_count, sizeof(*facts->go_unselected));
            if (!facts->go_unselected) {
                reason = "out of memory";
                goto reject;
            }
            facts->go_unselected[index] = true;
        }
        if (chunks)
            facts->file_package_ids[index] = ids;
        eligible[index] = selected;
        members[index] = yyjson_arr_size(ids);
        file_members += members[index];
        for (size_t j = 0; j < members[index]; j++) {
            CFIndexPackage *package =
                cf_index_package(packages, package_count, cf_string(yyjson_arr_get(ids, j)));
            if (!package || !cf_string_member(package->files, file->path)) {
                reason = "Go file/package membership differs";
                goto reject;
            }
            eligible[index] = eligible[index] && package->complete;
        }
        selected_files += selected;
        authoritative_files += eligible[index];
    }
    if (file_members != package_members) {
        reason = "incomplete Go file/package membership";
        goto reject;
    }
    if (!cf_index_summary(value, input_count, selected_files, package_count, failed, unprocessed,
                           authoritative_files)) {
        reason = "package index coverage summary differs";
        goto reject;
    }
    graph.facts = facts;
    cbm_gbuf_foreach_node(gbuf, cf_graph_node, &graph);
    if (graph.failed) {
        reason = "declaration index budget or allocation failed";
        goto reject;
    }
    if (graph.count > 1)
        qsort(graph.items, graph.count, sizeof(*graph.items), cf_declaration_compare);
    if (chunks) {
        uint64_t input_bytes = 0;
        for (size_t i = 0; i < facts->file_count; i++) {
            if (facts->files[i].length > CF_MAX_INPUT_BYTES - input_bytes) {
                reason = "chunk source byte budget exceeded";
                goto reject;
            }
            input_bytes += facts->files[i].length;
        }
        facts->index_packages = packages;
        facts->file_eligible = eligible;
        facts->file_members = members;
        packages = NULL;
        eligible = NULL;
        members = NULL;
        if ((reason = cf_chunk_catalogue(facts, &graph, selected_files)))
            goto reject;
        free(keys);
        return facts;
    }
    size_t json_bytes = 0, sites = 0, projection_bytes = 0;
    for (size_t i = 0; i < package_count; i++) {
        if (packages[i].complete &&
            (reason = cf_index_fragment(facts, &packages[i], &graph, &json_bytes,
                                         &sites, &projection_bytes)))
            goto reject;
    }
    if ((reason =
             cf_index_rows(facts, packages, package_count, eligible, members, sites, SIZE_MAX)))
        goto reject;
    free(graph.items);
    free(packages);
    free(eligible);
    free(members);
    free(keys);
    return facts;

reject:
    free(graph.items);
    free(packages);
    free(eligible);
    free(members);
    free(keys);
    cbm_compiler_facts_free(facts);
    if (error && error_size)
        cf_diagnostic_text(error, error_size, reason ? reason : "invalid compiler package index");
    return NULL;
}

CBMCompilerFacts *cbm_compiler_facts_parse_index(
    const char *json, size_t length, const char *root, const CBMCompilerInput *inputs,
    size_t input_count, const cbm_gbuf_t *gbuf, const char *fragment_directory, char *error,
    size_t error_size) {
    return cf_parse_index(json, length, root, inputs, input_count, gbuf, fragment_directory,
                             error, error_size, false, false);
}

CBMCompilerFacts *cbm_compiler_facts_parse_chunk_index(
    const char *json, size_t length, const char *root, const CBMCompilerInput *inputs,
    size_t input_count, const cbm_gbuf_t *gbuf, const char *fragment_directory, char *error,
    size_t error_size) {
    return cf_parse_index(json, length, root, inputs, input_count, gbuf, fragment_directory,
                             error, error_size, true, false);
}

CBMCompilerFacts *cbm_compiler_facts_parse_compact_chunk_index(
    const char *json, size_t length, const char *root, const CBMCompilerInput *inputs,
    size_t input_count, const cbm_gbuf_t *gbuf, const char *fragment_directory, char *error,
    size_t error_size) {
    return cf_parse_index(json, length, root, inputs, input_count, gbuf, fragment_directory,
                             error, error_size, true, true);
}

static bool cf_ts_ids(yyjson_val *ids, size_t limit) {
    if (!yyjson_is_arr(ids))
        return false;
    uint64_t previous = 0;
    for (size_t i = 0; i < yyjson_arr_size(ids); i++) {
        yyjson_val *id = yyjson_arr_get(ids, i);
        if (!yyjson_is_uint(id) || yyjson_get_uint(id) <= previous ||
            yyjson_get_uint(id) > limit)
            return false;
        previous = yyjson_get_uint(id);
    }
    return true;
}

static bool cf_ts_descriptor(yyjson_val *descriptor, size_t *offset, size_t total) {
    static const char *const names[] = {"offset", "byte_length", "sha256"};
    uint64_t start, length;
    if (!cf_object_fields(descriptor, names, 3) ||
        !cf_uint(descriptor, "offset", &start) || start != *offset ||
        !cf_uint(descriptor, "byte_length", &length) || !length ||
        length > total - *offset || !cf_hash(cf_str(descriptor, "sha256")))
        return false;
    *offset += (size_t)length;
    return true;
}

static bool cf_ts_ledger_path(const CBMCompilerFacts *facts, char path[CF_PATH_SIZE],
                               cbm_path_info_t *info) {
    yyjson_val *ledger = yyjson_obj_get(cbm_compiler_facts_json(facts), "ledger");
    char actual[CF_PATH_SIZE];
    uint64_t length;
    int n = snprintf(path, CF_PATH_SIZE, "%s/facts.jsonl", facts->fragment_directory);
    return n > 0 && n < CF_PATH_SIZE && cf_uint(ledger, "byte_length", &length) &&
           cbm_canonical_path(path, actual, sizeof(actual)) && cf_path_equal(path, actual) &&
           cbm_path_info_utf8(path, info) == CBM_PATH_INFO_OK && info->is_regular &&
           !info->is_symlink && info->size >= 0 && (uint64_t)info->size == length;
}

/* Admission reads every final row; file acquisition reads only its closed ID vectors. */
static const char *cf_ts_read_rows(CBMCompilerFacts *facts, yyjson_val *chunk,
                                    yyjson_doc **result) {
    *result = NULL;
    yyjson_val *ledger = yyjson_obj_get(cbm_compiler_facts_json(facts), "ledger");
    size_t length = (size_t)yyjson_get_uint(yyjson_obj_get(ledger, "byte_length"));
    char *all = NULL, path[CF_PATH_SIZE];
    cbm_path_info_t before, after;
    FILE *file = NULL;
    const char *reason = NULL;
    if (!cf_ts_ledger_path(facts, path, &before))
        return "TypeScript ledger path or length differs";
    if (chunk)
        file = cbm_fopen(path, "rb");
    else
        all = cf_fragment_read(facts->fragment_directory, "facts.jsonl", length,
                                cf_str(ledger, "sha256"));
    if ((chunk && !file) || (!chunk && !all))
        return "TypeScript ledger digest or file differs";
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = doc ? yyjson_mut_obj(doc) : NULL;
    if (doc)
        yyjson_mut_doc_set_root(doc, root);
    const char *names[] = {"types", "symbols", "sites"};
    for (size_t group = 0; !reason && group < 3; group++) {
        yyjson_val *ids = chunk ? yyjson_obj_get(chunk, names[group]) : NULL;
        size_t count = yyjson_arr_size(chunk ? ids : yyjson_obj_get(ledger, names[group]));
        yyjson_mut_val *rows = root ? yyjson_mut_obj_add_arr(doc, root, names[group]) : NULL;
        if (!rows) {
            reason = "out of memory";
            break;
        }
        for (size_t i = 0; !reason && i < count; i++) {
            size_t id = chunk ? (size_t)yyjson_get_uint(yyjson_arr_get(ids, i)) : i + 1;
            yyjson_val *descriptor = facts->ts_descriptors[group][id - 1];
            size_t offset = (size_t)yyjson_get_uint(yyjson_obj_get(descriptor, "offset"));
            size_t bytes = (size_t)yyjson_get_uint(yyjson_obj_get(descriptor, "byte_length"));
            char *owned = file ? malloc(bytes) : NULL;
            const char *raw = file ? owned : all + offset;
            if (file && (!owned || fseek(file, (long)offset, SEEK_SET) != 0 ||
                         fread(owned, 1, bytes, file) != bytes || ferror(file))) {
                free(owned);
                reason = "TypeScript ledger record read failed";
                break;
            }
            char hash[65];
            cbm_sha256_hex(raw, bytes, hash);
            yyjson_doc *record = bytes && raw[bytes - 1] == '\n' &&
                                        cf_equal(hash, cf_str(descriptor, "sha256"))
                                    ? yyjson_read(raw, bytes - 1, 0) : NULL;
            yyjson_val *value = yyjson_doc_get_root(record);
            bool valid = cf_json_shape(value, 0) && yyjson_is_obj(value);
            if (valid && group == 0) {
                static const char *const fields[] = {"domain", "depth", "row"};
                uint64_t depth;
                valid = cf_object_fields(value, fields, 3) &&
                        (cf_equal(cf_str(value, "domain"), "type") ||
                         cf_equal(cf_str(value, "domain"), "signature")) &&
                        cf_uint(value, "depth", &depth) && depth <= 10;
                value = yyjson_obj_get(value, "row");
                valid = valid && yyjson_is_obj(value);
            }
            uint64_t row_id;
            if (valid && group < 2)
                valid = cf_uint(value, "id", &row_id) && row_id == id;
            yyjson_mut_val *copy = valid ? yyjson_val_mut_copy(doc, value) : NULL;
            if (!copy || !yyjson_mut_arr_add_val(rows, copy))
                reason = "invalid TypeScript ledger record";
            yyjson_doc_free(record);
            free(owned);
        }
    }
    if (file)
        fclose(file);
    free(all);
    if (!reason &&
        (!cf_ts_ledger_path(facts, path, &after) || before.size != after.size ||
         before.mtime_ns != after.mtime_ns))
        reason = "TypeScript ledger changed during read";
    if (!reason) {
        *result = yyjson_mut_doc_imut_copy(doc, NULL);
        if (!*result)
            reason = "out of memory";
    }
    yyjson_mut_doc_free(doc);
    return reason;
}

static bool cf_ts_member(yyjson_val *array, const char *text) {
    for (size_t i = 0; i < yyjson_arr_size(array); i++) {
        if (cf_equal(cf_string(yyjson_arr_get(array, i)), text))
            return true;
    }
    return false;
}

static bool cf_ts_known_context(yyjson_val *root, const char *id, const char *path) {
    yyjson_val *projects = yyjson_obj_get(yyjson_obj_get(root, "context"), "projects");
    for (size_t i = 0; i < yyjson_arr_size(projects); i++) {
        yyjson_val *project = yyjson_arr_get(projects, i);
        if (cf_equal(cf_str(project, "id"), id))
            return !path || cf_ts_member(yyjson_obj_get(project, "analyzed_files"), path);
    }
    return false;
}

static yyjson_val *cf_ts_proof_project(yyjson_val *root, const char *id) {
    yyjson_val *projects = yyjson_obj_get(yyjson_obj_get(root, "context"), "projects");
    for (size_t i = 0; i < yyjson_arr_size(projects); i++) {
        yyjson_val *project = yyjson_arr_get(projects, i);
        if (cf_equal(cf_str(project, "id"), id))
            return project;
    }
    return NULL;
}

static bool cf_ts_proof_diagnosed(yyjson_val *root, const char *id) {
    return yyjson_arr_size(yyjson_obj_get(cf_ts_proof_project(root, id), "diagnostics")) != 0;
}

typedef struct {
    const CFFile *file;
    const char *context;
    uint64_t admitted, seen;
} CFTSProofCoverage;

static int cf_ts_proof_coverage_compare(const void *left, const void *right) {
    const CFTSProofCoverage *a = left, *b = right;
    int order = strcmp(a->file->path, b->file->path);
    return order ? order : strcmp(a->context, b->context);
}

static const char *cf_ts_proof_coverage(CBMCompilerFacts *facts, yyjson_val *root,
                                       yyjson_val *sites, const char *canonical) {
    yyjson_val *projects = yyjson_obj_get(yyjson_obj_get(root, "context"), "projects");
    yyjson_val *diagnostics = yyjson_obj_get(root, "diagnostics");
    yyjson_val *cache = yyjson_obj_get(root, "cache");
    yyjson_val *cached = yyjson_obj_get(cache, "projects");
    yyjson_val *coverage = yyjson_obj_get(root, "coverage");
    yyjson_val *counts = yyjson_obj_get(root, "counts");
    uint64_t observed, raw_sites, reused, rebuilt;
    size_t expected = 0, seen_diagnostics = 0, n = yyjson_arr_size(coverage);
    if (!yyjson_is_arr(diagnostics) || !yyjson_is_arr(coverage) ||
        n > CF_MAX_DISCOVERY_PROBES || !cf_uint(counts, "observed_calls", &observed) ||
        observed > UINT64_C(9007199254740991) || !cf_uint(counts, "raw_sites", &raw_sites) ||
        !yyjson_is_false(yyjson_obj_get(cache, "hit")) || !yyjson_is_arr(cached) ||
        yyjson_arr_size(cached) != yyjson_arr_size(projects) ||
        !cf_uint(cache, "reused_projects", &reused) || reused ||
        !cf_uint(cache, "rebuilt_projects", &rebuilt) || rebuilt != yyjson_arr_size(projects))
        return "invalid TypeScript proof coverage or cache";
    for (size_t p = 0; p < yyjson_arr_size(projects); p++) {
        yyjson_val *project = yyjson_arr_get(projects, p);
        yyjson_val *paths = yyjson_obj_get(project, "analyzed_files");
        yyjson_val *errors = yyjson_obj_get(project, "diagnostics");
        const char *id = cf_str(project, "id");
        if (!yyjson_is_arr(errors) || yyjson_arr_size(paths) > CF_MAX_DISCOVERY_PROBES - expected)
            return "invalid TypeScript proof diagnostics or membership";
        expected += yyjson_arr_size(paths);
        size_t cached_matches = 0;
        for (size_t c = 0; c < yyjson_arr_size(cached); c++) {
            yyjson_val *item = yyjson_arr_get(cached, c);
            if (!yyjson_is_false(yyjson_obj_get(item, "hit")))
                return "TypeScript proof cache reuse is forbidden";
            cached_matches += cf_equal(cf_str(item, "id"), id);
        }
        if (cached_matches != 1)
            return "TypeScript proof cache context differs";
        for (size_t d = 0; d < yyjson_arr_size(errors); d++) {
            yyjson_val *item = yyjson_arr_get(errors, d);
            if (!cf_local_diagnostic(facts, item, canonical, id) ||
                !cf_ts_member(paths, cf_str(item, "path") + strlen(canonical) + 1) ||
                !yyjson_equals(item, yyjson_arr_get(diagnostics, seen_diagnostics++)))
                return "TypeScript proof diagnostics differ";
        }
    }
    if (expected != n || seen_diagnostics != yyjson_arr_size(diagnostics))
        return "incomplete TypeScript proof coverage or diagnostics";
    CFTSProofCoverage *rows = n ? calloc(n, sizeof(*rows)) : NULL;
    if (n && !rows)
        return "out of memory";
    const char *reason = "invalid TypeScript proof coverage row";
    uint64_t observed_sum = 0, admitted_sum = 0;
    for (size_t i = 0; i < n; i++) {
        yyjson_val *row = yyjson_arr_get(coverage, i);
        yyjson_val *unavailable = yyjson_obj_get(row, "unavailable");
        static const char *const fields[] = {
            "path", "sha256", "context", "observed_calls", "admitted_calls", "unavailable"};
        static const char *const missing_fields[] = {"reason", "context", "start", "end"};
        const CFFile *file = cf_file(facts, cf_str(row, "path"));
        const char *context = cf_str(row, "context");
        uint64_t calls, admitted, start, end;
        if (!cf_object_fields(row, fields, 6) || !file ||
            !cf_equal(cf_str(row, "sha256"), file->sha256) ||
            !context || !cf_ts_known_context(root, context, file->path) ||
            !cf_uint(row, "observed_calls", &calls) ||
            calls > UINT64_C(9007199254740991) - observed_sum ||
            !cf_uint(row, "admitted_calls", &admitted) || admitted > calls ||
            admitted > raw_sites - admitted_sum ||
            !cf_object_fields(unavailable, missing_fields, 4) ||
            !cf_equal(cf_str(unavailable, "context"), context) ||
            !cf_uint(unavailable, "start", &start) || start ||
            !cf_uint(unavailable, "end", &end) || end != file->length ||
            !cf_equal(cf_str(unavailable, "reason"),
                      cf_ts_proof_diagnosed(root, context) ? "diagnostic_context"
                                                            : "proof_not_demanded"))
            goto done;
        observed_sum += calls;
        admitted_sum += admitted;
        rows[i] = (CFTSProofCoverage){file, context, admitted, 0};
    }
    if (n > 1)
        qsort(rows, n, sizeof(*rows), cf_ts_proof_coverage_compare);
    for (size_t i = 1; i < n; i++)
        if (cf_ts_proof_coverage_compare(rows + i - 1, rows + i) == 0)
            goto done;
    size_t i, site_count;
    yyjson_val *site;
    yyjson_arr_foreach(sites, i, site_count, site) {
        const CFFile *file = cf_file(facts, cf_str(site, "path"));
        yyjson_val *contexts = yyjson_obj_get(site, "contexts");
        if (!file || !yyjson_is_arr(contexts))
            goto done;
        for (size_t c = 0; c < yyjson_arr_size(contexts); c++) {
            const char *context = cf_string(yyjson_arr_get(contexts, c));
            if (!context)
                goto done;
            CFTSProofCoverage key = {.file = file, .context = context};
            CFTSProofCoverage *match =
                n ? bsearch(&key, rows, n, sizeof(*rows), cf_ts_proof_coverage_compare) : NULL;
            if (!match || ++match->seen > match->admitted)
                goto done;
        }
    }
    for (size_t i = 0; i < n; i++)
        if (rows[i].seen != rows[i].admitted)
            goto done;
    if (observed_sum != observed || admitted_sum != raw_sites)
        goto done;
    reason = NULL;
done:
    free(rows);
    return reason;
}

static bool cf_ts_proof_type(yyjson_val *row) {
    yyjson_val *unavailable = yyjson_obj_get(row, "unavailable");
    const char *kind = cf_str(row, "kind"), *context = cf_str(row, "context");
    yyjson_val *role = yyjson_obj_get(row, "nominal_role");
    uint64_t start, end;
    if (role && (!cf_equal(kind, "object") ||
                 !(cf_equal(cf_string(role), "instance") || cf_equal(cf_string(role), "value"))))
        return false;
    if (cf_equal(kind, "unavailable")) {
        static const char *const fields[] = {"id", "kind", "context", "reason", "start", "end"};
        const char *reason = cf_str(row, "reason");
        return cf_object_fields(row, fields, 6) &&
               (cf_equal(reason, "depth_limit") || cf_equal(reason, "missing_type")) &&
               cf_uint(row, "start", &start) && !start && cf_uint(row, "end", &end) && !end;
    }
    if (!unavailable)
        return true;
    if (!yyjson_is_arr(unavailable))
        return false;
    for (size_t i = 0; i < yyjson_arr_size(unavailable); i++) {
        yyjson_val *item = yyjson_arr_get(unavailable, i);
        static const char *const fields[] = {"field", "reason", "context", "start", "end"};
        const char *field = cf_str(item, "field");
        yyjson_val *value = field ? yyjson_obj_get(row, field) : NULL;
        if (!cf_object_fields(item, fields, 5) ||
            !(cf_equal(field, "fields") || cf_equal(field, "signatures") ||
              cf_equal(field, "embeds")) ||
            !cf_equal(cf_str(item, "reason"), "proof_not_demanded") ||
            !cf_equal(cf_str(item, "context"), context) ||
            !cf_uint(item, "start", &start) || start || !cf_uint(item, "end", &end) || end ||
            (value && (!yyjson_is_arr(value) || yyjson_arr_size(value))))
            return false;
        for (size_t j = 0; j < i; j++)
            if (cf_equal(field, cf_str(yyjson_arr_get(unavailable, j), "field")))
                return false;
    }
    return true;
}

static bool cf_ts_row_context(yyjson_val *root, yyjson_val *row, bool type, const char *path) {
    if (type)
        return cf_ts_known_context(root, cf_str(row, "context"), path);
    yyjson_val *ids = yyjson_obj_get(row, "contexts");
    if (!yyjson_is_arr(ids) || !yyjson_arr_size(ids))
        return false;
    for (size_t i = 0; i < yyjson_arr_size(ids); i++) {
        const char *id = cf_string(yyjson_arr_get(ids, i));
        if (!id || !*id || !cf_ts_known_context(root, id, path))
            return false;
        for (size_t j = 0; j < i; j++) {
            if (cf_equal(id, cf_string(yyjson_arr_get(ids, j))))
                return false;
        }
    }
    return true;
}

static bool cf_ts_owned(yyjson_val *row, const char *path) {
    yyjson_val *decl = yyjson_obj_get(row, "declaration");
    return yyjson_is_false(yyjson_obj_get(decl, "external")) &&
           !yyjson_is_true(yyjson_obj_get(decl, "excluded")) &&
           cf_equal(cf_str(decl, "path"), path);
}

typedef struct {
    bool *types, *symbols;
    size_t *queue, *symbol_queue;
    size_t type_count, symbol_count, queued, symbols_queued;
} CFTSClosure;

typedef struct {
    yyjson_val *declaration;
    size_t symbol;
} CFTSNominal;

static int cf_ts_nominal_compare(const void *left, const void *right) {
    yyjson_val *a = ((const CFTSNominal *)left)->declaration;
    yyjson_val *b = ((const CFTSNominal *)right)->declaration;
    const char *strings[] = {"path", "sha256"};
    for (size_t i = 0; i < sizeof(strings) / sizeof(*strings); i++) {
        const char *sa = cf_str(a, strings[i]), *sb = cf_str(b, strings[i]);
        int comparison = strcmp(sa ? sa : "", sb ? sb : "");
        if (comparison)
            return comparison;
    }
    const char *numbers[] = {"start", "end", "name_start", "name_end"};
    for (size_t i = 0; i < sizeof(numbers) / sizeof(*numbers); i++) {
        uint64_t na = yyjson_get_uint(yyjson_obj_get(a, numbers[i]));
        uint64_t nb = yyjson_get_uint(yyjson_obj_get(b, numbers[i]));
        if (na != nb)
            return na < nb ? -1 : 1;
    }
    const char *flags[] = {"external", "excluded"};
    for (size_t i = 0; i < sizeof(flags) / sizeof(*flags); i++) {
        bool fa = yyjson_is_true(yyjson_obj_get(a, flags[i]));
        bool fb = yyjson_is_true(yyjson_obj_get(b, flags[i]));
        if (fa != fb)
            return fa ? 1 : -1;
    }
    return 0;
}

static const char *const cf_ts_scalar_refs[] = {
    "type", "declared_type", "signature", "receiver", "underlying", "elem", "key"};
static const char *const cf_ts_array_refs[] = {
    "params", "returns", "args", "embeds", "signatures", "type_params", "arguments"};
static const char *const cf_ts_nested_refs[] = {
    "fields", "methods", "contextual_params", "parameters"};

static bool cf_ts_validate_refs(yyjson_val *row, size_t nt, size_t ns) {
    if (!yyjson_is_obj(row) || !cf_ref(cf_value(row), "target_symbol", ns))
        return false;
    for (size_t i = 0; i < sizeof(cf_ts_scalar_refs) / sizeof(*cf_ts_scalar_refs); i++) {
        if (!cf_ref(cf_value(row), cf_ts_scalar_refs[i], nt))
            return false;
    }
    for (size_t i = 0; i < sizeof(cf_ts_array_refs) / sizeof(*cf_ts_array_refs); i++) {
        if (!cf_refs(cf_value(row), cf_ts_array_refs[i], nt))
            return false;
    }
    for (size_t i = 0; i < sizeof(cf_ts_nested_refs) / sizeof(*cf_ts_nested_refs); i++) {
        yyjson_val *items = yyjson_obj_get(row, cf_ts_nested_refs[i]);
        if (items && !yyjson_is_arr(items))
            return false;
        for (size_t j = 0; j < yyjson_arr_size(items); j++) {
            if (!cf_ts_validate_refs(yyjson_arr_get(items, j), nt, ns))
                return false;
        }
    }
    return true;
}

static void cf_ts_mark_type(CFTSClosure *closure, size_t id) {
    if (id && id <= closure->type_count && !closure->types[id - 1]) {
        closure->types[id - 1] = true;
        closure->queue[closure->queued++] = id;
    }
}

static void cf_ts_mark_symbol(CFTSClosure *closure, size_t id) {
    if (id && id <= closure->symbol_count && !closure->symbols[id - 1]) {
        closure->symbols[id - 1] = true;
        closure->symbol_queue[closure->symbols_queued++] = id;
    }
}

/* Reference fields match the shared CF validators, including callback parameters. */
static void cf_ts_row_refs(CFTSClosure *closure, yyjson_val *row) {
    cf_ts_mark_symbol(closure, cf_raw_id(row, "target_symbol"));
    for (size_t i = 0; i < sizeof(cf_ts_scalar_refs) / sizeof(*cf_ts_scalar_refs); i++)
        cf_ts_mark_type(closure, cf_raw_id(row, cf_ts_scalar_refs[i]));
    for (size_t i = 0; i < sizeof(cf_ts_array_refs) / sizeof(*cf_ts_array_refs); i++) {
        yyjson_val *ids = yyjson_obj_get(row, cf_ts_array_refs[i]);
        for (size_t j = 0; j < yyjson_arr_size(ids); j++)
            cf_ts_mark_type(closure, (size_t)yyjson_get_uint(yyjson_arr_get(ids, j)));
    }
    for (size_t i = 0; i < sizeof(cf_ts_nested_refs) / sizeof(*cf_ts_nested_refs); i++) {
        yyjson_val *items = yyjson_obj_get(row, cf_ts_nested_refs[i]);
        for (size_t j = 0; j < yyjson_arr_size(items); j++)
            cf_ts_row_refs(closure, yyjson_arr_get(items, j));
    }
}

/* Browser proof structure is checked here against the admitted source bytes.
 * Receiver, request routing and script reachability come from the producer. */
enum { CF_BROWSER_MAX_PROOFS = 1024, CF_BROWSER_MAX_SOURCES = 64, CF_BROWSER_MAX_SCRIPTS = 128 };

typedef struct {
    const char *path, *sha256;
    char *bytes;
    uint32_t length;
    TSTree *tree;
} CFBrowserSource;

typedef struct {
    CFBrowserSource sources[CF_BROWSER_MAX_SOURCES];
    size_t count, bytes, proofs;
    uint64_t nodes;
} CFBrowserCheck;

static bool cf_browser_span(yyjson_val *array, uint32_t length, uint32_t *start, uint32_t *end) {
    yyjson_val *left = yyjson_arr_get(array, 0), *right = yyjson_arr_get(array, 1);
    if (yyjson_arr_size(array) != 2 || !yyjson_is_uint(left) || !yyjson_is_uint(right))
        return false;
    uint64_t a = yyjson_get_uint(left), b = yyjson_get_uint(right);
    if (a >= b || b > length)
        return false;
    *start = (uint32_t)a;
    *end = (uint32_t)b;
    return true;
}

static bool cf_browser_path(const char *canonical, const char *relative, char path[CF_PATH_SIZE]) {
    if (!cf_relative(relative))
        return false;
    int length = snprintf(path, CF_PATH_SIZE, "%s%s%s", canonical,
                          canonical[strlen(canonical) - 1] == '/' ? "" : "/", relative);
    return length > 0 && length < CF_PATH_SIZE;
}

static CFBrowserSource *cf_browser_source(CFBrowserCheck *check, const char *path,
                                          const char *sha256, uint64_t size,
                                          const TSLanguage *language) {
    for (size_t i = 0; i < check->count; i++) {
        CFBrowserSource *source = &check->sources[i];
        if (cf_path_equal(source->path, path))
            return cf_equal(source->sha256, sha256) && source->length == size ? source : NULL;
    }
    if (check->count >= CF_BROWSER_MAX_SOURCES || size > 8U * 1024U * 1024U ||
        size > CF_MAX_LOCAL_AST_BYTES - check->bytes || !language)
        return NULL;
    FILE *file = cbm_fopen(path, "rb");
    char *bytes = file ? malloc((size_t)size + 1) : NULL;
    bool valid = bytes && fread(bytes, 1, (size_t)size, file) == size &&
                 fgetc(file) == EOF && !ferror(file);
    if (file)
        valid = fclose(file) == 0 && valid;
    char hash[65];
    if (valid)
        cbm_sha256_hex(bytes, (size_t)size, hash);
    valid = valid && cf_equal(hash, sha256);
    TSParser *parser = valid ? ts_parser_new() : NULL;
    TSTree *tree = parser && ts_parser_set_language(parser, language)
        ? ts_parser_parse_string(parser, NULL, bytes, (uint32_t)size) : NULL;
    if (parser)
        ts_parser_delete(parser);
    if (!tree || ts_node_has_error(ts_tree_root_node(tree))) {
        if (tree)
            ts_tree_delete(tree);
        free(bytes);
        return NULL;
    }
    char *owned_path = strdup(path);
    if (!owned_path) {
        ts_tree_delete(tree);
        free(bytes);
        return NULL;
    }
    CFBrowserSource *source = &check->sources[check->count++];
    *source = (CFBrowserSource){owned_path, sha256, bytes, (uint32_t)size, tree};
    check->bytes += (size_t)size;
    return source;
}

static bool cf_browser_text(const CFBrowserSource *source, TSNode node, const char *text) {
    if (ts_node_is_null(node) || !text)
        return false;
    uint32_t start = ts_node_start_byte(node), end = ts_node_end_byte(node);
    return end <= source->length && end - start == strlen(text) &&
           memcmp(source->bytes + start, text, end - start) == 0;
}

static bool cf_ts_context_dependency(yyjson_val *root, yyjson_val *contexts,
                                         const char *path, const char *sha256) {
    for (size_t i = 0; i < yyjson_arr_size(contexts); i++) {
        const char *id = cf_string(yyjson_arr_get(contexts, i));
        yyjson_val *project = cf_ts_proof_project(root, id);
        yyjson_val *deps = yyjson_obj_get(project, "dependencies");
        bool found = false;
        size_t d, count;
        yyjson_val *dep;
        yyjson_arr_foreach(deps, d, count, dep)
            if (cf_path_equal(path, cf_str(dep, "path")) && cf_equal(sha256, cf_str(dep, "sha256"))) {
                found = true;
                break;
            }
        if (!found)
            return false;
    }
    return yyjson_arr_size(contexts) != 0;
}

static bool cf_browser_html_name(const CFBrowserSource *html, TSNode name, const char *expected) {
    uint32_t start = ts_node_start_byte(name), end = ts_node_end_byte(name);
    if (end > html->length || end - start != strlen(expected))
        return false;
    for (uint32_t i = start; i < end; i++) {
        if (tolower((unsigned char)html->bytes[i]) != expected[i - start])
            return false;
    }
    return true;
}

static bool cf_browser_target_tag(const CFBrowserSource *html, uint32_t start, uint32_t end,
                                  const char *html_path, const char *target) {
    TSNode tag = cf_local_node(ts_tree_root_node(html->tree), start, end, "script_element");
    if (ts_node_is_null(tag))
        return false;
    TSNode opener = ts_node_named_child(tag, 0);
    if (!cf_equal(ts_node_type(opener), "start_tag") || ts_node_named_child_count(opener) != 2)
        return false;
    TSNode attr = ts_node_named_child(opener, 1);
    if (!cf_equal(ts_node_type(attr), "attribute") ||
        !cf_browser_html_name(html, ts_node_named_child(attr, 0), "src"))
        return false;
    TSNode quoted = ts_node_named_child(attr, 1);
    TSNode value = ts_node_named_child(quoted, 0);
    if (!cf_equal(ts_node_type(quoted), "quoted_attribute_value") ||
        ts_node_is_null(value) || !cf_equal(ts_node_type(value), "attribute_value"))
        return false;
    size_t length = ts_node_end_byte(value) - ts_node_start_byte(value);
    const char *value_start = html->bytes + ts_node_start_byte(value);
    if (length > 2 && memcmp(value_start, "./", 2) == 0) {
        value_start += 2;
        length -= 2;
    }
    const char *slash = strrchr(html_path, '/');
    size_t directory_length = slash ? (size_t)(slash - html_path) + 1 : 0;
    if (!length || strlen(target) != directory_length + length ||
        memcmp(target, html_path, directory_length) != 0 ||
        memcmp(target + directory_length, value_start, length) != 0)
        return false;
    for (TSNode ancestor = ts_node_parent(tag); !ts_node_is_null(ancestor);
         ancestor = ts_node_parent(ancestor)) {
        if (!cf_equal(ts_node_type(ancestor), "element"))
            continue;
        TSNode name = ts_node_named_child(ts_node_named_child(ancestor, 0), 0);
        if (!(cf_browser_html_name(html, name, "html") || cf_browser_html_name(html, name, "head") ||
              cf_browser_html_name(html, name, "body")))
            return false;
    }
    return true;
}

static const TSLanguage *cf_browser_javascript(const char *path) {
    const char *suffix = strrchr(path, '.');
    if (cf_equal(suffix, ".js") || cf_equal(suffix, ".cjs") || cf_equal(suffix, ".mjs"))
        return tree_sitter_javascript();
    if (cf_equal(suffix, ".ts") || cf_equal(suffix, ".cts") || cf_equal(suffix, ".mts"))
        return tree_sitter_typescript();
    return cf_equal(suffix, ".tsx") ? tree_sitter_tsx() : NULL;
}

static bool cf_browser_caller(CFBrowserCheck *check, const CFBrowserSource *source,
                              yyjson_val *site, yyjson_val *proof, yyjson_val *symbol) {
    uint32_t first, last;
    TSNode root = ts_tree_root_node(source->tree);
    if (!cf_browser_span(yyjson_obj_get(proof, "evaluate_span"), source->length, &first, &last))
        return false;
    TSNode evaluate = cf_local_node(root, first, last, "call_expression");
    if (ts_node_is_null(evaluate))
        return false;
    TSNode method = ts_node_child_by_field_name(evaluate, "function", 8);
    if (!cf_equal(ts_node_type(method), "member_expression") ||
        !cf_browser_text(source, ts_node_child_by_field_name(method, "property", 8), "evaluate") ||
        !cf_equal(ts_node_type(ts_node_child_by_field_name(method, "object", 6)), "identifier") ||
        !cf_browser_span(yyjson_obj_get(proof, "callback_span"), source->length, &first, &last))
        return false;
    TSNode args = ts_node_child_by_field_name(evaluate, "arguments", 9), callback = {0};
    for (uint32_t i = 0; i < ts_node_named_child_count(args); i++) {
        TSNode candidate = ts_node_named_child(args, i);
        if (!ts_node_is_extra(candidate)) {
            callback = candidate;
            break;
        }
    }
    if (ts_node_is_null(callback) ||
        !(cf_equal(ts_node_type(callback), "arrow_function") ||
          cf_equal(ts_node_type(callback), "function_expression")) ||
        ts_node_start_byte(callback) != first || ts_node_end_byte(callback) != last ||
        cf_raw_id(site, "start") <= first || cf_raw_id(site, "end") > last)
        return false;
    TSNode call = cf_local_node(callback, cf_raw_id(site, "start"), cf_raw_id(site, "end"),
                                "call_expression");
    if (ts_node_is_null(call))
        return false;
    TSNode callee = ts_node_child_by_field_name(call, "function", 8);
    CFLocalProof entry = {.site = site, .symbol = symbol};
    return cf_equal(ts_node_type(callee), "identifier") &&
           ts_node_start_byte(callee) == cf_raw_id(site, "callee_start") &&
           ts_node_end_byte(callee) == cf_raw_id(site, "callee_end") &&
           cf_browser_text(source, callee, cf_str(symbol, "name")) &&
           cf_local_inventory(callback, source->bytes, &entry, 1, &check->nodes, NULL, 0);
}

static bool cf_browser_target(const CFBrowserSource *source, yyjson_val *symbol) {
    yyjson_val *decl = yyjson_obj_get(symbol, "declaration");
    TSNode root = ts_tree_root_node(source->tree);
    bool const_function = cf_equal(cf_str(symbol, "kind"), "ConstFunction");
    TSNode function = cf_local_node(root, cf_raw_id(decl, "start"), cf_raw_id(decl, "end"),
                                   const_function ? "variable_declarator" : "function_declaration");
    if (ts_node_is_null(function))
        return false;
    TSNode container = ts_node_parent(function);
    if (const_function) {
        if (ts_node_is_null(container) || !cf_equal(ts_node_type(container), "lexical_declaration"))
            return false;
        TSNode kind = ts_node_child_by_field_name(container, "kind", 4);
        TSNode value = ts_node_child_by_field_name(function, "value", 5);
        if (ts_node_is_null(kind) || ts_node_is_null(value) || !cf_equal(ts_node_type(kind), "const") ||
            !cf_equal(ts_node_type(value), "arrow_function"))
            return false;
        container = ts_node_parent(container);
    }
    if (!ts_node_eq(container, root))
        return false;
    TSNode name = ts_node_child_by_field_name(function, "name", 4);
    return !ts_node_is_null(name) && ts_node_start_byte(name) == cf_raw_id(decl, "name_start") &&
           ts_node_end_byte(name) == cf_raw_id(decl, "name_end") &&
           cf_browser_text(source, name, cf_str(symbol, "name"));
}

static bool cf_browser_proof(const CBMCompilerFacts *facts, const char *canonical,
                             yyjson_val *site, CFBrowserCheck *check) {
    if (++check->proofs > CF_BROWSER_MAX_PROOFS)
        return false;
    yyjson_val *proof = yyjson_obj_get(site, "proof");
    yyjson_val *browser = yyjson_obj_get(proof, "browser");
    static const char *const fields[] = {"callback_span", "evaluate_span", "html", "scripts"};
    static const char *const html_fields[] = {"path", "sha256", "script_tag_span"};
    static const char *const script_fields[] = {"path", "sha256"};
    yyjson_val *html = yyjson_obj_get(browser, "html"), *scripts = yyjson_obj_get(browser, "scripts");
    size_t symbol_id = cf_raw_id(site, "target_symbol");
    if (!cf_object_fields(browser, fields, 4) || !cf_object_fields(html, html_fields, 3) ||
        !yyjson_is_arr(scripts) || !yyjson_arr_size(scripts) ||
        yyjson_arr_size(scripts) > CF_BROWSER_MAX_SCRIPTS || !symbol_id || symbol_id > facts->symbol_count ||
        !cf_equal(cf_str(site, "dispatch"), "static") ||
        !cf_equal(cf_str(yyjson_obj_get(proof, "types"), "status"), "unavailable"))
        return false;
    const CFSymbol *target = &facts->symbols[symbol_id - 1];
    yyjson_val *symbol = target->json.raw;
    yyjson_val *decl = yyjson_obj_get(symbol, "declaration");
    const char *kind = cf_str(symbol, "kind");
    if (!target->callable || target->external || target->excluded ||
        !(cf_equal(kind, "FunctionDeclaration") || cf_equal(kind, "ConstFunction")) ||
        yyjson_is_true(yyjson_obj_get(symbol, "ambiguous")) || cf_raw_id(symbol, "type") != 0)
        return false;
    const CFFile *caller = cf_file(facts, cf_str(site, "path"));
    const CFFile *target_file = cf_file(facts, cf_str(decl, "path"));
    if (!caller || !target_file || caller == target_file ||
        !cf_equal(strrchr(target_file->path, '.'), ".js"))
        return false;
    const char *html_name = cf_str(html, "path"), *html_hash = cf_str(html, "sha256");
    char path[CF_PATH_SIZE], actual[CF_PATH_SIZE];
    cbm_path_info_t info;
    if (!cf_hash(html_hash) || !cf_browser_path(canonical, html_name, path) ||
        !cf_equal(strrchr(html_name, '.'), ".html") ||
        !cf_ts_context_dependency(facts->proof_root, yyjson_obj_get(site, "contexts"), path, html_hash) ||
        !cbm_canonical_path(path, actual, sizeof(actual)) || !cf_path_equal(path, actual) ||
        cbm_path_info_utf8(path, &info) != CBM_PATH_INFO_OK || !info.is_regular || info.is_symlink || info.size < 0)
        return false;
    CFBrowserSource *document = cf_browser_source(check, path, html_hash, (uint64_t)info.size,
                                                  tree_sitter_html());
    uint32_t first, last;
    if (!document || !cf_browser_span(yyjson_obj_get(html, "script_tag_span"), document->length, &first, &last) ||
        !cf_browser_target_tag(document, first, last, html_name, target_file->path))
        return false;
    bool found = false;
    for (size_t i = 0; i < yyjson_arr_size(scripts); i++) {
        yyjson_val *script = yyjson_arr_get(scripts, i);
        const char *name = cf_str(script, "path"), *sha = cf_str(script, "sha256");
        if (!cf_object_fields(script, script_fields, 2) || !cf_browser_path(canonical, name, path) ||
            !cf_equal(strrchr(name, '.'), ".js") || !cf_hash(sha))
            return false;
        for (size_t j = 0; j < i; j++)
            if (cf_path_equal(name, cf_str(yyjson_arr_get(scripts, j), "path")))
                return false;
        const CFFile *admitted = cf_file(facts, name);
        if (admitted ? !cf_equal(sha, admitted->sha256) :
            !cf_ts_context_dependency(facts->proof_root, yyjson_obj_get(site, "contexts"), path, sha))
            return false;
        found |= admitted == target_file;
    }
    if (!found || !cf_browser_path(canonical, caller->path, path))
        return false;
    CFBrowserSource *caller_source = cf_browser_source(check, path, caller->sha256, caller->length,
                                                       cf_browser_javascript(caller->path));
    if (!caller_source || !cf_browser_caller(check, caller_source, site, browser, symbol) ||
        !cf_browser_path(canonical, target_file->path, path))
        return false;
    CFBrowserSource *target_source = cf_browser_source(check, path, target_file->sha256,
                                                       target_file->length, tree_sitter_javascript());
    return target_source && cf_browser_target(target_source, symbol);
}

static const char *cf_browser_proofs(CBMCompilerFacts *facts, yyjson_val *sites,
                                      const char *canonical) {
    CFBrowserCheck check = {0};
    const char *reason = NULL;
    size_t i, count;
    yyjson_val *site;
    yyjson_arr_foreach(sites, i, count, site) {
        yyjson_val *proof = yyjson_obj_get(site, "proof");
        yyjson_val *target = yyjson_obj_get(proof, "target");
        if (cf_equal(cf_str(target, "reason"), "browser_page_context") &&
            !cf_browser_proof(facts, canonical, site, &check)) {
            reason = "invalid TypeScript browser page proof";
            break;
        }
    }
    for (size_t f = 0; f < check.count; f++) {
        CFBrowserSource *source = &check.sources[f];
        ts_tree_delete(source->tree);
        free(source->bytes);
        free((void *)source->path);
    }
    return reason;
}


static bool cf_ts_proof_site(yyjson_val *root, yyjson_val *site, const CFType *types,
                             CFTSClosure *closure) {
    yyjson_val *proof = yyjson_obj_get(site, "proof");
    yyjson_val *contexts = yyjson_obj_get(site, "contexts");
    static const char *const parts[] = {"target", "types"};
    yyjson_val *target = yyjson_obj_get(proof, "target");
    bool browser = cf_equal(cf_str(target, "reason"), "browser_page_context");
    if (browser != (yyjson_obj_get(proof, "browser") != NULL) ||
        (browser && (!cf_equal(cf_str(target, "status"), "available") ||
                     yyjson_obj_get(proof, "lexical"))))
        return false;
    if (!cf_equal(cf_str(proof, "profile"), "proof_index_v1"))
        return false;
    for (size_t p = 0; p < 2; p++) {
        yyjson_val *part = yyjson_obj_get(proof, parts[p]);
        static const char *const fields[] = {"status", "reason", "context", "start", "end"};
        const char *status = cf_str(part, "status"), *reason = cf_str(part, "reason");
        const char *context = cf_str(part, "context");
        uint64_t start, end;
        if (!cf_object_fields(part, fields, 5) ||
            !(cf_equal(status, "available") || cf_equal(status, "unavailable")) ||
            !reason || !*reason || !context || !cf_ts_member(contexts, context) ||
            !cf_uint(part, "start", &start) || start != cf_raw_id(site, "start") ||
            !cf_uint(part, "end", &end) || end != cf_raw_id(site, "end"))
            return false;
        if (cf_equal(status, "available")) {
            yyjson_val *projects = yyjson_obj_get(yyjson_obj_get(root, "context"), "projects");
            for (size_t c = 0; c < yyjson_arr_size(projects); c++) {
                yyjson_val *project = yyjson_arr_get(projects, c);
                if (cf_ts_member(yyjson_obj_get(project, "analyzed_files"),
                                 cf_str(site, "path")) &&
                    !cf_ts_member(contexts, cf_str(project, "id")))
                    return false;
            }
            if (p == 0 && cf_equal(reason, "lexical_target")) {
                if (!yyjson_is_obj(yyjson_obj_get(proof, "lexical")))
                    return false;
            } else {
                if (!cf_equal(reason, "checker_context") &&
                    !(p == 0 && browser))
                    return false;
                for (size_t c = 0; c < yyjson_arr_size(contexts); c++)
                    if (cf_ts_proof_diagnosed(root, cf_string(yyjson_arr_get(contexts, c))))
                        return false;
            }
        }
    }
    if (!cf_equal(cf_str(yyjson_obj_get(proof, "types"), "status"), "available")) {
        static const char *const refs[] = {"type", "signature", "receiver"};
        static const char *const arrays[] = {"args", "arguments", "contextual_params"};
        for (size_t i = 0; i < 3; i++) {
            uint64_t id;
            yyjson_val *items = yyjson_obj_get(site, arrays[i]);
            if (!cf_uint(site, refs[i], &id) || id || !yyjson_is_arr(items) ||
                yyjson_arr_size(items))
                return false;
        }
        return true;
    }
    if (!cf_raw_id(site, "type") || !cf_raw_id(site, "signature"))
        return false;
    static const char *const required_arrays[] = {"args", "arguments"};
    for (size_t a = 0; a < 2; a++) {
        yyjson_val *ids = yyjson_obj_get(site, required_arrays[a]);
        for (size_t i = 0; i < yyjson_arr_size(ids); i++)
            if (!yyjson_get_uint(yyjson_arr_get(ids, i)))
                return false;
    }
    yyjson_val *callbacks = yyjson_obj_get(site, "contextual_params");
    for (size_t i = 0; i < yyjson_arr_size(callbacks); i++) {
        yyjson_val *callback = yyjson_arr_get(callbacks, i);
        if (!cf_raw_id(callback, "type"))
            return false;
        yyjson_val *parameters = yyjson_obj_get(callback, "parameters");
        for (size_t j = 0; j < yyjson_arr_size(parameters); j++)
            if (!cf_raw_id(yyjson_arr_get(parameters, j), "type"))
                return false;
    }
    memset(closure->types, 0, (closure->type_count + 1) * sizeof(bool));
    closure->queued = 0;
    cf_ts_row_refs(closure, site);
    for (size_t cursor = 0; cursor < closure->queued; cursor++) {
        yyjson_val *type = types[closure->queue[cursor] - 1].json.raw;
        if (cf_equal(cf_str(type, "kind"), "unavailable") ||
            !cf_ts_member(contexts, cf_str(type, "context")))
            return false;
        if (cf_equal(cf_str(type, "kind"), "object") &&
            !cf_equal(cf_str(type, "nominal_role"), "instance") &&
            cf_raw_id(type, "fields_omitted")) {
            yyjson_val *unavailable = yyjson_obj_get(type, "unavailable");
            for (size_t i = 0; i < yyjson_arr_size(unavailable); i++)
                if (cf_equal(cf_str(yyjson_arr_get(unavailable, i), "field"), "fields"))
                    return false;
        }
        cf_ts_row_refs(closure, type);
    }
    return true;
}

static const char *cf_ts_proof_sites(CBMCompilerFacts *facts, yyjson_val *rows,
                                    const char *canonical) {
    yyjson_val *sites = yyjson_obj_get(rows, "sites");
    CFTSClosure closure = {.type_count = facts->type_count};
    closure.types = calloc(closure.type_count + 1, sizeof(bool));
    closure.queue = malloc((closure.type_count + 1) * sizeof(size_t));
    if (!closure.types || !closure.queue) {
        free(closure.types);
        free(closure.queue);
        return "out of memory";
    }
    const char *reason = NULL;
    size_t i, count;
    yyjson_val *site;
    yyjson_arr_foreach(sites, i, count, site) {
        if (!cf_ts_proof_site(facts->proof_root, site, facts->types, &closure)) {
            reason = "invalid TypeScript site proof authority";
            break;
        }
    }
    free(closure.types);
    free(closure.queue);
    if (!reason)
        reason = cf_browser_proofs(facts, sites, canonical);
    return reason ? reason : cf_local_proofs(facts, rows, canonical);
}

static bool cf_ts_exact_ids(yyjson_val *ids, const bool *needed, size_t count) {
    size_t cursor = 0;
    for (size_t i = 0; i < count; i++) {
        if (needed[i] && yyjson_get_uint(yyjson_arr_get(ids, cursor++)) != i + 1)
            return false;
    }
    return cursor == yyjson_arr_size(ids);
}

static const char *cf_ts_closure(const CBMCompilerFacts *check, yyjson_val *chunk,
                                 yyjson_val *const *sites, bool *site_seen,
                                 const CFTSNominal *nominal, size_t nominal_count) {
    size_t nt = check->type_count, ns = check->symbol_count;
    CFTSClosure closure = {.type_count = nt, .symbol_count = ns};
    closure.types = calloc(nt + 1, sizeof(bool));
    closure.symbols = calloc(ns + 1, sizeof(bool));
    closure.queue = malloc((nt + 1) * sizeof(size_t));
    closure.symbol_queue = malloc((ns + 1) * sizeof(size_t));
    if (!closure.types || !closure.symbols || !closure.queue || !closure.symbol_queue) {
        free(closure.types);
        free(closure.symbols);
        free(closure.queue);
        free(closure.symbol_queue);
        return "out of memory";
    }
    const char *path = cf_str(chunk, "path"), *reason = NULL;
    for (size_t i = 0; i < nt; i++) {
        if (cf_ts_owned(check->types[i].json.raw, path))
            cf_ts_mark_type(&closure, i + 1);
    }
    for (size_t i = 0; i < ns; i++) {
        if (cf_ts_owned(check->symbols[i].json.raw, path))
            cf_ts_mark_symbol(&closure, i + 1);
    }
    yyjson_val *ids = yyjson_obj_get(chunk, "sites");
    for (size_t i = 0; !reason && i < yyjson_arr_size(ids); i++) {
        size_t id = (size_t)yyjson_get_uint(yyjson_arr_get(ids, i));
        yyjson_val *site = sites[id - 1];
        if (site_seen[id - 1] || !cf_equal(cf_str(site, "path"), path)) {
            reason = "TypeScript site file membership differs";
            break;
        }
        site_seen[id - 1] = true;
        cf_ts_row_refs(&closure, site);
    }
    size_t ti = 0, si = 0;
    while (ti < closure.queued || si < closure.symbols_queued) {
        while (si < closure.symbols_queued)
            cf_ts_row_refs(&closure, check->symbols[closure.symbol_queue[si++] - 1].json.raw);
        while (ti < closure.queued) {
            yyjson_val *type = check->types[closure.queue[ti++] - 1].json.raw;
            cf_ts_row_refs(&closure, type);
            CFTSNominal key = {.declaration = yyjson_obj_get(type, "declaration")};
            const CFTSNominal *match = nominal_count
                ? bsearch(&key, nominal, nominal_count, sizeof(*nominal), cf_ts_nominal_compare)
                : NULL;
            if (match) {
                while (match > nominal && cf_ts_nominal_compare(&key, match - 1) == 0)
                    match--;
                for (; match < nominal + nominal_count &&
                       cf_ts_nominal_compare(&key, match) == 0; match++)
                    cf_ts_mark_symbol(&closure, match->symbol);
            }
        }
    }
    if (!reason && (!cf_ts_exact_ids(yyjson_obj_get(chunk, "types"), closure.types, nt) ||
                    !cf_ts_exact_ids(yyjson_obj_get(chunk, "symbols"), closure.symbols, ns)))
        reason = "TypeScript support closure differs";
    free(closure.types);
    free(closure.symbols);
    free(closure.queue);
    free(closure.symbol_queue);
    return reason;
}

static bool cf_ts_remap_id(yyjson_mut_val *value, const size_t *map, size_t count) {
    if (!value)
        return true;
    if (!yyjson_mut_is_uint(value))
        return false;
    uint64_t id = yyjson_mut_get_uint(value);
    return id <= count && (!id || map[id]) && yyjson_mut_set_uint(value, id ? map[id] : 0);
}

static bool cf_ts_remap_row(yyjson_mut_val *row, const size_t *types, size_t nt,
                             const size_t *symbols, size_t ns) {
    if (!cf_ts_remap_id(yyjson_mut_obj_get(row, "target_symbol"), symbols, ns))
        return false;
    for (size_t i = 0; i < sizeof(cf_ts_scalar_refs) / sizeof(*cf_ts_scalar_refs); i++) {
        if (!cf_ts_remap_id(yyjson_mut_obj_get(row, cf_ts_scalar_refs[i]), types, nt))
            return false;
    }
    for (size_t i = 0; i < sizeof(cf_ts_array_refs) / sizeof(*cf_ts_array_refs); i++) {
        yyjson_mut_val *ids = yyjson_mut_obj_get(row, cf_ts_array_refs[i]);
        for (size_t j = 0; j < yyjson_mut_arr_size(ids); j++) {
            if (!cf_ts_remap_id(yyjson_mut_arr_get(ids, j), types, nt))
                return false;
        }
    }
    for (size_t i = 0; i < sizeof(cf_ts_nested_refs) / sizeof(*cf_ts_nested_refs); i++) {
        yyjson_mut_val *items = yyjson_mut_obj_get(row, cf_ts_nested_refs[i]);
        for (size_t j = 0; j < yyjson_mut_arr_size(items); j++) {
            if (!cf_ts_remap_row(yyjson_mut_arr_get(items, j), types, nt, symbols, ns))
                return false;
        }
    }
    return true;
}

static const char *cf_ts_dense_rows(CBMCompilerFacts *facts, yyjson_val *chunk,
                                     yyjson_doc **document) {
    yyjson_doc *raw = NULL;
    const char *reason = cf_ts_read_rows(facts, chunk, &raw);
    if (reason)
        return reason;
    yyjson_mut_doc *doc = yyjson_doc_mut_copy(raw, NULL);
    yyjson_doc_free(raw);
    if (!doc)
        return "out of memory";
    yyjson_val *ledger = yyjson_obj_get(cbm_compiler_facts_json(facts), "ledger");
    size_t nt = yyjson_arr_size(yyjson_obj_get(ledger, "types"));
    size_t ns = yyjson_arr_size(yyjson_obj_get(ledger, "symbols"));
    size_t *tm = calloc(nt + 1, sizeof(*tm)), *sm = calloc(ns + 1, sizeof(*sm));
    if (!tm || !sm)
        reason = "out of memory";
    const char *names[] = {"types", "symbols", "sites"};
    for (size_t group = 0; !reason && group < 2; group++) {
        yyjson_val *ids = yyjson_obj_get(chunk, names[group]);
        size_t *map = group ? sm : tm;
        for (size_t i = 0; i < yyjson_arr_size(ids); i++)
            map[yyjson_get_uint(yyjson_arr_get(ids, i))] = i + 1;
    }
    yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);
    for (size_t group = 0; !reason && group < 3; group++) {
        yyjson_mut_val *rows = yyjson_mut_obj_get(root, names[group]);
        for (size_t i = 0; !reason && i < yyjson_mut_arr_size(rows); i++) {
            yyjson_mut_val *row = yyjson_mut_arr_get(rows, i);
            if ((group < 2 && !yyjson_mut_set_uint(yyjson_mut_obj_get(row, "id"), i + 1)) ||
                !cf_ts_remap_row(row, tm, nt, sm, ns))
                reason = "TypeScript file view has an unclosed reference";
        }
    }
    if (!reason) {
        *document = yyjson_mut_doc_imut_copy(doc, NULL);
        if (!*document)
            reason = "out of memory";
    }
    free(tm);
    free(sm);
    yyjson_mut_doc_free(doc);
    return reason;
}

static const char *cf_ts_load(CBMCompilerFacts *facts, yyjson_val *chunk,
                              CBMCompilerFacts **result) {
    *result = NULL;
    CBMCompilerFacts *view = calloc(1, sizeof(*view));
    if (!view)
        return "out of memory";
    view->borrowed_tables = true;
    view->package_fragment = true;
    view->proof_index = facts->proof_index;
    view->proof_root = facts->proof_root;
    view->files = facts->files;
    view->file_count = facts->file_count;
    view->packages = facts->packages;
    view->package_count = facts->package_count;
    view->type_budget = CF_MAX_TYPE_BYTES - facts->catalogue_bytes;
    const char *reason = cf_ts_dense_rows(facts, chunk, &view->doc);
    yyjson_val *root = cbm_compiler_facts_json(view);
    CFValue types = cf_value(yyjson_obj_get(root, "types"));
    CFValue symbols = cf_value(yyjson_obj_get(root, "symbols"));
    CFValue sites = cf_value(yyjson_obj_get(root, "sites"));
    CFGraph graph = {.facts = facts, .items = facts->declarations,
                     .count = facts->declaration_count};
    if (!reason)
        reason = cf_types(view, types, cfv_size(symbols), false);
    if (!reason)
        reason = cf_symbols(view, symbols, cfv_size(types), false, &graph);
    if (!reason)
        reason = cf_project_types(view, types, false, &graph);
    if (!reason)
        reason = cf_sites(view, sites, cfv_size(types), false, true, NULL);
    if (!reason)
        reason = cf_matches(view, view->type_budget);
    if (!reason && view->row_count != cfv_size(sites))
        reason = "duplicate TypeScript file occurrence";
    if (reason)
        cbm_compiler_facts_free(view);
    else
        *result = view;
    return reason;
}

CBMCompilerFacts *cbm_compiler_facts_parse_ts_chunk_index(
    const char *json, size_t length, const char *root, const CBMCompilerInput *inputs,
    size_t input_count, const cbm_gbuf_t *gbuf, const char *fragment_directory, char *error,
    size_t error_size) {
    if (error && error_size)
        error[0] = '\0';
    const char *reason = "invalid TypeScript file index arguments";
    CBMCompilerFacts *facts = NULL, *check = NULL;
    CFGraph graph = {0};
    bool *site_seen = NULL;
    yyjson_val **site_rows = NULL;
    CFTSNominal *nominal = NULL;
    size_t nominal_count = 0;
    char canonical[CF_PATH_SIZE], directory[CF_PATH_SIZE];
    if (!json || !length || length > CF_MAX_JSON || !root || !inputs || !input_count ||
        input_count > CF_MAX_FILES || !gbuf || !fragment_directory)
        goto reject;
    if (cf_temporary(root) || !cbm_canonical_path(root, canonical, sizeof(canonical)) ||
        cf_temporary(canonical) || cf_temporary(fragment_directory) ||
        !cbm_canonical_path(fragment_directory, directory, sizeof(directory)) ||
        cf_temporary(directory)) {
        reason = "invalid canonical TypeScript index root or ledger directory";
        goto reject;
    }
    cf_slashes(canonical);
    cf_slashes(directory);
    facts = calloc(1, sizeof(*facts));
    if (!facts)
        goto reject;
    facts->chunk_index = facts->ts_chunk_index = true;
    facts->active_chunk = SIZE_MAX;
    facts->fragment_directory = malloc(strlen(directory) + 1);
    if (!facts->fragment_directory)
        goto reject;
    strcpy(facts->fragment_directory, directory);
    facts->doc = yyjson_read(json, length, 0);
    yyjson_val *value = cbm_compiler_facts_json(facts);
    uint64_t schema;
    if (!yyjson_is_obj(value) || !cf_json_shape(value, 0) ||
        !cf_uint(value, "schema", &schema) || schema != 3 ||
        !cf_equal(cf_str(value, "kind"), "typescript_chunk_index") ||
        !(cf_equal(cf_str(value, "profile"), "file_index_v1") ||
          cf_equal(cf_str(value, "profile"), "proof_index_v1")) ||
        !cf_equal(cf_str(value, "language"), "typescript") ||
        !cf_equal(cf_str(value, "helper_version"), "1.1.0") ||
        !(cf_equal(cf_str(value, "profile"), "proof_index_v1")
              ? cf_equal(cf_str(value, "status"), "partial") &&
                    yyjson_is_false(yyjson_obj_get(value, "complete")) &&
                    yyjson_is_arr(yyjson_obj_get(value, "diagnostics"))
              : cf_equal(cf_str(value, "status"), "ok") &&
                    yyjson_is_true(yyjson_obj_get(value, "complete")) &&
                    cf_empty_array(value, "diagnostics")) ||
        !cf_empty_array(value, "errors") ||
        !yyjson_is_arr(yyjson_obj_get(value, "types")) ||
        !yyjson_is_arr(yyjson_obj_get(value, "symbols")) ||
        !yyjson_is_arr(yyjson_obj_get(value, "sites")) ||
        !cf_empty_array(value, "types") || !cf_empty_array(value, "symbols") ||
        !cf_empty_array(value, "sites") || !cf_path_equal(cf_str(value, "root"), canonical)) {
        reason = "unsupported or incomplete TypeScript file index";
        goto reject;
    }
    facts->proof_index = cf_equal(cf_str(value, "profile"), "proof_index_v1");
    facts->proof_root = facts->proof_index ? value : NULL;
    if ((reason = cf_context(value, false, false, inputs, input_count)) ||
        (reason = cf_files(facts, value, canonical, inputs, input_count)) ||
        (reason = cf_packages(facts, value, false)))
        goto reject;
    yyjson_val *ledger = yyjson_obj_get(value, "ledger");
    yyjson_val *counts = yyjson_obj_get(value, "counts");
    const char *names[] = {"types", "symbols", "sites"};
    static const char *const ledger_fields[] = {
        "file", "byte_length", "sha256", "types", "symbols", "sites"};
    static const char *const count_fields[] = {
        "types", "symbols", "raw_sites", "sites", "observed_calls"};
    uint64_t total, raw_sites;
    if (!cf_object_fields(ledger, ledger_fields, 6) ||
        !cf_equal(cf_str(ledger, "file"), "facts.jsonl") ||
        !cf_uint(ledger, "byte_length", &total) || total > CF_MAX_JSON - length ||
        !cf_hash(cf_str(ledger, "sha256")) ||
        !cf_object_fields(counts, count_fields, facts->proof_index ? 5 : 4) ||
        !cf_uint(counts, "raw_sites", &raw_sites) || raw_sites > CF_TS_MAX_SITES) {
        reason = "invalid TypeScript ledger budget or identity";
        goto reject;
    }
    size_t offset = 0, limits[] = {CF_TS_MAX_TYPES, CF_TS_MAX_SYMBOLS, CF_TS_MAX_SITES};
    for (size_t group = 0; group < 3; group++) {
        yyjson_val *descriptors = yyjson_obj_get(ledger, names[group]);
        uint64_t count;
        if (!yyjson_is_arr(descriptors) || yyjson_arr_size(descriptors) > limits[group] ||
            !cf_uint(counts, names[group], &count) || count != yyjson_arr_size(descriptors) ||
            (group == 2 && count > raw_sites)) {
            reason = "TypeScript cumulative identity or site budget exceeded";
            goto reject;
        }
        if (count) {
            /* Object arrays in yyjson require a scan for each indexed lookup. */
            facts->ts_descriptors[group] = malloc((size_t)count * sizeof(yyjson_val *));
            if (!facts->ts_descriptors[group]) {
                reason = "out of memory";
                goto reject;
            }
        }
        size_t i, n;
        yyjson_val *descriptor;
        yyjson_arr_foreach(descriptors, i, n, descriptor) {
            if (!cf_ts_descriptor(descriptor, &offset, (size_t)total)) {
                reason = "invalid TypeScript ledger descriptor";
                goto reject;
            }
            facts->ts_descriptors[group][i] = descriptor;
        }
    }
    if (offset != total) {
        reason = "TypeScript ledger has unaccounted bytes";
        goto reject;
    }
    yyjson_val *projects = yyjson_obj_get(yyjson_obj_get(value, "context"), "projects");
    if (!yyjson_is_arr(projects) || !yyjson_arr_size(projects)) {
        reason = "missing TypeScript index contexts";
        goto reject;
    }
    for (size_t i = 0; i < yyjson_arr_size(projects); i++) {
        yyjson_val *project = yyjson_arr_get(projects, i);
        const char *id = cf_str(project, "id");
        if (!id || !*id || !yyjson_is_arr(yyjson_obj_get(project, "analyzed_files"))) {
            reason = "invalid TypeScript index context";
            goto reject;
        }
        for (size_t j = 0; j < i; j++) {
            if (cf_equal(id, cf_str(yyjson_arr_get(projects, j), "id"))) {
                reason = "duplicate TypeScript index context";
                goto reject;
            }
        }
        yyjson_val *paths = yyjson_obj_get(project, "analyzed_files");
        for (size_t j = 0; j < yyjson_arr_size(paths); j++) {
            const char *path = cf_string(yyjson_arr_get(paths, j));
            if (!path || !cf_relative(path) || !cf_file(facts, path)) {
                reason = "TypeScript context file is outside discovery";
                goto reject;
            }
            for (size_t k = 0; k < j; k++) {
                if (cf_equal(path, cf_string(yyjson_arr_get(paths, k)))) {
                    reason = "duplicate TypeScript context file";
                    goto reject;
                }
            }
        }
    }
    graph.facts = facts;
    cbm_gbuf_foreach_node(gbuf, cf_graph_node, &graph);
    if (graph.failed) {
        reason = "declaration index budget or allocation failed";
        goto reject;
    }
    if (graph.count > 1)
        qsort(graph.items, graph.count, sizeof(*graph.items), cf_declaration_compare);
    facts->file_chunks = malloc(input_count * sizeof(size_t));
    facts->file_eligible = calloc(input_count, sizeof(bool));
    if (!facts->file_chunks || !facts->file_eligible) {
        reason = "out of memory";
        goto reject;
    }
    size_t arrays = graph.capacity * sizeof(*graph.items) +
                    input_count * (sizeof(CFFile) + sizeof(size_t) + sizeof(bool)) +
                    facts->package_count * sizeof(CFPackage);
    for (size_t group = 0; group < 3; group++)
        arrays += yyjson_arr_size(yyjson_obj_get(ledger, names[group])) * sizeof(yyjson_val *);
    if ((reason = cf_own_declarations(facts, &graph, arrays)))
        goto reject;
    graph.items = facts->declarations;
    graph.count = facts->declaration_count;
    check = calloc(1, sizeof(*check));
    if (!check) {
        reason = "out of memory";
        goto reject;
    }
    check->borrowed_tables = true;
    check->package_fragment = true;
    check->proof_index = facts->proof_index;
    check->proof_root = facts->proof_root;
    check->files = facts->files;
    check->file_count = facts->file_count;
    check->packages = facts->packages;
    check->package_count = facts->package_count;
    check->type_budget = CF_MAX_TYPE_BYTES - facts->catalogue_bytes;
    if ((reason = cf_ts_read_rows(facts, NULL, &check->doc)))
        goto reject;
    yyjson_val *rows = cbm_compiler_facts_json(check);
    CFValue types = cf_value(yyjson_obj_get(rows, "types"));
    CFValue symbols = cf_value(yyjson_obj_get(rows, "symbols"));
    CFValue sites = cf_value(yyjson_obj_get(rows, "sites"));
    if ((reason = cf_types(check, types, cfv_size(symbols), false)) ||
        (reason = cf_symbols(check, symbols, cfv_size(types), false, &graph)) ||
        (reason = cf_sites(check, sites, cfv_size(types), false, false, NULL)))
        goto reject;
    if (check->row_count != cfv_size(sites)) {
        reason = "duplicate TypeScript ledger occurrence";
        goto reject;
    }
    nominal = calloc(cfv_size(symbols) + 1, sizeof(*nominal));
    if (!nominal) {
        reason = "out of memory";
        goto reject;
    }
    for (size_t i = 0; i < check->symbol_count; i++) {
        const char *kind = cfv_str(check->symbols[i].json, "kind");
        if (cf_equal(kind, "ClassDeclaration") || cf_equal(kind, "InterfaceDeclaration") ||
            cf_equal(kind, "TypeAliasDeclaration"))
            nominal[nominal_count++] = (CFTSNominal){
                .declaration = yyjson_obj_get(check->symbols[i].json.raw, "declaration"),
                .symbol = i + 1};
    }
    if (nominal_count > 1)
        qsort(nominal, nominal_count, sizeof(*nominal), cf_ts_nominal_compare);
    if (cfv_size(sites)) {
        site_rows = malloc(cfv_size(sites) * sizeof(*site_rows));
        if (!site_rows) {
            reason = "out of memory";
            goto reject;
        }
    }
    for (size_t group = 0; group < 3; group++) {
        yyjson_val *array = yyjson_obj_get(rows, names[group]);
        size_t i, n;
        yyjson_val *row;
        yyjson_arr_foreach(array, i, n, row) {
            if (group == 2)
                site_rows[i] = row;
            if (!cf_ts_validate_refs(row, cfv_size(types), cfv_size(symbols))) {
                reason = "invalid TypeScript ledger reference";
                goto reject;
            }
            const char *path = group == 2 ? cf_str(row, "path")
                              : cf_ts_owned(row, cf_str(yyjson_obj_get(row, "declaration"), "path"))
                                  ? cf_str(yyjson_obj_get(row, "declaration"), "path") : NULL;
            if (!cf_ts_row_context(value, row, group == 0, path)) {
                reason = "TypeScript row context membership differs";
                goto reject;
            }
            if (facts->proof_index && group == 0 && !cf_ts_proof_type(row)) {
                reason = "invalid TypeScript unavailable type proof";
                goto reject;
            }
        }
    }
    if (facts->proof_index &&
        ((reason = cf_ts_proof_coverage(facts, value, sites.raw, canonical)) ||
         (reason = cf_ts_proof_sites(check, rows, canonical))))
        goto reject;
    yyjson_val *chunks = yyjson_obj_get(value, "chunks");
    site_seen = calloc(cfv_size(sites) + 1, sizeof(bool));
    if (!site_seen || !yyjson_is_arr(chunks) || yyjson_arr_size(chunks) != input_count) {
        reason = "invalid TypeScript chunk inventory";
        goto reject;
    }
    for (size_t i = 0; i < input_count; i++) {
        yyjson_val *chunk = yyjson_arr_get(chunks, i);
        static const char *const fields[] = {"path", "contexts", "types", "symbols", "sites"};
        yyjson_val *contexts = yyjson_obj_get(chunk, "contexts");
        const CFFile *file = cf_file(facts, cf_str(chunk, "path"));
        if (!cf_object_fields(chunk, fields, 5) || !file || file != facts->files + i ||
            !yyjson_is_arr(contexts) ||
            !cf_ts_ids(yyjson_obj_get(chunk, "types"), cfv_size(types)) ||
            !cf_ts_ids(yyjson_obj_get(chunk, "symbols"), cfv_size(symbols)) ||
            !cf_ts_ids(yyjson_obj_get(chunk, "sites"), cfv_size(sites))) {
            reason = "invalid TypeScript file chunk";
            goto reject;
        }
        size_t applicable = 0;
        for (size_t j = 0; j < yyjson_arr_size(contexts); j++) {
            const char *id = cf_string(yyjson_arr_get(contexts, j));
            if (!id || !*id || !cf_ts_known_context(value, id, file->path)) {
                reason = "TypeScript file context is unknown";
                goto reject;
            }
            for (size_t k = 0; k < j; k++) {
                if (cf_equal(id, cf_string(yyjson_arr_get(contexts, k)))) {
                    reason = "duplicate TypeScript file context";
                    goto reject;
                }
            }
        }
        for (size_t j = 0; j < yyjson_arr_size(projects); j++) {
            yyjson_val *project = yyjson_arr_get(projects, j);
            if (cf_ts_member(yyjson_obj_get(project, "analyzed_files"), file->path)) {
                applicable++;
                if (!cf_ts_member(contexts, cf_str(project, "id"))) {
                    reason = "TypeScript file contexts differ";
                    goto reject;
                }
            }
        }
        if (applicable != yyjson_arr_size(contexts)) {
            reason = "TypeScript file contexts differ";
            goto reject;
        }
        if ((reason = cf_ts_closure(check, chunk, site_rows, site_seen, nominal, nominal_count)))
            goto reject;
        facts->file_chunks[i] = i;
        facts->file_eligible[i] = true;
    }
    for (size_t i = 0; i < cfv_size(sites); i++) {
        if (!site_seen[i]) {
            reason = "incomplete TypeScript site membership";
            goto reject;
        }
    }
    facts->verified_sites = check->row_count;
    free(nominal);
    free(site_seen);
    free(site_rows);
    cbm_compiler_facts_free(check);
    return facts;
reject:
    if (!facts || graph.items != facts->declarations)
        free(graph.items);
    free(site_seen);
    free(site_rows);
    free(nominal);
    cbm_compiler_facts_free(check);
    cbm_compiler_facts_free(facts);
    if (error && error_size)
        cf_diagnostic_text(error, error_size, reason ? reason : "invalid TypeScript file index");
    return NULL;
}

bool cbm_compiler_facts_is_chunk_index(const CBMCompilerFacts *facts) {
    return facts && facts->chunk_index;
}

size_t cbm_compiler_facts_file_order(const CBMCompilerFacts *facts, const char *path) {
    const CFFile *file = facts && facts->chunk_index ? cf_file(facts, path) : NULL;
    return file ? facts->file_chunks[file - facts->files] : SIZE_MAX;
}

bool cbm_compiler_facts_file_matches(const CBMCompilerFacts *facts, const char *path,
                                      const char *sha256) {
    const CFFile *file = facts ? cf_file(facts, path) : NULL;
    return file && cf_hash(sha256) && cf_equal(file->sha256, sha256);
}

bool cbm_compiler_facts_go_file_unselected(const CBMCompilerFacts *facts, const char *path,
                                          const char *sha256) {
    const CFFile *file = facts && facts->go_unselected ? cf_file(facts, path) : NULL;
    return file && facts->go_unselected[file - facts->files] && cf_equal(file->sha256, sha256);
}

bool cbm_compiler_facts_go_selection_digest(const CBMCompilerFacts *facts, char digest[65]) {
    if (!facts || !facts->go_unselected)
        return false;
    cbm_sha256_ctx hash;
    cbm_sha256_init(&hash);
    for (size_t i = 0; i < facts->file_count; i++)
        if (facts->go_unselected[i])
            cbm_sha256_update(&hash, facts->files[i].path, strlen(facts->files[i].path) + 1);
    cf_digest_finish(&hash, digest);
    return true;
}

static bool cf_chunk_failure(CBMCompilerFacts *facts, const char *reason, char *error,
                               size_t error_size) {
    if (facts && facts->chunk_index) {
        facts->chunks_failed = true;
        cbm_compiler_facts_free(facts->active_view);
        facts->active_view = NULL;
        facts->active_chunk = SIZE_MAX;
        facts->file_acquired = false;
    }
    if (error && error_size)
        cf_diagnostic_text(error, error_size, reason);
    return false;
}

bool cbm_compiler_facts_acquire_file(CBMCompilerFacts *facts, const char *path,
                                      const CBMCompilerFacts **view, char *error,
                                      size_t error_size) {
    if (error && error_size)
        error[0] = '\0';
    if (view)
        *view = NULL;
    if (!facts || !view || !path)
        return cf_chunk_failure(facts, "invalid chunk acquire arguments", error, error_size);
    if (!facts->chunk_index) {
        *view = facts;
        return true;
    }
    if (facts->chunks_failed || facts->file_acquired || facts->files_finished)
        return cf_chunk_failure(facts, "chunk view is busy, finished or failed", error, error_size);
    const CFFile *file = cf_file(facts, path);
    if (!file || !cf_chunk_source_current(facts, file))
        return cf_chunk_failure(facts, "chunk source hash, length or path changed", error,
                                  error_size);
    size_t file_index = (size_t)(file - facts->files);
    size_t chunk_index = facts->file_chunks[file_index];
    if (chunk_index != SIZE_MAX && chunk_index != facts->active_chunk) {
        if (chunk_index < facts->next_chunk)
            return cf_chunk_failure(facts, "chunk consumption order moved backwards",
                                      error, error_size);
        cbm_compiler_facts_free(facts->active_view);
        facts->active_view = NULL;
        facts->active_chunk = SIZE_MAX;
        yyjson_val *chunks = yyjson_obj_get(cbm_compiler_facts_json(facts), "chunks");
        yyjson_val *chunk = yyjson_arr_get(chunks, chunk_index);
        const char *reason = facts->ts_chunk_index
                                 ? NULL : cf_chunk_sources(facts, yyjson_obj_get(chunk, "files"));
        size_t expanded = 0;
        yyjson_val *fragments = yyjson_obj_get(chunk, "fragments");
        for (size_t i = 0; !reason && i < yyjson_arr_size(fragments); i++) {
            size_t bytes = (size_t)yyjson_get_uint(
                yyjson_obj_get(yyjson_arr_get(fragments, i), "raw_byte_length"));
            if (bytes > CF_CHUNK_MAX_EXPANDED - facts->consumed_expanded - expanded)
                reason = "chunk consumption expansion budget exceeded";
            else
                expanded += bytes;
        }
        if (!reason)
            reason = facts->ts_chunk_index ? cf_ts_load(facts, chunk, &facts->active_view)
                                            : cf_chunk_load(facts, chunk, &facts->active_view);
        if (reason)
            return cf_chunk_failure(facts, reason, error, error_size);
        facts->consumed_expanded += expanded;
        facts->active_chunk = chunk_index;
        facts->next_chunk = chunk_index + 1;
    }
    facts->file_acquired = true;
    if (facts->file_eligible[file_index])
        *view = facts->active_view;
    return true;
}

void cbm_compiler_facts_release_file(CBMCompilerFacts *facts) {
    if (facts && facts->chunk_index)
        facts->file_acquired = false;
}

bool cbm_compiler_facts_finish_files(CBMCompilerFacts *facts, char *error, size_t error_size) {
    if (error && error_size)
        error[0] = '\0';
    if (!facts || !facts->chunk_index)
        return true;
    if (facts->chunks_failed || facts->file_acquired)
        return cf_chunk_failure(facts, "chunk view is busy or failed", error, error_size);
    const char *reason = NULL;
    for (size_t i = 0; !reason && i < facts->file_count; i++) {
        if (!cf_chunk_source_current(facts, &facts->files[i]))
            reason = "chunk source hash, length or path changed before finish";
    }
    if (!reason && facts->ts_chunk_index) {
        CBMCompilerInput *inputs = calloc(facts->file_count, sizeof(*inputs));
        if (!inputs)
            reason = "out of memory";
        for (size_t i = 0; inputs && i < facts->file_count; i++)
            inputs[i] = (CBMCompilerInput){facts->files[i].path, facts->files[i].sha256,
                                          facts->files[i].length};
        if (!reason)
            reason = cf_context(cbm_compiler_facts_json(facts), false, false, inputs,
                                facts->file_count);
        free(inputs);
        yyjson_val *ledger = yyjson_obj_get(cbm_compiler_facts_json(facts), "ledger");
        char *raw = !reason ? cf_fragment_read(
            facts->fragment_directory, "facts.jsonl",
            (size_t)yyjson_get_uint(yyjson_obj_get(ledger, "byte_length")),
            cf_str(ledger, "sha256")) : NULL;
        if (!reason && !raw)
            reason = "TypeScript ledger changed before finish";
        free(raw);
    }
    yyjson_val *chunks = yyjson_obj_get(cbm_compiler_facts_json(facts), "chunks");
    for (size_t i = 0; !reason && i < yyjson_arr_size(chunks); i++) {
        yyjson_val *fragments = yyjson_obj_get(yyjson_arr_get(chunks, i), "fragments");
        for (size_t j = 0; !reason && j < yyjson_arr_size(fragments); j++) {
            yyjson_val *descriptor = yyjson_arr_get(fragments, j);
            char *compressed = cf_fragment_read(
                facts->fragment_directory, cf_str(descriptor, "file"),
                (size_t)yyjson_get_uint(yyjson_obj_get(descriptor, "byte_length")),
                cf_str(descriptor, "sha256"));
            if (!compressed)
                reason = "compressed chunk changed before finish";
            free(compressed);
        }
    }
    cbm_compiler_facts_free(facts->active_view);
    facts->active_view = NULL;
    facts->active_chunk = SIZE_MAX;
    if (reason)
        return cf_chunk_failure(facts, reason, error, error_size);
    facts->files_finished = true;
    return true;
}

CBMCompilerFacts *cbm_compiler_facts_rebind(const CBMCompilerFacts *facts, const char *root,
                                            const CBMCompilerInput *inputs, size_t input_count,
                                            const cbm_gbuf_t *gbuf, char *error, size_t error_size) {
    size_t length = 0;
    char *json = facts ? yyjson_write(facts->doc, 0, &length) : NULL;
    CBMCompilerFacts *bound =
        facts && facts->ts_chunk_index
            ? cbm_compiler_facts_parse_ts_chunk_index(
                  json, length, root, inputs, input_count, gbuf,
                  facts->fragment_directory, error, error_size)
        : facts && facts->compact_index
            ? cbm_compiler_facts_parse_compact_chunk_index(
                  json, length, root, inputs, input_count, gbuf,
                  facts->fragment_directory, error, error_size)
        : facts && facts->chunk_index
            ? cbm_compiler_facts_parse_chunk_index(json, length, root, inputs, input_count, gbuf,
                                                    facts->fragment_directory, error, error_size)
        : facts && facts->package_index
            ? cbm_compiler_facts_parse_index(json, length, root, inputs, input_count, gbuf,
                                              facts->fragment_directory, error, error_size)
            : cbm_compiler_facts_parse(
                  json, length, root, cf_str(cbm_compiler_facts_json(facts), "language"), inputs,
                  input_count, gbuf, error, error_size);
    free(json);
    return bound;
}

void cbm_compiler_facts_free(CBMCompilerFacts *facts) {
    if (!facts)
        return;
    cbm_compiler_facts_free(facts->active_view);
    for (size_t i = 0; i < facts->child_count; i++)
        cbm_compiler_facts_free(facts->children[i]);
    free(facts->children);
    free(facts->fragment_directory);
    free(facts->index_packages);
    free(facts->go_unselected);
    free(facts->file_eligible);
    free(facts->file_members);
    free(facts->file_chunks);
    free(facts->file_package_ids);
    for (size_t group = 0; group < 3; group++)
        free(facts->ts_descriptors[group]);
    free(facts->declarations);
    cbm_arena_destroy(&facts->declaration_arena);
    for (size_t i = 0; i < facts->symbol_count; i++) {
        free(facts->symbols ? facts->symbols[i].qn : NULL);
        free(facts->symbols ? facts->symbols[i].external_name : NULL);
    }
    if (!facts->borrowed_tables) {
        free(facts->files);
        free(facts->packages);
    }
    free(facts->symbols);
    free(facts->rows);
    free(facts->matches);
    free(facts->conflicts);
    free(facts->types);
    free(facts->bindings);
    if (facts->compact) {
        free(facts->compact->strings);
        free(facts->compact->schemas);
        free(facts->compact);
    }
    cbm_arena_destroy(&facts->arena);
    yyjson_doc_free(facts->doc);
    free(facts);
}

size_t cbm_compiler_facts_count(const CBMCompilerFacts *facts) {
    return facts ? facts->chunk_index ? facts->verified_sites : facts->row_count : 0;
}

const CBMCompilerSite *cbm_compiler_facts_site(const CBMCompilerFacts *facts, size_t index) {
    return facts && index < facts->row_count ? &facts->rows[index].site : NULL;
}

const CBMCompilerSite *cbm_compiler_facts_find_occurrence(
    const CBMCompilerFacts *facts, const char *path, const char *sha256, uint32_t start,
    uint32_t end) {
    if (!facts || !facts->row_count || !cf_relative(path) || !cf_hash(sha256) || start >= end)
        return NULL;
    CFRow key = {.site = {.path = path, .start_byte = start, .end_byte = end}};
    const CFRow *match =
        bsearch(&key, facts->rows, facts->row_count, sizeof(*facts->rows), cf_row_compare);
    return match && cf_equal(match->site.sha256, sha256) ? &match->site : NULL;
}

const CBMCompilerSite *cbm_compiler_facts_find(const CBMCompilerFacts *facts, const char *path,
                                               const char *sha256, uint32_t start, uint32_t end) {
    if (!facts || !facts->match_count || !cf_relative(path) || !cf_hash(sha256) || start >= end)
        return NULL;
    CFMatch key = {path, sha256, start, end, 0};
    const CFMatch *match = bsearch(&key, facts->matches, facts->match_count,
                                   sizeof(*facts->matches), cf_match_compare);
    if (!match)
        return NULL;
    return match->site < facts->row_count ? &facts->rows[match->site].site
                                          : &facts->conflicts[match->site - facts->row_count];
}

yyjson_val *cbm_compiler_facts_json(const CBMCompilerFacts *facts) {
    return facts ? yyjson_doc_get_root(facts->doc) : NULL;
}

const CBMType *cbm_compiler_facts_type(const CBMCompilerFacts *facts, size_t id) {
    return facts && id && id <= facts->type_count && facts->types[id - 1].value
               ? facts->types[id - 1].value
               : cbm_type_unknown();
}

static size_t cf_type_vector_count(const CBMType *const *types) {
    size_t count = 0;
    while (types && types[count])
        count++;
    return count;
}

static size_t cf_name_vector_count(const char *const *names) {
    size_t count = 0;
    while (names && names[count])
        count++;
    return count;
}

static const char *cf_type_qn(const CBMType *type) {
    for (unsigned i = 0; type && i < CF_TYPE_DEPTH; i++) {
        switch (type->kind) {
        case CBM_TYPE_NAMED:
            return type->data.named.qualified_name;
        case CBM_TYPE_TEMPLATE:
            return type->data.template_type.template_name;
        case CBM_TYPE_ALIAS:
            return type->data.alias.alias_qn;
        case CBM_TYPE_POINTER:
            type = type->data.pointer.elem;
            break;
        default:
            return NULL;
        }
    }
    return NULL;
}

typedef struct {
    const CBMType *source;
    CBMType *copy;
} CFOwnedType;

typedef struct {
    CBMArena *arena;
    CFOwnedType *types;
    size_t count, capacity;
    bool failed;
} CFOwnedProjection;

static void *cf_owned_alloc(CFOwnedProjection *owned, size_t bytes) {
    void *value = owned->failed ? NULL : cbm_arena_calloc(owned->arena, bytes);
    if (!value)
        owned->failed = true;
    return value;
}

static const char *cf_owned_string(CFOwnedProjection *owned, const char *text) {
    if (!text)
        return NULL;
    char *value = owned->failed ? NULL : cbm_arena_strdup(owned->arena, text);
    if (!value)
        owned->failed = true;
    return value;
}

static size_t cf_owned_slot(const CBMType *source, size_t capacity) {
    uintptr_t key = (uintptr_t)source >> 3;
    key ^= key >> 16;
    return (size_t)key & (capacity - 1);
}

static CFOwnedType *cf_owned_entry(CFOwnedProjection *owned, const CBMType *source) {
    if (owned->failed)
        return NULL;
    if (owned->count >= owned->capacity / 2) {
        size_t capacity = owned->capacity ? owned->capacity * 2 : 64;
        if (capacity < owned->capacity || capacity > SIZE_MAX / sizeof(*owned->types)) {
            owned->failed = true;
            return NULL;
        }
        CFOwnedType *types = calloc(capacity, sizeof(*types));
        if (!types) {
            owned->failed = true;
            return NULL;
        }
        for (size_t i = 0; i < owned->capacity; i++) {
            CFOwnedType entry = owned->types[i];
            if (!entry.source)
                continue;
            size_t slot = cf_owned_slot(entry.source, capacity);
            while (types[slot].source)
                slot = (slot + 1) & (capacity - 1);
            types[slot] = entry;
        }
        free(owned->types);
        owned->types = types;
        owned->capacity = capacity;
    }
    size_t slot = cf_owned_slot(source, owned->capacity);
    while (owned->types[slot].source && owned->types[slot].source != source)
        slot = (slot + 1) & (owned->capacity - 1);
    return &owned->types[slot];
}

static const CBMType *cf_owned_type(CFOwnedProjection *owned, const CBMType *source);

static const CBMType **cf_owned_types(CFOwnedProjection *owned, const CBMType *const *source) {
    if (!source)
        return NULL;
    size_t count = cf_type_vector_count(source);
    const CBMType **copy = cf_owned_alloc(owned, (count + 1) * sizeof(*copy));
    for (size_t i = 0; copy && i < count; i++)
        copy[i] = cf_owned_type(owned, source[i]);
    return copy;
}

static const char **cf_owned_names(CFOwnedProjection *owned, const char *const *source) {
    if (!source)
        return NULL;
    size_t count = cf_name_vector_count(source);
    const char **copy = cf_owned_alloc(owned, (count + 1) * sizeof(*copy));
    for (size_t i = 0; copy && i < count; i++)
        copy[i] = cf_owned_string(owned, source[i]);
    return copy;
}

/* Copy only projected subgraphs retained by a merge. One memo covers all
 * bindings, preserving shared nodes without copying native/fallback objects. */
static const CBMType *cf_owned_type(CFOwnedProjection *owned, const CBMType *source) {
    if (!source)
        return NULL;
    if (cbm_type_is_unknown(source))
        return cbm_type_unknown();
    CFOwnedType *entry = cf_owned_entry(owned, source);
    if (!entry)
        return NULL;
    if (entry->copy)
        return entry->copy;
    CBMType *copy = cf_owned_alloc(owned, sizeof(*copy));
    if (!copy)
        return NULL;
    *copy = *source;
    *entry = (CFOwnedType){source, copy};
    owned->count++;
    switch (source->kind) {
    case CBM_TYPE_NAMED:
        copy->data.named.qualified_name = cf_owned_string(owned, source->data.named.qualified_name);
        break;
    case CBM_TYPE_BUILTIN:
        copy->data.builtin.name = cf_owned_string(owned, source->data.builtin.name);
        break;
    case CBM_TYPE_TYPE_PARAM:
        copy->data.type_param.name = cf_owned_string(owned, source->data.type_param.name);
        break;
    case CBM_TYPE_POINTER:
        copy->data.pointer.elem = cf_owned_type(owned, source->data.pointer.elem);
        break;
    case CBM_TYPE_SLICE:
        copy->data.slice.elem = cf_owned_type(owned, source->data.slice.elem);
        break;
    case CBM_TYPE_CHANNEL:
        copy->data.channel.elem = cf_owned_type(owned, source->data.channel.elem);
        break;
    case CBM_TYPE_MAP:
        copy->data.map.key = cf_owned_type(owned, source->data.map.key);
        copy->data.map.value = cf_owned_type(owned, source->data.map.value);
        break;
    case CBM_TYPE_FUNC:
        copy->data.func.param_names = cf_owned_names(owned, source->data.func.param_names);
        copy->data.func.param_types = cf_owned_types(owned, source->data.func.param_types);
        copy->data.func.return_types = cf_owned_types(owned, source->data.func.return_types);
        break;
    case CBM_TYPE_TUPLE:
        copy->data.tuple.elems = cf_owned_types(owned, source->data.tuple.elems);
        break;
    case CBM_TYPE_UNION:
    case CBM_TYPE_INTERSECTION:
        copy->data.union_type.members = cf_owned_types(owned, source->data.union_type.members);
        break;
    case CBM_TYPE_TEMPLATE:
        copy->data.template_type.template_name =
            cf_owned_string(owned, source->data.template_type.template_name);
        copy->data.template_type.template_args =
            cf_owned_types(owned, source->data.template_type.template_args);
        break;
    case CBM_TYPE_ALIAS:
        copy->data.alias.alias_qn = cf_owned_string(owned, source->data.alias.alias_qn);
        copy->data.alias.underlying = cf_owned_type(owned, source->data.alias.underlying);
        break;
    case CBM_TYPE_INTERFACE:
        copy->data.interface_type.method_names =
            cf_owned_names(owned, source->data.interface_type.method_names);
        copy->data.interface_type.method_sigs =
            cf_owned_types(owned, source->data.interface_type.method_sigs);
        break;
    case CBM_TYPE_STRUCT:
        copy->data.struct_type.field_names =
            cf_owned_names(owned, source->data.struct_type.field_names);
        copy->data.struct_type.field_types =
            cf_owned_types(owned, source->data.struct_type.field_types);
        copy->data.struct_type.embedded_types =
            cf_owned_types(owned, source->data.struct_type.embedded_types);
        break;
    case CBM_TYPE_OBJECT_LIT:
        copy->data.object_lit.prop_names =
            cf_owned_names(owned, source->data.object_lit.prop_names);
        copy->data.object_lit.prop_types =
            cf_owned_types(owned, source->data.object_lit.prop_types);
        copy->data.object_lit.call_signature =
            cf_owned_type(owned, source->data.object_lit.call_signature);
        copy->data.object_lit.index_value =
            cf_owned_type(owned, source->data.object_lit.index_value);
        break;
    default:
        owned->failed = true;
        break;
    }
    return owned->failed ? NULL : copy;
}

static const CBMType *cf_merge_type(CFOwnedProjection *owned, const CBMType *native,
                                    const CBMType *projected, unsigned depth);

static const CBMType **cf_merge_slots(CFOwnedProjection *owned, const CBMType *const *native,
                                      const CBMType *const *projected, unsigned depth) {
    size_t old_count = cf_type_vector_count(native), new_count = cf_type_vector_count(projected);
    size_t count = old_count > new_count ? old_count : new_count;
    const CBMType **out = cf_owned_alloc(owned, (count + 1) * sizeof(*out));
    if (!out)
        return NULL;
    for (size_t i = 0; i < count; i++)
        out[i] = cf_merge_type(owned, i < old_count ? native[i] : NULL,
                               i < new_count ? projected[i] : NULL, depth + 1);
    for (size_t i = 0; i < count; i++) {
        if (!out[i])
            return NULL;
    }
    return out;
}

typedef struct {
    const char *name;
    size_t index;
    bool projected;
} CFMergeField;

static int cf_merge_field_compare(const void *left, const void *right) {
    const CFMergeField *a = left, *b = right;
    int result = strcmp(a->name, b->name);
    if (!result && a->projected != b->projected)
        return a->projected ? 1 : -1;
    return result ? result : (a->index > b->index) - (a->index < b->index);
}

static bool cf_merge_fields(CFOwnedProjection *owned, const char *const *old_names,
                            const CBMType *const *old_types, const char *const *new_names,
                            const CBMType *const *new_types, const char ***names_out,
                            const CBMType ***types_out, unsigned depth) {
    size_t old_count = cf_name_vector_count(old_names), new_count = cf_name_vector_count(new_names);
    const char **names = cf_owned_alloc(owned, (old_count + new_count + 1) * sizeof(*names));
    const CBMType **types = cf_owned_alloc(owned, (old_count + new_count + 1) * sizeof(*types));
    CFMergeField *order = old_count + new_count
                              ? cf_owned_alloc(owned, (old_count + new_count) * sizeof(*order))
                              : NULL;
    if (!names || !types || ((old_count + new_count) && !order))
        return false;
    for (size_t i = 0; i < old_count; i++) {
        names[i] = old_names[i];
        types[i] = old_types && old_types[i] ? old_types[i] : cbm_type_unknown();
        order[i] = (CFMergeField){old_names[i], i, false};
    }
    for (size_t i = 0; i < new_count; i++)
        order[old_count + i] = (CFMergeField){new_names[i], i, true};
    if (old_count + new_count > 1)
        qsort(order, old_count + new_count, sizeof(*order), cf_merge_field_compare);
    size_t count = old_count;
    for (size_t first = 0; first < old_count + new_count;) {
        size_t end = first + 1;
        while (end < old_count + new_count && strcmp(order[first].name, order[end].name) == 0)
            end++;
        size_t index = order[first].projected ? count++ : order[first].index;
        names[index] =
            order[first].projected ? cf_owned_string(owned, order[first].name) : order[first].name;
        if (!names[index])
            return false;
        for (size_t i = first; i < end; i++) {
            if (!order[i].projected)
                continue;
            types[index] = cf_merge_type(owned, types[index],
                                         new_types ? new_types[order[i].index] : NULL, depth + 1);
            if (!types[index])
                return false;
        }
        first = end;
    }
    *names_out = names;
    *types_out = types;
    return true;
}

static CBMType *cf_merge_shell(CFOwnedProjection *owned, const CBMType *projected) {
    CBMType *type = cf_owned_alloc(owned, sizeof(*type));
    if (type)
        *type = *projected;
    return type;
}

static const CBMType *cf_merge_type(CFOwnedProjection *owned, const CBMType *native,
                                    const CBMType *projected, unsigned depth) {
    if (cbm_type_is_unknown(projected) || depth >= CF_TYPE_DEPTH)
        return native ? native : cbm_type_unknown();
    if (!native || native->kind != projected->kind)
        return cf_owned_type(owned, projected);
    if (projected->kind == CBM_TYPE_POINTER || projected->kind == CBM_TYPE_SLICE ||
        projected->kind == CBM_TYPE_CHANNEL) {
        const CBMType *old_elem = cbm_type_elem(native), *new_elem = cbm_type_elem(projected);
        const CBMType *element = cf_merge_type(owned, old_elem, new_elem, depth + 1);
        CBMType *type = element ? cf_merge_shell(owned, projected) : NULL;
        if (!type)
            return NULL;
        if (projected->kind == CBM_TYPE_POINTER)
            type->data.pointer.elem = element;
        else if (projected->kind == CBM_TYPE_SLICE)
            type->data.slice.elem = element;
        else
            type->data.channel.elem = element;
        return type;
    }
    if (projected->kind == CBM_TYPE_MAP) {
        const CBMType *key =
            cf_merge_type(owned, native->data.map.key, projected->data.map.key, depth + 1);
        const CBMType *value =
            cf_merge_type(owned, native->data.map.value, projected->data.map.value, depth + 1);
        CBMType *type = key && value ? cf_merge_shell(owned, projected) : NULL;
        if (type) {
            type->data.map.key = key;
            type->data.map.value = value;
        }
        return type;
    }
    if (projected->kind == CBM_TYPE_TUPLE) {
        const CBMType **elements =
            cf_merge_slots(owned, native->data.tuple.elems, projected->data.tuple.elems, depth);
        CBMType *type = elements ? cf_merge_shell(owned, projected) : NULL;
        if (type) {
            type->data.tuple.elems = elements;
            type->data.tuple.count = (int)cf_type_vector_count(elements);
        }
        return type;
    }
    if (projected->kind == CBM_TYPE_ALIAS &&
        cf_equal(native->data.alias.alias_qn, projected->data.alias.alias_qn)) {
        const CBMType *underlying = cf_merge_type(owned, native->data.alias.underlying,
                                                  projected->data.alias.underlying, depth + 1);
        CBMType *type = underlying ? cf_merge_shell(owned, projected) : NULL;
        if (type) {
            type->data.alias.alias_qn = native->data.alias.alias_qn;
            type->data.alias.underlying = underlying;
        }
        return type;
    }
    if (projected->kind == CBM_TYPE_TEMPLATE &&
        cf_equal(native->data.template_type.template_name,
                 projected->data.template_type.template_name)) {
        const CBMType **args = cf_merge_slots(owned, native->data.template_type.template_args,
                                              projected->data.template_type.template_args, depth);
        CBMType *type = args ? cf_merge_shell(owned, projected) : NULL;
        if (type) {
            type->data.template_type.template_name = native->data.template_type.template_name;
            type->data.template_type.arg_count = (int)cf_type_vector_count(args);
            type->data.template_type.template_args =
                type->data.template_type.arg_count ? args : NULL;
        }
        return type;
    }
    if (projected->kind == CBM_TYPE_FUNC) {
        const CBMType **params = cf_merge_slots(owned, native->data.func.param_types,
                                                projected->data.func.param_types, depth);
        const CBMType **returns = cf_merge_slots(owned, native->data.func.return_types,
                                                 projected->data.func.return_types, depth);
        if (!params || !returns)
            return NULL;
        size_t count = cf_type_vector_count(params);
        size_t old_names = cf_name_vector_count(native->data.func.param_names);
        size_t new_names = cf_name_vector_count(projected->data.func.param_names);
        const char **names = cf_owned_alloc(owned, (count + 1) * sizeof(*names));
        if (!names)
            return NULL;
        for (size_t i = 0; i < count; i++)
            names[i] = i < new_names && projected->data.func.param_names[i][0]
                           ? cf_owned_string(owned, projected->data.func.param_names[i])
                       : i < old_names ? native->data.func.param_names[i]
                                       : "";
        CBMType *type = cf_merge_shell(owned, projected);
        if (type) {
            type->data.func.param_names = names;
            type->data.func.param_types = params;
            type->data.func.return_types = returns;
        }
        return owned->failed ? NULL : type;
    }
    if (projected->kind == CBM_TYPE_OBJECT_LIT) {
        const char **names;
        const CBMType **types;
        if (!cf_merge_fields(owned, native->data.object_lit.prop_names,
                             native->data.object_lit.prop_types,
                             projected->data.object_lit.prop_names,
                             projected->data.object_lit.prop_types, &names, &types, depth))
            return NULL;
        const CBMType *signature =
            cf_merge_type(owned, native->data.object_lit.call_signature,
                          projected->data.object_lit.call_signature, depth + 1);
        const CBMType *index = cf_merge_type(owned, native->data.object_lit.index_value,
                                             projected->data.object_lit.index_value, depth + 1);
        CBMType *type = signature && index ? cf_merge_shell(owned, projected) : NULL;
        if (type) {
            type->data.object_lit.prop_names = names[0] ? names : NULL;
            type->data.object_lit.prop_types = names[0] ? types : NULL;
            type->data.object_lit.call_signature = signature;
            type->data.object_lit.index_value = index;
        }
        return type;
    }
    return cf_owned_type(owned, projected);
}

static CFValue cf_binding_shape(const CBMCompilerFacts *facts, size_t id) {
    for (unsigned depth = 0; id && id <= facts->type_count && depth < CF_TYPE_DEPTH; depth++) {
        CFValue type = facts->types[id - 1].json;
        const char *kind = cfv_str(type, "kind");
        if (!cf_equal(kind, "named") && !cf_equal(kind, "alias"))
            return type;
        id = cf_id(type, "underlying");
    }
    return (CFValue){0};
}

static const CBMType *cf_callable_signature(const CBMType *type) {
    for (unsigned depth = 0; type && depth < CF_TYPE_DEPTH; depth++) {
        if (type->kind == CBM_TYPE_FUNC)
            return type;
        if (type->kind == CBM_TYPE_OBJECT_LIT)
            return type->data.object_lit.call_signature;
        if (type->kind != CBM_TYPE_ALIAS)
            break;
        type = type->data.alias.underlying;
    }
    return NULL;
}

static bool cf_merge_receiver_params(CFOwnedProjection *owned, CBMRegisteredFunc *function,
                                     const CBMType *receiver) {
    if (function->type_param_names)
        return true;
    for (unsigned depth = 0; receiver && depth < CF_TYPE_DEPTH; depth++) {
        if (receiver->kind == CBM_TYPE_POINTER)
            receiver = receiver->data.pointer.elem;
        else if (receiver->kind == CBM_TYPE_ALIAS)
            receiver = receiver->data.alias.underlying;
        else
            break;
    }
    if (!receiver || receiver->kind != CBM_TYPE_TEMPLATE)
        return true;
    const CBMType *const *args = receiver->data.template_type.template_args;
    size_t count = cf_type_vector_count(args);
    if (!count)
        return true;
    for (size_t i = 0; i < count; i++) {
        if (args[i]->kind != CBM_TYPE_TYPE_PARAM)
            return true;
    }
    const char **names = cf_owned_alloc(owned, (count + 1) * sizeof(*names));
    if (!names)
        return false;
    /* Go receiver parameters may rename the type declaration's parameters. */
    for (size_t i = 0; i < count; i++)
        names[i] = cf_owned_string(owned, args[i]->data.type_param.name);
    function->type_param_names = names;
    return !owned->failed;
}

static bool cf_merge_binding(const CBMCompilerFacts *facts, const CFBinding *binding,
                             CBMTypeRegistry *registry, CFOwnedProjection *owned) {
    const char *qn = binding->symbol->qn;
    /* Physical Go callables require exact site evidence, never short-name lookup. */
    if (!binding->is_type && strstr(qn, ".@go:"))
        return true;
    const CBMType *projected = cbm_compiler_facts_type(facts, binding->type_id);
    if (!binding->is_type) {
        projected = cf_callable_signature(projected);
        if (!projected || projected->kind != CBM_TYPE_FUNC)
            return true;
        const CBMType *receiver_type =
            cbm_compiler_facts_type(facts, cf_id(binding->symbol->json, "receiver"));
        bool go_method = cf_equal(cfv_str(binding->symbol->json, "kind"), "method");
        CBMRegisteredFunc *function = cbm_registry_func_for_update(registry, qn);
        if (!function) {
            const char *receiver = cf_type_qn(receiver_type);
            if (go_method && !receiver)
                return true;
            const char *owned_qn = cf_owned_string(owned, qn);
            const char *name = cf_owned_string(owned, cfv_str(binding->symbol->json, "name"));
            const char *owned_receiver = cf_owned_string(owned, receiver);
            const CBMType *signature = cf_owned_type(owned, projected);
            if (owned->failed)
                return false;
            int before = registry->func_count;
            cbm_registry_add_func(registry, (CBMRegisteredFunc){.qualified_name = owned_qn,
                                                                .short_name = name,
                                                                .receiver_type = owned_receiver,
                                                                .signature = signature,
                                                                .min_params = -1});
            if (registry->func_count != before + 1)
                return false;
            function = &registry->funcs[before];
        } else {
            const CBMType *merged = cf_merge_type(owned, function->signature, projected, 0);
            if (!merged)
                return false;
            function->signature = merged;
        }
        return !go_method || cf_merge_receiver_params(owned, function, receiver_type);
    }
    CFValue shape = cf_binding_shape(facts, binding->type_id);
    if (!shape.raw)
        return true;
    CBMRegisteredType *type = cbm_registry_type_for_update(registry, qn);
    if (!type) {
        const char *owned_qn = cf_owned_string(owned, qn);
        const char *name = cf_owned_string(owned, cfv_str(binding->symbol->json, "name"));
        if (owned->failed)
            return false;
        int before = registry->type_count;
        cbm_registry_add_type(registry,
                              (CBMRegisteredType){.qualified_name = owned_qn, .short_name = name});
        if (registry->type_count != before + 1)
            return false;
        type = &registry->types[before];
    }
    CFValue fields = cfv_get(shape, "fields");
    if (cfv_size(fields)) {
        size_t count = cfv_size(fields);
        const char **names = cf_owned_alloc(owned, (count + 1) * sizeof(*names));
        const CBMType **types = cf_owned_alloc(owned, (count + 1) * sizeof(*types));
        if (!names || !types)
            return false;
        size_t i, field_count;
        CFValue field;
        cfv_foreach(fields, i, field_count, field) {
            names[i] = cfv_str(field, "name");
            types[i] = cbm_compiler_facts_type(facts, cf_id(field, "type"));
        }
        if (!cf_merge_fields(owned, type->field_names, type->field_types, names, types,
                             &type->field_names, &type->field_types, 0))
            return false;
    }
    CFValue embeds = cfv_get(shape, "embeds");
    size_t old_count = cf_name_vector_count(type->embedded_types), count = cfv_size(embeds);
    if (count) {
        const char **out = cf_owned_alloc(owned, (old_count + count + 1) * sizeof(*out));
        if (!out)
            return false;
        if (old_count)
            memcpy(out, type->embedded_types, old_count * sizeof(*out));
        for (size_t i = 0; i < count; i++) {
            const char *embed = cf_type_qn(
                cbm_compiler_facts_type(facts, (size_t)cfv_get_uint(cfv_at(embeds, i))));
            size_t j = 0;
            while (embed && j < old_count && strcmp(out[j], embed) != 0)
                j++;
            if (embed && j == old_count) {
                out[old_count++] = cf_owned_string(owned, embed);
                if (owned->failed)
                    return false;
            }
        }
        type->embedded_types = out;
    }
    if (cf_equal(cfv_str(shape, "kind"), "interface") ||
        cf_equal(cfv_str(binding->symbol->json, "kind"), "InterfaceDeclaration"))
        type->is_interface = true;
    CFValue declaration_type =
        binding->type_id ? facts->types[binding->type_id - 1].json : (CFValue){0};
    CFValue parameters = cfv_get(declaration_type, "type_params");
    if (!parameters.raw)
        parameters = cfv_get(declaration_type, "args");
    size_t parameter_count = cfv_size(parameters);
    if (parameter_count && !type->type_param_names) {
        const char **names = cf_owned_alloc(owned, (parameter_count + 1) * sizeof(*names));
        const CBMType **constraints =
            cf_owned_alloc(owned, (parameter_count + 1) * sizeof(*constraints));
        if (!names || !constraints)
            return false;
        bool valid = true;
        for (size_t i = 0; i < parameter_count; i++) {
            size_t id = (size_t)cfv_get_uint(cfv_at(parameters, i));
            const CBMType *parameter = cbm_compiler_facts_type(facts, id);
            if (parameter->kind != CBM_TYPE_TYPE_PARAM) {
                valid = false;
                break;
            }
            names[i] = cf_owned_string(owned, parameter->data.type_param.name);
            constraints[i] = cf_owned_type(
                owned,
                cbm_compiler_facts_type(facts, cf_id(facts->types[id - 1].json, "underlying")));
            if (owned->failed)
                return false;
        }
        if (valid) {
            type->type_param_names = names;
            type->type_param_constraints = constraints;
        }
    }
    CFValue methods = cfv_get(shape, "methods");
    size_t i, method_count;
    CFValue method;
    cfv_foreach(methods, i, method_count, method) {
        const CBMType *signature = cbm_compiler_facts_type(facts, cf_id(method, "type"));
        if (signature->kind != CBM_TYPE_FUNC)
            continue;
        for (size_t j = 0; type->method_names && type->method_names[j]; j++) {
            if (!cf_equal(type->method_names[j], cfv_str(method, "name")) || !type->method_qns ||
                !type->method_qns[j])
                continue;
            CBMRegisteredFunc *function =
                cbm_registry_func_for_update(registry, type->method_qns[j]);
            if (function) {
                const CBMType *merged = cf_merge_type(owned, function->signature, signature, 0);
                if (!merged)
                    return false;
                function->signature = merged;
            }
        }
    }
    if (projected->kind == CBM_TYPE_ALIAS) {
        const char *underlying = cf_type_qn(projected->data.alias.underlying);
        if (underlying && strcmp(underlying, qn) != 0) {
            type->alias_of = cf_owned_string(owned, underlying);
            if (owned->failed)
                return false;
        }
    }
    CFValue signatures = cfv_get(shape, "signatures");
    const CBMType *signature =
        cf_equal(cfv_str(shape, "kind"), "function") || cf_equal(cfv_str(shape, "kind"), "signature")
            ? cbm_compiler_facts_type(facts, cf_id(shape, "id"))
        : cfv_size(signatures) == 1
            ? cbm_compiler_facts_type(facts, (size_t)cfv_get_uint(cfv_at(signatures, 0)))
            : NULL;
    if (signature && signature->kind == CBM_TYPE_FUNC) {
        const CBMType *merged = cf_merge_type(owned, type->call_signature, signature, 0);
        if (!merged)
            return false;
        type->call_signature = merged;
    }
    return true;
}

bool cbm_compiler_facts_merge_registry(const CBMCompilerFacts *facts, CBMTypeRegistry *registry,
                                       const char *rel_path) {
    if (!facts || !registry || !registry->arena || registry->read_only ||
        (rel_path && !cf_relative(rel_path)))
        return false;
    if (facts->package_index || facts->local_target_index || facts->proof_index)
        return true;
    CFOwnedProjection owned = {.arena = registry->arena};
    bool ok = true;
    size_t first = 0, end = facts->binding_count;
    if (rel_path) {
        size_t high = end;
        while (first < high) {
            size_t middle = first + (high - first) / 2;
            if (strcmp(facts->bindings[middle].path, rel_path) < 0)
                first = middle + 1;
            else
                high = middle;
        }
        end = first;
        while (end < facts->binding_count && strcmp(facts->bindings[end].path, rel_path) == 0)
            end++;
    }
    for (size_t i = first; i < end; i++) {
        const CFBinding *binding = &facts->bindings[i];
        if (!binding->ambiguous && !cf_merge_binding(facts, binding, registry, &owned)) {
            ok = false;
            break;
        }
        while (i + 1 < end && cf_binding_compare(binding, &facts->bindings[i + 1]) == 0)
            i++;
    }
    free(owned.types);
    return ok && !owned.failed;
}
