#ifndef CBM_EXTRACT_SQLITE_H
#define CBM_EXTRACT_SQLITE_H

#include "foundation/hash_table.h"
#include "sqlite3.h"
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Project unsupported SQLite trigger wrappers only after validation;
 * the original WHEN expression and body still get parsed. */
typedef struct {
    uint32_t start, end, line;
    char kind;
} CBMSQLiteToken;

typedef struct {
    const char *source;
    uint32_t len, at, line;
    CBMSQLiteToken token;
} CBMSQLiteScan;

typedef struct {
    CBMSQLiteToken name, schema, table, table_schema;
    uint32_t start, end, start_line, end_line;
    uint32_t update_of, update_of_end, condition, begin, closing;
    unsigned row_images;
    bool temporary, instead_of;
} CBMSQLiteTrigger;

enum { CBM_SQLITE_ROW_NEW = 1u, CBM_SQLITE_ROW_OLD = 2u };

static bool cbm_sqlite_word_char(unsigned char c) {
    return isalnum(c) || c == '_' || c == '$' || c >= 0x80;
}

static void cbm_sqlite_next(CBMSQLiteScan *s) {
    const char *src = s->source;
    while (s->at < s->len) {
        unsigned char c = (unsigned char)src[s->at];
        if (isspace(c)) {
            s->line += c == '\n';
            s->at++;
        } else if (c == '-' && s->at + 1 < s->len && src[s->at + 1] == '-') {
            while (s->at < s->len && src[s->at] != '\n')
                s->at++;
        } else if (c == '/' && s->at + 1 < s->len && src[s->at + 1] == '*') {
            uint32_t start = s->at;
            s->at += 2;
            while (s->at + 1 < s->len &&
                   !(src[s->at] == '*' && src[s->at + 1] == '/')) {
                s->line += src[s->at++] == '\n';
            }
            if (s->at + 1 >= s->len) {
                s->at = s->len;
                s->token = (CBMSQLiteToken){start, s->len, s->line, '\x01'};
                return;
            }
            s->at += 2;
        } else {
            break;
        }
    }
    CBMSQLiteToken t = {.start = s->at, .line = s->line};
    if (s->at < s->len) {
        unsigned char c = (unsigned char)src[s->at++];
        uint32_t tag_end = s->at;
        if (c == '$' && tag_end < s->len &&
            (src[tag_end] == '$' || isalpha((unsigned char)src[tag_end]) ||
             src[tag_end] == '_')) {
            while (tag_end < s->len &&
                   (isalnum((unsigned char)src[tag_end]) || src[tag_end] == '_'))
                tag_end++;
        }
        if (c == '$' && tag_end < s->len && src[tag_end] == '$') {
            uint32_t tag_len = tag_end - t.start + 1;
            s->at = tag_end + 1;
            t.kind = '\x01';
            while (s->at < s->len) {
                if (s->len - s->at >= tag_len &&
                    memcmp(src + s->at, src + t.start, tag_len) == 0) {
                    s->at += tag_len;
                    t.kind = 's';
                    break;
                }
                s->line += src[s->at++] == '\n';
            }
        } else if (cbm_sqlite_word_char(c)) {
            t.kind = 'w';
            while (s->at < s->len && cbm_sqlite_word_char((unsigned char)src[s->at]))
                s->at++;
        } else if (c == '\'' || c == '"' || c == '`' || c == '[') {
            char close = c == '[' ? ']' : (char)c;
            t.kind = '\x01';
            while (s->at < s->len) {
                char ch = src[s->at++];
                s->line += ch == '\n';
                if (ch == close) {
                    if (c != '[' && s->at < s->len && src[s->at] == close) {
                        s->at++;
                        continue;
                    }
                    t.kind = c == '\'' ? 's' : 'q';
                    break;
                }
            }
        } else {
            t.kind = (char)c;
        }
    }
    t.end = s->at;
    s->token = t;
}

static bool cbm_sqlite_is(CBMSQLiteScan *s, const char *word) {
    CBMSQLiteToken t = s->token;
    size_t len = strlen(word);
    if (t.kind != 'w' || t.end - t.start != len)
        return false;
    for (size_t i = 0; i < len; i++) {
        if (toupper((unsigned char)s->source[t.start + i]) != word[i])
            return false;
    }
    return true;
}

static bool cbm_sqlite_take(CBMSQLiteScan *s, const char *word) {
    if (!cbm_sqlite_is(s, word))
        return false;
    cbm_sqlite_next(s);
    return true;
}

/* Error recovery can put DDL following a savepoint boundary at file scope. */
static void cbm_sqlite_discard_unproven_schema_usages(CBMExtractCtx *ctx) {
    if (!ts_node_has_error(ctx->root))
        return;
    CBMUsageArray *usages = &ctx->result->usages;
    bool has_schema_usage = false;
    for (int i = 0; i < usages->count && !has_schema_usage; i++) {
        CBMUsageKind kind = usages->items[i].kind;
        has_schema_usage = kind == CBM_USAGE_SQL_FOREIGN_TABLE ||
                           kind == CBM_USAGE_SQL_TRIGGER_COLUMN ||
                           kind == CBM_USAGE_SQL_TRIGGER_OF_COLUMN;
    }
    if (!has_schema_usage)
        return;

    CBMSQLiteScan scan = {.source = ctx->source, .len = (uint32_t)ctx->source_len};
    bool boundary = true;
    bool uncertain = false;
    for (cbm_sqlite_next(&scan); scan.token.kind; cbm_sqlite_next(&scan)) {
        if (boundary) {
            if (cbm_sqlite_is(&scan, "SAVEPOINT") || cbm_sqlite_is(&scan, "RELEASE")) {
                uncertain = true;
                break;
            }
            CBMSQLiteScan rollback = scan;
            if (cbm_sqlite_take(&rollback, "ROLLBACK")) {
                (void)cbm_sqlite_take(&rollback, "TRANSACTION");
                if (cbm_sqlite_is(&rollback, "TO")) {
                    uncertain = true;
                    break;
                }
            }
        }
        boundary = scan.token.kind == ';';
    }
    if (!uncertain)
        return;
    int kept = 0;
    for (int i = 0; i < usages->count; i++) {
        CBMUsage usage = usages->items[i];
        if (usage.kind != CBM_USAGE_SQL_FOREIGN_TABLE && usage.kind != CBM_USAGE_SQL_TRIGGER_COLUMN &&
            usage.kind != CBM_USAGE_SQL_TRIGGER_OF_COLUMN)
            usages->items[kept++] = usage;
    }
    usages->count = kept;
}

static bool cbm_sqlite_identifier(CBMSQLiteScan *s, CBMSQLiteToken *name) {
    if (s->token.kind != 'q' && s->token.kind != 'w')
        return false;
    unsigned char first = (unsigned char)s->source[s->token.start];
    if (s->token.kind != 'q' &&
        (s->token.kind != 'w' || (!isalpha(first) && first != '_' && first < 0x80)))
        return false;
    *name = s->token;
    cbm_sqlite_next(s);
    return true;
}

static bool cbm_sqlite_name_is_keyword(const char *source, CBMSQLiteToken name) {
    return name.kind == 'w' &&
           sqlite3_keyword_check(source + name.start, (int)(name.end - name.start));
}

static int cbm_sqlite_prepare_default(sqlite3 **db, const char *source, uint32_t len,
                                      bool column, int *error_offset);

static bool cbm_sqlite_name_is_reserved(const char *source, CBMSQLiteToken name) {
    if (!cbm_sqlite_name_is_keyword(source, name))
        return false;
    /* SQLite allows keyword fallback names such as KEY and INDEXED. */
    sqlite3 *db = NULL;
    int rc = cbm_sqlite_prepare_default(&db, source + name.start, name.end - name.start,
                                       true, NULL);
    sqlite3_close(db);
    return rc != SQLITE_OK;
}

static bool cbm_sqlite_object_name(CBMSQLiteScan *s, CBMSQLiteToken *name,
                                    CBMSQLiteToken *schema) {
    if (!cbm_sqlite_identifier(s, name))
        return false;
    if (s->token.kind == '.') {
        if (cbm_sqlite_name_is_reserved(s->source, *name))
            return false;
        if (schema)
            *schema = *name;
        cbm_sqlite_next(s);
        if (!cbm_sqlite_identifier(s, name))
            return false;
    }
    return !cbm_sqlite_name_is_reserved(s->source, *name);
}

static bool cbm_sqlite_trigger_name(CBMSQLiteScan *s, CBMSQLiteTrigger *t) {
    if (!cbm_sqlite_take(s, "CREATE"))
        return false;
    t->temporary = cbm_sqlite_take(s, "TEMP") || cbm_sqlite_take(s, "TEMPORARY");
    if (!cbm_sqlite_take(s, "TRIGGER"))
        return false;
    if (cbm_sqlite_take(s, "IF") &&
        (!cbm_sqlite_take(s, "NOT") || !cbm_sqlite_take(s, "EXISTS")))
        return false;
    if (!cbm_sqlite_object_name(s, &t->name, &t->schema))
        return false;
    return !t->temporary || t->schema.end <= t->schema.start;
}

static bool cbm_sqlite_trigger(CBMSQLiteScan *s, CBMSQLiteTrigger *trigger) {
    CBMSQLiteTrigger t = {
        .start = s->token.start, .start_line = s->token.line, .condition = UINT32_MAX};
    if (!cbm_sqlite_trigger_name(s, &t))
        return false;
    if (!cbm_sqlite_take(s, "BEFORE") && !cbm_sqlite_take(s, "AFTER")) {
        t.instead_of = cbm_sqlite_take(s, "INSTEAD");
        if (t.instead_of && !cbm_sqlite_take(s, "OF"))
            return false;
    }
    if (cbm_sqlite_take(s, "UPDATE")) {
        t.row_images = CBM_SQLITE_ROW_NEW | CBM_SQLITE_ROW_OLD;
        if (cbm_sqlite_take(s, "OF")) {
            t.update_of = s->token.start;
            CBMSQLiteToken column;
            for (;;) {
                if (s->token.kind == 's' && s->source[s->token.start] == '\'') {
                    column = s->token;
                    cbm_sqlite_next(s);
                } else if (!cbm_sqlite_identifier(s, &column) ||
                           cbm_sqlite_name_is_keyword(s->source, column)) {
                    return false;
                }
                if (s->token.kind != ',')
                    break;
                cbm_sqlite_next(s);
            }
            t.update_of_end = column.end;
        }
    } else if (cbm_sqlite_take(s, "INSERT")) {
        t.row_images = CBM_SQLITE_ROW_NEW;
    } else if (cbm_sqlite_take(s, "DELETE")) {
        t.row_images = CBM_SQLITE_ROW_OLD;
    } else {
        return false;
    }
    if (!cbm_sqlite_take(s, "ON") || !cbm_sqlite_object_name(s, &t.table, &t.table_schema))
        return false;
    if (cbm_sqlite_take(s, "FOR") &&
        (!cbm_sqlite_take(s, "EACH") || !cbm_sqlite_take(s, "ROW")))
        return false;
    int parens = 0, cases = 0;
    if (cbm_sqlite_take(s, "WHEN")) {
        t.condition = s->token.start;
        while (s->token.kind && s->token.kind != '\x01') {
            if (parens == 0 && cases == 0 && cbm_sqlite_is(s, "BEGIN"))
                break;
            if (s->token.kind == ';' || (s->token.kind == ',' && parens == 0))
                return false;
            if (s->token.kind == '(')
                parens++;
            else if (s->token.kind == ')' && --parens < 0)
                return false;
            else if (cbm_sqlite_is(s, "CASE"))
                cases++;
            else if (cbm_sqlite_is(s, "END") && --cases < 0)
                return false;
            cbm_sqlite_next(s);
        }
        if (s->token.start == t.condition || parens || cases)
            return false;
    }
    t.begin = s->token.start;
    if (!cbm_sqlite_take(s, "BEGIN"))
        return false;
    bool statement_start = true;
    int statements = 0;
    while (s->token.kind && s->token.kind != '\x01') {
        if (parens == 0 && cases == 0 && cbm_sqlite_is(s, "END")) {
            if (!statement_start || statements == 0)
                return false;
            t.closing = s->token.start;
            cbm_sqlite_next(s);
            if (s->token.kind != ';')
                return false;
            t.end = s->token.end;
            t.end_line = s->token.line;
            cbm_sqlite_next(s);
            *trigger = t;
            return true;
        }
        if (statement_start) {
            if (!cbm_sqlite_is(s, "UPDATE") && !cbm_sqlite_is(s, "INSERT") &&
                !cbm_sqlite_is(s, "DELETE") && !cbm_sqlite_is(s, "REPLACE") &&
                !cbm_sqlite_is(s, "SELECT"))
                return false;
            statement_start = false;
            statements++;
        }
        if (s->token.kind == '(')
            parens++;
        else if (s->token.kind == ')' && --parens < 0)
            return false;
        else if (cbm_sqlite_is(s, "CASE"))
            cases++;
        else if (cbm_sqlite_is(s, "END") && --cases < 0)
            return false;
        else if (s->token.kind == ';') {
            if (parens || cases)
                return false;
            statement_start = true;
        }
        cbm_sqlite_next(s);
    }
    return false;
}

static void cbm_sqlite_mask(char *source, uint32_t start, uint32_t end) {
    for (uint32_t i = start; i < end; i++) {
        if (source[i] != '\r' && source[i] != '\n')
            source[i] = ' ';
    }
}

static bool cbm_sqlite_default_not_null_column(TSNode column, const char *source,
                                               int source_len, char *masked) {
    uint32_t children = ts_node_named_child_count(column);
    for (uint32_t i = 0; i + 1 < children; i++) {
        if (strcmp(ts_node_type(ts_node_named_child(column, i)), "keyword_default") != 0)
            continue;
        TSNode expr = ts_node_named_child(column, i + 1);
        if (strcmp(ts_node_type(expr), "binary_expression") != 0)
            continue;
        TSNode left = ts_node_child_by_field_name(expr, "left", 4);
        TSNode op = ts_node_child_by_field_name(expr, "operator", 8);
        TSNode right = ts_node_child_by_field_name(expr, "right", 5);
        if (ts_node_is_null(left) || ts_node_is_null(op) || ts_node_is_null(right) ||
            ts_node_has_error(left) || ts_node_has_error(right) || !ts_node_has_error(op) ||
            (strcmp(ts_node_type(left), "literal") != 0 &&
             strcmp(ts_node_type(left), "parenthesized_expression") != 0) ||
            strcmp(ts_node_type(op), "not_like") != 0 ||
            strcmp(ts_node_type(right), "literal") != 0)
            continue;
        uint32_t start = ts_node_start_byte(op), end = ts_node_end_byte(right);
        if (end > (uint32_t)source_len || start >= end)
            continue;
        CBMSQLiteScan s = {.source = source, .len = end, .at = start, .line = 1};
        cbm_sqlite_next(&s);
        if (!cbm_sqlite_take(&s, "NOT") || !cbm_sqlite_take(&s, "NULL") || s.token.kind)
            continue;
        /* The grammar mistakes this constraint for NOT LIKE with a missing
         * LIKE token. Keep the valid DEFAULT expression at its original span. */
        cbm_sqlite_mask(masked, start, end);
        return true;
    }
    return false;
}

static bool cbm_sqlite_default_not_null_compat_source(TSNode root, const char *source,
                                                      int source_len, char *masked) {
    if (!source || source_len <= 0 || ts_node_is_null(root))
        return false;
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    bool changed = false;
    for (;;) {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        if (ts_node_has_error(node) && strcmp(ts_node_type(node), "column_definition") == 0)
            changed |= cbm_sqlite_default_not_null_column(node, source, source_len, masked);
        if (ts_node_has_error(node) && ts_tree_cursor_goto_first_child(&cursor))
            continue;
        while (!ts_tree_cursor_goto_next_sibling(&cursor)) {
            if (!ts_tree_cursor_goto_parent(&cursor)) {
                ts_tree_cursor_delete(&cursor);
                return changed;
            }
        }
    }
}

static bool cbm_sqlite_dialect_evidence(const char *source, int source_len) {
    CBMSQLiteScan s = {.source = source, .len = (uint32_t)source_len, .line = 1};
    cbm_sqlite_next(&s);
    bool statement_start = true;
    bool previous_close = false, primary = false, primary_key = false;
    while (s.token.kind && s.token.kind != '\x01') {
        if (statement_start && cbm_sqlite_is(&s, "PRAGMA"))
            return true;
        if (previous_close && cbm_sqlite_is(&s, "WITHOUT")) {
            CBMSQLiteScan next = s;
            cbm_sqlite_next(&next);
            if (cbm_sqlite_is(&next, "ROWID"))
                return true;
        }
        if (primary_key && cbm_sqlite_is(&s, "AUTOINCREMENT"))
            return true;
        primary_key = primary && cbm_sqlite_is(&s, "KEY");
        primary = cbm_sqlite_is(&s, "PRIMARY");
        previous_close = s.token.kind == ')';
        statement_start = s.token.kind == ';';
        cbm_sqlite_next(&s);
    }
    return false;
}

static bool cbm_sqlite_has_autoincrement(const char *source, uint32_t len) {
    CBMSQLiteScan s = {.source = source, .len = len, .line = 1};
    cbm_sqlite_next(&s);
    while (s.token.kind && s.token.kind != '\x01') {
        if (cbm_sqlite_is(&s, "AUTOINCREMENT"))
            return true;
        cbm_sqlite_next(&s);
    }
    return false;
}

static int cbm_sqlite_prepare_table(sqlite3 **db, const char *prefix, const char *source,
                                   uint32_t len, const char *suffix, int *error_offset) {
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    if (error_offset)
        *error_offset = -1;
    if (!len || len > INT_MAX - prefix_len - suffix_len || memchr(source, '\0', len))
        return SQLITE_MISUSE;
    if (!*db) {
        int rc = sqlite3_open_v2(":memory:", db,
                                  SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_MEMORY |
                                      SQLITE_OPEN_NOMUTEX,
                                  NULL);
        if (rc != SQLITE_OK) {
            sqlite3_close(*db);
            *db = NULL;
            return rc;
        }
        (void)sqlite3_db_config(*db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, NULL);
    }
    size_t sql_len = prefix_len + len + suffix_len;
    char *sql = malloc(sql_len + 1);
    if (!sql)
        return SQLITE_NOMEM;
    memcpy(sql, prefix, prefix_len);
    memcpy(sql + prefix_len, source, len);
    memcpy(sql + prefix_len + len, suffix, suffix_len + 1);
    sqlite3_stmt *statement = NULL;
    const char *tail = NULL;
    /* Prepare only this fixed CREATE TABLE shell. No user statement or
     * default function is executed, and no table is created. */
    int rc = sqlite3_prepare_v3(*db, sql, (int)sql_len, SQLITE_PREPARE_NO_VTAB, &statement, &tail);
    int offset = sqlite3_error_offset(*db);
    if (error_offset && offset >= (int)prefix_len &&
        (size_t)offset < prefix_len + len)
        *error_offset = offset - (int)prefix_len;
    if (rc == SQLITE_OK && (!statement || tail != sql + sql_len))
        rc = SQLITE_MISUSE;
    sqlite3_finalize(statement);
    free(sql);
    return rc;
}

static int cbm_sqlite_prepare_default(sqlite3 **db, const char *source, uint32_t len,
                                      bool column, int *error_offset) {
    return cbm_sqlite_prepare_table(db, column ? "CREATE TABLE cbm_default("
                                              : "CREATE TABLE cbm_default(x DEFAULT ",
                                    source, len, ")", error_offset);
}

static char *cbm_sqlite_index_name(CBMExtractCtx *ctx, CBMSQLiteScan *scan) {
    CBMSQLiteToken name;
    if (!cbm_sqlite_identifier(scan, &name) || cbm_sqlite_name_is_keyword(ctx->source, name))
        return NULL;
    return cbm_sql_identifier_key(ctx->arena, ctx->source + name.start, name.end - name.start);
}

typedef struct {
    TSNode table;
    CBMHashTable *columns;
} CBMSQLiteSchemaObject;

static char *cbm_sqlite_node_key(CBMExtractCtx *ctx, TSNode name) {
    if (ts_node_is_null(name))
        return NULL;
    uint32_t from = ts_node_start_byte(name), to = ts_node_end_byte(name);
    return cbm_sql_identifier_key(ctx->arena, ctx->source + from, to - from);
}

static bool cbm_sqlite_record_column(CBMSQLiteSchemaObject *object, const char *key) {
    if (!key || cbm_ht_has(object->columns, key))
        return false;
    cbm_ht_set(object->columns, key, object);
    return cbm_ht_has(object->columns, key);
}

static bool cbm_sqlite_index_columns(CBMExtractCtx *ctx, CBMSQLiteSchemaObject *object) {
    if (object->columns)
        return true;
    TSNode definitions = cbm_find_child_by_kind(object->table, "column_definitions");
    if (ts_node_is_null(definitions))
        return false;
    object->columns = cbm_ht_create(0);
    if (!object->columns)
        return false;
    for (uint32_t i = 0; i < ts_node_named_child_count(definitions); ++i) {
        TSNode column = ts_node_named_child(definitions, i);
        if (strcmp(ts_node_type(column), "column_definition") != 0)
            continue;
        TSNode name = ts_node_child_by_field_name(column, "name", 4);
        if (!cbm_sqlite_record_column(object, cbm_sqlite_node_key(ctx, name)))
            return false;
    }
    return true;
}

/* shortcut: bind only declared columns in an empty, earlier table until
 * constraints, expressions and mutable data can be evaluated. */
static const char *cbm_sqlite_bare_index(CBMExtractCtx *ctx, CBMSQLiteScan scan,
                                         CBMHashTable *objects, sqlite3 *db) {
    (void)cbm_sqlite_take(&scan, "UNIQUE");
    if (!db || !cbm_sqlite_take(&scan, "INDEX"))
        return NULL;
    const char *index = cbm_sqlite_index_name(ctx, &scan);
    if (!index || !index[0] || strncmp(index, "sqlite_", 7) == 0 ||
        !cbm_sqlite_take(&scan, "ON"))
        return NULL;
    const char *target = cbm_sqlite_index_name(ctx, &scan);
    CBMSQLiteSchemaObject *object = target ? cbm_ht_get(objects, target) : NULL;
    if (!object || ts_node_is_null(object->table) || scan.token.kind != '(' ||
        !cbm_sqlite_index_columns(ctx, object))
        return NULL;
    const int limit = sqlite3_limit(db, SQLITE_LIMIT_COLUMN, -1);
    int count = 0;
    do {
        cbm_sqlite_next(&scan);
        const char *key = cbm_sqlite_index_name(ctx, &scan);
        if (!key || ++count > limit || !cbm_ht_has(object->columns, key))
            return NULL;
        (void)(cbm_sqlite_take(&scan, "ASC") || cbm_sqlite_take(&scan, "DESC"));
    } while (scan.token.kind == ',');
    if (scan.token.kind != ')')
        return NULL;
    cbm_sqlite_next(&scan);
    return !scan.token.kind && scan.token.start == scan.len ? index : NULL;
}

enum { CBM_SQLITE_MAX_REPLAY_BYTES = 65536 };

static bool cbm_sqlite_take_foreign_keys_pragma(CBMSQLiteScan *scan) {
    if (!cbm_sqlite_take(scan, "PRAGMA"))
        return false;
    if (cbm_sqlite_take(scan, "MAIN")) {
        if (scan->token.kind != '.')
            return false;
        cbm_sqlite_next(scan);
    }
    if (!cbm_sqlite_take(scan, "FOREIGN_KEYS") ||
        (scan->token.kind != '=' && scan->token.kind != '('))
        return false;
    bool parentheses = scan->token.kind == '(';
    cbm_sqlite_next(scan);
    CBMSQLiteScan value = *scan;
    if (value.token.kind == 'q' || value.token.kind == 's') {
        value.token.kind = 'w';
        ++value.token.start;
        --value.token.end;
    }
    if (!cbm_sqlite_is(&value, "ON") && !cbm_sqlite_is(&value, "TRUE") &&
        !cbm_sqlite_is(&value, "YES") && !cbm_sqlite_is(&value, "1"))
        return false;
    cbm_sqlite_next(scan);
    if (parentheses) {
        if (scan->token.kind != ')')
            return false;
        cbm_sqlite_next(scan);
    }
    if (scan->token.kind != ';')
        return false;
    cbm_sqlite_next(scan);
    return true;
}

static bool cbm_sqlite_take_begin(CBMSQLiteScan *scan) {
    if (!cbm_sqlite_take(scan, "BEGIN"))
        return false;
    (void)cbm_sqlite_take(scan, "TRANSACTION");
    if (scan->token.kind != ';')
        return false;
    cbm_sqlite_next(scan);
    return true;
}

/* The replay guard checks every tuple against the original source. */
static bool cbm_sqlite_keep_replay_values(const char *source, uint32_t length) {
    if (length > CBM_SQLITE_MAX_REPLAY_BYTES)
        return false;
    CBMSQLiteScan scan = {.source = source, .len = length};
    cbm_sqlite_next(&scan);
    return cbm_sqlite_take_foreign_keys_pragma(&scan) &&
           (cbm_sqlite_is(&scan, "CREATE") || cbm_sqlite_take_begin(&scan));
}

typedef struct {
    const char *table;
    const char *dropped_column;
    bool changes_existing_column;
} CBMSQLiteReplayAlter;

static int cbm_sqlite_replay_authorizer(void *userdata, int action, const char *arg,
                                       const char *detail, const char *database, const char *scope) {
    const CBMSQLiteReplayAlter *alter = userdata;
    if (scope)
        return SQLITE_DENY;
    if (action == SQLITE_ALTER_TABLE)
        return alter && arg && strcmp(arg, "main") == 0 && detail &&
               sqlite3_stricmp(alter->table, detail) == 0 &&
               ((!database && !alter->dropped_column) ||
                (database && alter->dropped_column &&
                 sqlite3_stricmp(database, alter->dropped_column) == 0))
                   ? SQLITE_OK : SQLITE_DENY;
    if (database && strcmp(database, "main") != 0) {
        /* SQLite reparses both catalogs when changing an existing column. */
        return alter && alter->changes_existing_column && strcmp(database, "temp") == 0 &&
               arg && strcmp(arg, "sqlite_temp_master") == 0 &&
               (action == SQLITE_READ ||
                (action == SQLITE_UPDATE && detail && strcmp(detail, "sql") == 0))
                   ? SQLITE_OK : SQLITE_DENY;
    }
    switch (action) {
    case SQLITE_TRANSACTION:
    case SQLITE_CREATE_TABLE:
    case SQLITE_CREATE_INDEX:
    case SQLITE_REINDEX:  /* `CREATE INDEX` compiles an internal refill. */
    case SQLITE_INSERT:
    case SQLITE_READ:
    case SQLITE_SELECT:  /* SQLite compiles multiple literal rows as an internal SELECT. */
        return SQLITE_OK;
    case SQLITE_PRAGMA:
        /* The closed replay loop issues this fixed check after COMMIT. */
        return arg && strcmp(arg, "foreign_key_check") == 0 && !detail
                   ? SQLITE_OK : SQLITE_DENY;
    case SQLITE_UPDATE:
        return arg && strcmp(arg, "sqlite_master") == 0 ? SQLITE_OK : SQLITE_DENY;
    case SQLITE_FUNCTION:
        if (!alter || !detail)
            return SQLITE_DENY;
        if (!alter->changes_existing_column)
            return strcmp(detail, "printf") == 0 || strcmp(detail, "substr") == 0 ||
                   strcmp(detail, "length") == 0 ? SQLITE_OK : SQLITE_DENY;
        return strcmp(detail, "like") == 0 || strcmp(detail, "sqlite_rename_test") == 0 ||
               strcmp(detail, "sqlite_rename_quotefix") == 0 ||
               strcmp(detail, "sqlite_rename_column") == 0 ||
               strcmp(detail, "sqlite_drop_column") == 0 ? SQLITE_OK : SQLITE_DENY;
    default:
        return SQLITE_DENY;
    }
}

static int cbm_sqlite_replay_progress(void *budget) {
    int *remaining = budget;
    return --*remaining <= 0;
}

static bool cbm_sqlite_replay_step(sqlite3 *db, const char *sql, int size) {
    sqlite3_stmt *statement = NULL;
    const char *tail = NULL;
    int rc = sqlite3_prepare_v3(db, sql, size, SQLITE_PREPARE_NO_VTAB, &statement, &tail);
    bool succeeded = rc == SQLITE_OK && statement && tail == sql + size &&
                     sqlite3_bind_parameter_count(statement) == 0 &&
                     sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return succeeded;
}

static bool cbm_sqlite_replay_open(sqlite3 **db, int *budget) {
    if (sqlite3_open_v2(":memory:", db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                        SQLITE_OPEN_MEMORY | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK ||
        sqlite3_db_config(*db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, NULL) != SQLITE_OK ||
        sqlite3_db_config(*db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, NULL) != SQLITE_OK ||
        sqlite3_db_config(*db, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL) != SQLITE_OK ||
        sqlite3_db_config(*db, SQLITE_DBCONFIG_ENABLE_FKEY, 1, NULL) != SQLITE_OK ||
        sqlite3_set_authorizer(*db, cbm_sqlite_replay_authorizer, NULL) != SQLITE_OK)
        return false;
    (void)sqlite3_limit(*db, SQLITE_LIMIT_ATTACHED, 0);
    sqlite3_progress_handler(*db, 1024, cbm_sqlite_replay_progress, budget);
    return true;
}

static bool cbm_sqlite_replay_column_alter(CBMExtractCtx *ctx, sqlite3 *db, TSNode alter,
                                           CBMHashTable *objects, bool add_only) {
    TSNode object = cbm_find_child_by_kind(alter, "object_reference");
    if (ts_node_is_null(object))
        return false;
    CBMSQLColumnAlter change = cbm_sql_column_alter(ctx, alter, object);
    if (add_only && !ts_node_is_null(change.old_name))
        return false;
    const char *old_key = cbm_sqlite_node_key(ctx, change.old_name);
    const char *new_key = cbm_sqlite_node_key(ctx, change.new_name);
    if ((!old_key && !new_key) || (!old_key && !ts_node_is_null(change.old_name)) ||
        (!new_key && !ts_node_is_null(change.new_name)))
        return false;
    const char *target = cbm_sqlite_node_key(ctx, ts_node_child_by_field_name(object, "name", 4));
    CBMSQLiteSchemaObject *table = target ? cbm_ht_get(objects, target) : NULL;
    if (!table || ts_node_is_null(table->table) || !cbm_sqlite_index_columns(ctx, table) ||
        (old_key && !cbm_ht_has(table->columns, old_key)))
        return false;
    CBMSQLiteReplayAlter permission = {.table = target, .dropped_column = new_key ? NULL : old_key,
                                      .changes_existing_column = old_key != NULL};
    if (sqlite3_set_authorizer(db, cbm_sqlite_replay_authorizer, &permission) != SQLITE_OK)
        return false;
    uint32_t from = ts_node_start_byte(alter), to = ts_node_end_byte(alter);
    bool applied = cbm_sqlite_replay_step(db, ctx->source + from, (int)(to - from));
    if (sqlite3_set_authorizer(db, cbm_sqlite_replay_authorizer, NULL) != SQLITE_OK || !applied)
        return false;
    if (old_key)
        cbm_ht_delete(table->columns, old_key);
    return !new_key || cbm_sqlite_record_column(table, new_key);
}

static bool cbm_sqlite_replay_table_defaults(CBMSQLiteScan scan) {
    for (; scan.token.kind; cbm_sqlite_next(&scan)) {
        if (scan.token.kind == '\x01')
            return false;
        if (cbm_sqlite_is(&scan, "GENERATED") || cbm_sqlite_is(&scan, "AS"))
            return false;
        if (!cbm_sqlite_take(&scan, "DEFAULT"))
            continue;
        if (cbm_sqlite_is(&scan, "NULL") ||
            (scan.token.kind == 's' && scan.source[scan.token.start] == '\''))
            continue;
        if (scan.token.kind == '+' || scan.token.kind == '-')
            cbm_sqlite_next(&scan);
        if (!isdigit((unsigned char)scan.source[scan.token.start]) && scan.token.kind != '.')
            return false;
    }
    return true;
}

static TSNode cbm_sqlite_next_named(TSNode node) {
    do {
        node = ts_node_next_named_sibling(node);
    } while (!ts_node_is_null(node) && ts_node_is_extra(node));
    return node;
}

static bool cbm_sqlite_node_is(TSNode node, const char *kind) {
    return !ts_node_is_null(node) && strcmp(ts_node_type(node), kind) == 0;
}

static bool cbm_sqlite_replay_literal(TSNode node, const char *source) {
    if (!cbm_sqlite_node_is(node, "literal"))
        return false;
    uint32_t start = ts_node_start_byte(node), end = ts_node_end_byte(node);
    CBMSQLiteScan scan = {.source = source, .len = end, .at = start};
    cbm_sqlite_next(&scan);
    if (cbm_sqlite_take(&scan, "NULL"))
        return scan.token.start == end;
    if (source[start] == '\'' && scan.token.kind == 's')
        return scan.token.start == start && scan.token.end == end;
    const char *digits = source + start;
    if (*digits == '+' || *digits == '-')
        ++digits;
    if (digits >= source + end || (!isdigit((unsigned char)*digits) && *digits != '.'))
        return false;
    for (; digits < source + end; ++digits) {
        if (!strchr("0123456789abcdefABCDEFxX+-. _", (unsigned char)*digits))
            return false;
    }
    return true;
}

static bool cbm_sqlite_name_matches(TSNode name, const char *source, const char *text, uint32_t len);

static bool cbm_sqlite_replay_insert(sqlite3 *db, TSNode op, CBMSQLiteScan scan) {
    uint32_t from = ts_node_start_byte(op), to = ts_node_end_byte(op);
    if (!cbm_sqlite_take(&scan, "INSERT") || !cbm_sqlite_take(&scan, "INTO"))
        return false;
    CBMSQLiteToken identifier, schema = {0};
    if (!cbm_sqlite_object_name(&scan, &identifier, &schema) ||
        (scan.token.kind != '(' && !cbm_sqlite_is(&scan, "VALUES")))
        return false;
    uint32_t first = identifier.start + (identifier.kind == 'q');
    if (identifier.end - first >= 7 && sqlite3_strnicmp(scan.source + first, "sqlite_", 7) == 0)
        return false;
    TSNode node = ts_node_named_child(op, 0);
    while (ts_node_is_extra(node))
        node = cbm_sqlite_next_named(node);
    if (!cbm_sqlite_node_is(node, "keyword_insert"))
        return false;
    node = cbm_sqlite_next_named(node);
    if (!cbm_sqlite_node_is(node, "keyword_into"))
        return false;
    node = cbm_sqlite_next_named(node);
    if (!cbm_sqlite_node_is(node, "object_reference"))
        return false;
    TSNode name = ts_node_child_by_field_name(node, "name", 4);
    TSNode qualifier = ts_node_child_by_field_name(node, "schema", 6);
    if (ts_node_is_null(name) || ts_node_start_byte(name) != identifier.start ||
        ts_node_end_byte(name) != identifier.end ||
        ts_node_start_byte(node) != (schema.kind ? schema.start : identifier.start) ||
        ts_node_end_byte(node) != identifier.end ||
        (schema.kind ? (ts_node_start_byte(qualifier) != schema.start ||
                        ts_node_end_byte(qualifier) != schema.end ||
                        !cbm_sqlite_name_matches(qualifier, scan.source, "main", 4))
                     : !ts_node_is_null(qualifier)))
        return false;
    node = cbm_sqlite_next_named(node);
    if (cbm_sqlite_node_is(node, "list")) {
        for (uint32_t i = 0; i < ts_node_named_child_count(node); ++i) {
            TSNode column = ts_node_named_child(node, i);
            if (!ts_node_is_extra(column) && !cbm_sqlite_node_is(column, "column"))
                return false;
        }
        node = cbm_sqlite_next_named(node);
    }
    if (!cbm_sqlite_node_is(node, "keyword_values"))
        return false;
    enum { MAX_REPLAY_VALUES = 128 };
    int rows = 0, values = 0;
    for (node = cbm_sqlite_next_named(node); !ts_node_is_null(node); node = cbm_sqlite_next_named(node)) {
        if (!cbm_sqlite_node_is(node, "list"))
            return false;
        ++rows;
        for (uint32_t i = 0; i < ts_node_named_child_count(node); ++i) {
            TSNode value = ts_node_named_child(node, i);
            if (!ts_node_is_extra(value) && (++values > MAX_REPLAY_VALUES || !cbm_sqlite_replay_literal(value, scan.source)))
                return false;
        }
    }
    if (!rows || !values)
        return false;
    return cbm_sqlite_replay_step(db, scan.source + from, (int)(to - from)) &&
           sqlite3_changes64(db) == rows;
}

/* Creating the trigger records its definition without executing its body. */
static int cbm_sqlite_replay_trigger_authorizer(void *userdata, int action, const char *arg,
                                               const char *detail, const char *database,
                                               const char *scope) {
    (void)userdata;
    (void)detail;
    if (scope || !database || strcmp(database, "main") != 0)
        return SQLITE_DENY;
    return action == SQLITE_CREATE_TRIGGER ||
           (action == SQLITE_INSERT && arg && strcmp(arg, "sqlite_master") == 0)
               ? SQLITE_OK : SQLITE_DENY;
}

static bool cbm_sqlite_replay_triggers(sqlite3 *db, CBMSQLiteScan scan, CBMSQLiteTrigger trigger) {
    if (sqlite3_set_authorizer(db, cbm_sqlite_replay_trigger_authorizer, NULL) != SQLITE_OK)
        return false;
    do {
        if (!cbm_sqlite_replay_step(db, scan.source + trigger.start,
                                    (int)(trigger.end - trigger.start)))
            return false;
        if (!scan.token.kind)
            return scan.token.start == scan.len;
    } while (cbm_sqlite_trigger(&scan, &trigger));
    return false;
}

static bool cbm_sqlite_has_trigger_columns(CBMExtractCtx *ctx) {
    const CBMUsageArray *usages = &ctx->result->usages;
    for (int i = 0; i < usages->count; ++i) {
        CBMUsageKind kind = usages->items[i].kind;
        if (kind == CBM_USAGE_SQL_TRIGGER_COLUMN || kind == CBM_USAGE_SQL_TRIGGER_OF_COLUMN)
            return true;
    }
    return false;
}

/* shortcut: require any prior schema to be declared by supported DDL in this file. */
static TSNode cbm_sqlite_verified_schema(CBMExtractCtx *ctx, bool *require_replay,
                                        TSNode *verified_top_level_alter) {
    TSNode none = {0};
    TSNode block = cbm_find_child_by_kind(ctx->root, "block");
    TSNode transaction = cbm_find_child_by_kind(ctx->root, "transaction");
    bool top_level = ts_node_is_null(block) && ts_node_is_null(transaction);
    *require_replay = false;
    *verified_top_level_alter = none;
    if (top_level && ctx->source_len > CBM_SQLITE_MAX_REPLAY_BYTES)
        return none;

    enum { MAX_SCHEMA_BYTES = 1024 * 1024, MAX_SCHEMA_STATEMENTS = 128 };
    uint32_t length = (uint32_t)ctx->source_len;
    CBMSQLiteScan scan = {.source = ctx->source, .len = length};
    cbm_sqlite_next(&scan);
    bool fk_pragma = cbm_sqlite_is(&scan, "PRAGMA");
    bool fk_enforced = fk_pragma && cbm_sqlite_take_foreign_keys_pragma(&scan);
    *require_replay = !top_level && fk_enforced;

    if (length > MAX_SCHEMA_BYTES || memchr(ctx->source, '\0', length) ||
        memchr(ctx->source, '\v', length) || ts_node_has_error(ctx->root) ||
        (fk_pragma && !fk_enforced))
        return none;

    if (*require_replay && !ts_node_is_null(transaction) &&
        (ts_node_is_null(block) || ts_node_start_byte(transaction) < ts_node_start_byte(block)))
        block = transaction;
    if (top_level ? !fk_enforced || !cbm_sqlite_has_trigger_columns(ctx)
                  : ts_node_is_null(block))
        return none;

    const uint32_t start = top_level ? 0 : ts_node_start_byte(block);
    const uint32_t end = top_level ? 0 : ts_node_end_byte(block);
    bool prefix = !top_level && *require_replay && scan.token.start < start;
    if (!top_level &&
        ((!prefix && (scan.token.start != start || !cbm_sqlite_take_begin(&scan))) ||
         (!fk_pragma && !cbm_sqlite_dialect_evidence(ctx->source + start, (int)(end - start)))))
        return none;

    bool replay = top_level || prefix || cbm_sqlite_node_is(block, "transaction");
    for (TSNode stmt = replay ? none : ts_node_named_child(block, 0);
         !replay && !ts_node_is_null(stmt);
         stmt = ts_node_next_named_sibling(stmt)) {
        if (cbm_sqlite_node_is(stmt, "statement") &&
            (!ts_node_is_null(cbm_find_child_by_kind(stmt, "insert")) ||
             !ts_node_is_null(cbm_find_child_by_kind(stmt, "alter_table")))) {
            replay = true;
            break;
        }
    }
    /* shortcut: replay bounded scripts with explicit FK enforcement and literal writes. */
    enum { REPLAY_BUDGET = 1000 };
    if (replay && (!fk_enforced || length > CBM_SQLITE_MAX_REPLAY_BYTES))
        return none;

    CBMHashTable *objects = cbm_ht_create(0);
    if (!objects)
        return none;
    CBMSQLiteSchemaObject declarations[MAX_SCHEMA_STATEMENTS] = {0};
    sqlite3 *db = NULL;
    int budget = REPLAY_BUDGET;
    if (replay && !cbm_sqlite_replay_open(&db, &budget)) {
        sqlite3_close(db);
        cbm_ht_free(objects);
        return none;
    }
    unsigned count = 0;
    bool valid = false, altered = false;
    TSNode begin = top_level ? none : cbm_find_child_by_kind(block, "keyword_begin");
    TSNode body = top_level ? none : cbm_sqlite_next_named(begin);
    if (cbm_sqlite_node_is(body, "keyword_transaction"))
        body = cbm_sqlite_next_named(body);
    TSNode child = (prefix || top_level) ? ts_node_named_child(ctx->root, 0) : body;
    if (prefix || top_level) {
        while (!ts_node_is_null(child) && ts_node_end_byte(child) <= scan.token.start)
            child = cbm_sqlite_next_named(child);
    } else if (replay && !cbm_sqlite_replay_step(db, "BEGIN", 5)) {
        child = none;
    }
    unsigned prefix_count = 0;
    TSNode last_alter = none;
    const char check[] = "PRAGMA main.foreign_key_check";
    for (; !ts_node_is_null(child); child = cbm_sqlite_next_named(child)) {
        /* Trigger compatibility can project the body to top-level statements.
         * Validate the original trigger DDL in the isolated schema instead. */
        CBMSQLiteScan suffix = scan;
        CBMSQLiteTrigger trigger;
        if (top_level && !ts_node_is_null(last_alter) && cbm_sqlite_trigger(&suffix, &trigger)) {
            if (cbm_sqlite_replay_step(db, check, (int)sizeof(check) - 1) &&
                cbm_sqlite_replay_triggers(db, suffix, trigger))
                *verified_top_level_alter = last_alter;
            break;
        }
        if (prefix && ts_node_eq(child, block)) {
            if (scan.token.start != start || !cbm_sqlite_take_begin(&scan) ||
                !cbm_sqlite_replay_step(db, "BEGIN", 5) || ts_node_is_null(body))
                break;
            prefix_count = count;
            prefix = false;
            child = body;
        }
        if (cbm_sqlite_node_is(child, "keyword_end") || cbm_sqlite_node_is(child, "keyword_commit")) {
            if (scan.token.start != ts_node_start_byte(child) ||
                !(cbm_sqlite_is(&scan, "END") || cbm_sqlite_is(&scan, "COMMIT")))
                break;
            uint32_t close = scan.token.end;
            cbm_sqlite_next(&scan);
            if (close < end && cbm_sqlite_is(&scan, "TRANSACTION")) {
                close = scan.token.end;
                cbm_sqlite_next(&scan);
            }
            if (close != end)
                break;
            if (scan.token.kind == ';')
                cbm_sqlite_next(&scan);
            valid = count > prefix_count && !scan.token.kind && scan.token.start == length &&
                    (!replay || (cbm_sqlite_replay_step(db, "COMMIT", 6) && sqlite3_get_autocommit(db)));
            if (valid && (altered || prefix_count))
                valid = cbm_sqlite_replay_step(db, check, (int)sizeof(check) - 1);
            break;
        }
        TSNode create = cbm_find_child_by_kind(child, "create_table");
        const bool table = !ts_node_is_null(create);
        if (!table)
            create = cbm_find_child_by_kind(child, "create_index");
        TSNode insert = replay && !prefix && !top_level
                            ? cbm_find_child_by_kind(child, "insert") : none;
        TSNode alter = replay && !prefix ? cbm_find_child_by_kind(child, "alter_table") : none;
        TSNode operation = !ts_node_is_null(insert) ? insert : !ts_node_is_null(alter) ? alter : create;
        uint32_t from = ts_node_start_byte(child), to = ts_node_end_byte(child);
        if (strcmp(ts_node_type(child), "statement") != 0 || ts_node_is_null(operation) ||
            ts_node_start_byte(operation) != from || ts_node_end_byte(operation) != to ||
            count == MAX_SCHEMA_STATEMENTS || scan.token.start != from)
            break;
        CBMSQLiteScan statement = scan;
        statement.len = to;
        const char *key = NULL;
        if (!ts_node_is_null(insert)) {
            if (!cbm_sqlite_replay_insert(db, insert, statement))
                break;
        } else if (!ts_node_is_null(alter)) {
            if (!cbm_sqlite_replay_column_alter(ctx, db, alter, objects, top_level))
                break;
            altered = true;
            last_alter = child;
        } else if (!cbm_sqlite_take(&statement, "CREATE")) {
            break;
        } else if (table) {
            CBMSQLiteToken name;
            if (!cbm_sqlite_take(&statement, "TABLE") || !cbm_sqlite_identifier(&statement, &name) ||
                statement.token.kind != '(')
                break;
            if (replay) {
                TSNode columns = cbm_find_child_by_kind(create, "column_definitions");
                if (ts_node_is_null(columns) || ts_node_start_byte(columns) != statement.token.start ||
                    !cbm_sqlite_replay_table_defaults(statement) ||
                    !cbm_sqlite_replay_step(db, ctx->source + from, (int)(to - from)))
                    break;
            } else if (cbm_sqlite_prepare_table(&db, "", ctx->source + from, to - from, "", NULL) != SQLITE_OK) {
                break;
            }
            key = cbm_sql_identifier_key(ctx->arena, ctx->source + name.start, name.end - name.start);
            declarations[count].table = create;
        } else {
            key = cbm_sqlite_bare_index(ctx, statement, objects, db);
            if (replay && key && !cbm_sqlite_replay_step(db, ctx->source + from, (int)(to - from)))
                break;
        }
        if (!ts_node_is_null(create)) {
            if (!key || cbm_ht_has(objects, key))
                break;
            cbm_ht_set(objects, key, &declarations[count]);
            if (!cbm_ht_has(objects, key))
                break;
        }
        ++count;
        scan.at = to;
        cbm_sqlite_next(&scan);
        if (scan.token.kind != ';')
            break;
        cbm_sqlite_next(&scan);
    }
    sqlite3_close(db);
    for (unsigned i = 0; i < count; ++i)
        cbm_ht_free(declarations[i].columns);
    cbm_ht_free(objects);
    return valid ? block : none;
}

static bool cbm_sqlite_strict_compat(TSNode table, TSNode definitions, const char *source,
                                     int source_len, sqlite3 **db, char *masked) {
    uint32_t start = ts_node_start_byte(definitions), end = ts_node_end_byte(definitions);
    if (end <= start + 2 || end > (uint32_t)source_len || source[start] != '(' ||
        source[end - 1] != ')' || ts_node_has_error(definitions))
        return false;

    CBMSQLiteScan scan = {.source = source, .len = (uint32_t)source_len, .at = end};
    cbm_sqlite_next(&scan);
    CBMSQLiteToken mask_first = scan.token, mask_last = scan.token;
    if (cbm_sqlite_take(&scan, "STRICT")) {
        if (scan.token.kind == ',') {
            mask_last = scan.token;
            cbm_sqlite_next(&scan);
            if (!cbm_sqlite_take(&scan, "WITHOUT") || !cbm_sqlite_take(&scan, "ROWID"))
                return false;
        }
    } else if (cbm_sqlite_take(&scan, "WITHOUT") && cbm_sqlite_take(&scan, "ROWID") &&
               scan.token.kind == ',') {
        mask_first = scan.token;
        cbm_sqlite_next(&scan);
        mask_last = scan.token;
        if (!cbm_sqlite_take(&scan, "STRICT"))
            return false;
    } else {
        return false;
    }
    if (scan.token.kind && scan.token.kind != ';')
        return false;
    if (masked && masked[mask_first.start] == ' ' && masked[mask_last.start] == ' ')
        return false;
    uint32_t statement_end = scan.token.end;
    uint32_t statement_start = ts_node_start_byte(table);
    scan.at = statement_start;
    cbm_sqlite_next(&scan);
    if (!cbm_sqlite_take(&scan, "CREATE"))
        return false;
    (void)(cbm_sqlite_take(&scan, "TEMP") || cbm_sqlite_take(&scan, "TEMPORARY"));
    if (!cbm_sqlite_take(&scan, "TABLE") ||
        cbm_sqlite_prepare_table(db, "", source + statement_start, statement_end - statement_start,
                                 "", NULL) != SQLITE_OK)
        return false;
    if (masked) {
        cbm_sqlite_mask(masked, mask_first.start, mask_first.end);
        cbm_sqlite_mask(masked, mask_last.start, mask_last.end);
    }
    return true;
}

static bool cbm_sqlite_strict_compat_source(TSNode root, const char *source, int source_len,
                                            char *masked) {
    sqlite3 *db = NULL;
    bool changed = false;
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    if (!ts_tree_cursor_goto_first_child(&cursor)) {
        ts_tree_cursor_delete(&cursor);
        return false;
    }
    do {
        TSNode statement = ts_tree_cursor_current_node(&cursor);
        if (strcmp(ts_node_type(statement), "statement") != 0)
            continue;
        TSNode table = ts_node_named_child(statement, 0);
        if (ts_node_is_null(table) || strcmp(ts_node_type(table), "create_table") != 0)
            continue;
        uint32_t children = ts_node_named_child_count(table);
        for (uint32_t j = 0; j < children; j++) {
            TSNode child = ts_node_named_child(table, j);
            if (strcmp(ts_node_type(child), "column_definitions") == 0) {
                changed |= cbm_sqlite_strict_compat(table, child, source, source_len, &db, masked);
                break;
            }
        }
    } while (ts_tree_cursor_goto_next_sibling(&cursor));
    ts_tree_cursor_delete(&cursor);
    sqlite3_close(db);
    return changed;
}

/* The complete original column list is validated before projecting a column. */
static bool cbm_sqlite_column_compat(const char *source, uint32_t start, uint32_t end,
                                     char *masked) {
    CBMSQLiteScan s = {.source = source, .len = end, .at = start, .line = 1};
    CBMSQLiteToken name, bare = {0}, autoincrement = {0};
    cbm_sqlite_next(&s);
    if (!cbm_sqlite_identifier(&s, &name) || cbm_sqlite_name_is_keyword(source, name))
        return false;
    int parens = 0;
    while (s.token.kind && s.token.kind != '\x01') {
        if (parens == 0 && cbm_sqlite_take(&s, "DEFAULT")) {
            CBMSQLiteToken value;
            CBMSQLiteScan candidate = s;
            /* SQLite accepts some keywords as default strings; preparing
             * the complete original column list validates their context. */
            bool grammar_literal =
                cbm_sqlite_is(&candidate, "NULL") || cbm_sqlite_is(&candidate, "TRUE") ||
                cbm_sqlite_is(&candidate, "FALSE") ||
                cbm_sqlite_is(&candidate, "CURRENT_TIMESTAMP");
            if (!grammar_literal && candidate.token.kind == 'w' &&
                cbm_sqlite_identifier(&candidate, &value) &&
                (!candidate.token.kind || candidate.token.kind == 'w')) {
                bare = value;
                s = candidate;
                continue;
            }
        }
        if (parens == 0 && cbm_sqlite_is(&s, "AUTOINCREMENT"))
            autoincrement = s.token;
        if (s.token.kind == '(')
            parens++;
        else if (s.token.kind == ')' && --parens < 0)
            return false;
        cbm_sqlite_next(&s);
    }
    if (!bare.end && !autoincrement.end)
        return false;
    /* Bare SQLite defaults are strings, not field references. Keep
     * their spans; a following NOT NULL uses the existing projection. */
    if (bare.end)
        memset(masked + bare.start, '0', bare.end - bare.start);
    if (autoincrement.end)
        cbm_sqlite_mask(masked, autoincrement.start, autoincrement.end);
    return true;
}

static bool cbm_sqlite_fk_deferral(TSNode error, uint32_t definitions_end, const char *source,
                                    CBMSQLiteScan *clause) {
    TSNode parent = ts_node_parent(error);
    const char *parent_kind = ts_node_type(parent);
    bool inline_constraint = strcmp(parent_kind, "column_definition") == 0;
    if (!inline_constraint && strcmp(parent_kind, "column_definitions") != 0 &&
        strcmp(parent_kind, "constraints") != 0)
        return false;
    uint32_t start = ts_node_start_byte(error), end = ts_node_end_byte(error);
    TSNode wrapped = ts_node_named_child(error, 0);
    bool split = ts_node_named_child_count(error) == 1 &&
                 ts_node_start_byte(wrapped) == start && ts_node_end_byte(wrapped) == end &&
                 (strcmp(ts_node_type(wrapped), "column_definition") == 0 ||
                  strcmp(ts_node_type(wrapped), "constraint") == 0);
    TSNode owner = wrapped;
    if (split) {
        /* A comment between keywords can make the parser wrap the intact reference in ERROR. */
        start = end;
        end = definitions_end;
    } else {
        TSNode previous = ts_node_prev_sibling(error);
        while (!ts_node_is_null(previous) && ts_node_is_extra(previous))
            previous = ts_node_prev_sibling(previous);
        if (ts_node_is_null(previous) || strcmp(ts_node_type(previous), ",") == 0)
            return false;
        owner = inline_constraint ? parent : previous;
        if (strcmp(ts_node_type(owner), "constraints") == 0) {
            owner = ts_node_named_child(owner, ts_node_named_child_count(owner) - 1);
            while (!ts_node_is_null(owner) && ts_node_is_extra(owner))
                owner = ts_node_prev_named_sibling(owner);
        }
    }
    if (ts_node_is_null(owner))
        return false;
    bool column = strcmp(ts_node_type(owner), "column_definition") == 0;
    if (!column && strcmp(ts_node_type(owner), "constraint") != 0)
        return false;
    CBMSQLiteScan scan = {.source = source, .len = end, .at = start};
    cbm_sqlite_next(&scan);
    uint32_t first = scan.token.start;
    (void)cbm_sqlite_take(&scan, "NOT");
    if (!cbm_sqlite_take(&scan, "DEFERRABLE") ||
        (cbm_sqlite_take(&scan, "INITIALLY") && !cbm_sqlite_take(&scan, "DEFERRED") &&
         !cbm_sqlite_take(&scan, "IMMEDIATE")) ||
        (!split && scan.token.kind) ||
        (split && scan.token.kind != ',' && scan.token.kind != ')' &&
         !(column && scan.token.kind == 'w')))
        return false;
    uint32_t count = ts_node_named_child_count(owner);
    for (uint32_t i = 0; i < count; i++) {
        TSNode child = ts_node_named_child(owner, i);
        if (ts_node_start_byte(child) >= start)
            break;
        if (strcmp(ts_node_type(child), "keyword_references") == 0) {
            *clause = (CBMSQLiteScan){.source = source, .len = scan.token.start, .at = first};
            return true;
        }
    }
    return false;
}

static bool cbm_sqlite_fk_constraint_name(TSNode error, uint32_t definitions_end,
                                           const char *source, CBMSQLiteScan *clause) {
    const char *parent = ts_node_type(ts_node_parent(error));
    if (strcmp(parent, "column_definition") != 0 && strcmp(parent, "column_definitions") != 0 &&
        strcmp(parent, "constraints") != 0)
        return false;
    uint32_t start = ts_node_start_byte(error);
    CBMSQLiteScan scan = {.source = source, .len = definitions_end, .at = start};
    cbm_sqlite_next(&scan);
    if (!cbm_sqlite_take(&scan, "CONSTRAINT"))
        return false;
    CBMSQLiteToken name = scan.token;
    if (name.kind == 's') {
        cbm_sqlite_next(&scan);
    } else if (!cbm_sqlite_identifier(&scan, &name)) {
        return false;
    }
    if (!cbm_sqlite_is(&scan, "REFERENCES") &&
        !(cbm_sqlite_take(&scan, "FOREIGN") && cbm_sqlite_is(&scan, "KEY")))
        return false;
    *clause = (CBMSQLiteScan){.source = source, .len = name.end, .at = start};
    return true;
}

static bool cbm_sqlite_conflict_clause(TSNode error, uint32_t definitions_end, const char *source,
                                       CBMSQLiteScan *clause) {
    const char *parent = ts_node_type(ts_node_parent(error));
    if (strcmp(parent, "column_definition") != 0 && strcmp(parent, "column_definitions") != 0 &&
        strcmp(parent, "constraints") != 0 && strcmp(parent, "constraint") != 0)
        return false;
    uint32_t start = ts_node_start_byte(error), end = ts_node_end_byte(error);
    TSNode wrapped = ts_node_named_child(error, 0);
    bool split = ts_node_named_child_count(error) == 1 &&
                 ts_node_start_byte(wrapped) == start && ts_node_end_byte(wrapped) == end &&
                 (strcmp(ts_node_type(wrapped), "column_definition") == 0 ||
                  strcmp(ts_node_type(wrapped), "constraint") == 0);
    if (split) {
        start = end;
        end = definitions_end;
    }
    CBMSQLiteScan scan = {.source = source, .len = end, .at = start};
    cbm_sqlite_next(&scan);
    uint32_t first = scan.token.start;
    if (!cbm_sqlite_take(&scan, "ON") || !cbm_sqlite_take(&scan, "CONFLICT") ||
        !(cbm_sqlite_take(&scan, "ROLLBACK") || cbm_sqlite_take(&scan, "ABORT") ||
          cbm_sqlite_take(&scan, "FAIL") || cbm_sqlite_take(&scan, "IGNORE") ||
          cbm_sqlite_take(&scan, "REPLACE")) ||
        (!split && scan.token.kind))
        return false;
    *clause = (CBMSQLiteScan){.source = source, .len = scan.token.start, .at = first};
    return true;
}

static bool cbm_sqlite_constraints_compat(TSNode definitions, const char *source,
                                          int source_len, sqlite3 **db, char *masked) {
    bool changed = false;
    TSTreeCursor cursor = ts_tree_cursor_new(definitions);
    uint32_t end = ts_node_end_byte(definitions);
    for (;;) {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        CBMSQLiteScan clause;
        if (ts_node_is_error(node) && masked[ts_node_start_byte(node)] != ' ' &&
            (cbm_sqlite_fk_deferral(node, end, source, &clause) ||
             cbm_sqlite_fk_constraint_name(node, end, source, &clause) ||
             cbm_sqlite_conflict_clause(node, end, source, &clause))) {
            if (!changed) {
                uint32_t start = ts_node_start_byte(ts_node_parent(definitions));
                CBMSQLiteScan scan = {.source = source, .len = (uint32_t)source_len, .at = start};
                cbm_sqlite_next(&scan);
                bool create = cbm_sqlite_take(&scan, "CREATE");
                (void)(cbm_sqlite_take(&scan, "TEMP") || cbm_sqlite_take(&scan, "TEMPORARY"));
                if (!create || !cbm_sqlite_take(&scan, "TABLE"))
                    break;
                scan.at = end;
                cbm_sqlite_next(&scan);
                while (scan.token.kind && scan.token.kind != ';' && scan.token.kind != '\x01')
                    cbm_sqlite_next(&scan);
                if (scan.token.kind == '\x01' ||
                    cbm_sqlite_prepare_table(db, "", source + start, scan.token.end - start,
                                             "", NULL) != SQLITE_OK)
                    break;
            }
            for (cbm_sqlite_next(&clause); clause.token.kind; cbm_sqlite_next(&clause))
                cbm_sqlite_mask(masked, clause.token.start, clause.token.end);
            changed = true;
        }
        if (ts_node_has_error(node) && ts_tree_cursor_goto_first_child(&cursor))
            continue;
        while (!ts_tree_cursor_goto_next_sibling(&cursor)) {
            if (!ts_tree_cursor_goto_parent(&cursor))
                goto done;
        }
    }
done:
    ts_tree_cursor_delete(&cursor);
    return changed;
}

static bool cbm_sqlite_columns_compat(TSNode definitions, const char *source,
                                      int source_len, sqlite3 **db, char *masked) {
    uint32_t start = ts_node_start_byte(definitions), end = ts_node_end_byte(definitions);
    if (start >= end || end > (uint32_t)source_len)
        return false;
    CBMSQLiteScan s = {.source = source, .len = end, .at = start, .line = 1};
    cbm_sqlite_next(&s);
    if (s.token.kind != '(')
        return false;
    uint32_t column_start = s.token.end;
    CBMSQLiteScan columns = s;
    int parens = 1;
    while (parens && s.token.kind && s.token.kind != '\x01') {
        cbm_sqlite_next(&s);
        if (s.token.kind == '(')
            parens++;
        else if (s.token.kind == ')')
            parens--;
    }
    /* Preparing the whole original list resolves sibling CHECK references
     * and prevents valid columns from hiding invalid sibling declarations. */
    if (parens ||
        cbm_sqlite_prepare_default(db, source + column_start, s.token.start - column_start,
                                   true, NULL) != SQLITE_OK)
        return false;
    s = columns;
    cbm_sqlite_next(&s);
    bool changed = cbm_sqlite_constraints_compat(definitions, source, source_len, db, masked);
    parens = 1;
    while (s.token.kind && s.token.kind != '\x01') {
        if (s.token.kind == '(')
            parens++;
        else if (s.token.kind == ')')
            parens--;
        if ((s.token.kind == ',' && parens == 1) || parens == 0) {
            changed |= cbm_sqlite_column_compat(source, column_start, s.token.start, masked);
            if (parens == 0)
                return changed;
            column_start = s.token.end;
        }
        cbm_sqlite_next(&s);
    }
    return changed;
}

/* shortcut: the diagnostic probe needs a contiguous name without escaped delimiters. */
static bool cbm_sqlite_name_span(TSNode node, const char *source, CBMSQLiteToken *name) {
    if (ts_node_is_null(node))
        return false;
    CBMSQLiteScan s = {.source = source, .len = ts_node_end_byte(node),
                       .at = ts_node_start_byte(node)};
    cbm_sqlite_next(&s);
    if (!cbm_sqlite_identifier(&s, name) || s.token.kind)
        return false;
    if (name->kind == 'q') {
        char quote = source[name->start] == '[' ? ']' : source[name->start];
        name->start++;
        name->end--;
        if (memchr(source + name->start, quote, name->end - name->start))
            return false;
    }
    return name->end > name->start;
}

static bool cbm_sqlite_name_matches(TSNode name, const char *source, const char *text, uint32_t len) {
    if (ts_node_is_null(name))
        return false;
    uint32_t start = ts_node_start_byte(name), end = ts_node_end_byte(name);
    if (end - start >= 2 && strchr("\"`['", source[start])) {
        start++;
        end--;
    }
    return end - start == len && sqlite3_strnicmp(source + start, text, (int)len) == 0;
}

static bool cbm_sqlite_append_column_name(sqlite3_str *columns, const char *source, TSNode column) {
    CBMSQLiteToken name;
    if (!cbm_sqlite_name_span(ts_node_child_by_field_name(column, "name", 4), source, &name))
        return false;
    sqlite3_str_appendf(columns, "\"%.*w\",", (int)(name.end - name.start), source + name.start);
    return sqlite3_str_errcode(columns) == SQLITE_OK;
}

static TSNode cbm_sqlite_added_column(TSNode add) {
    if (ts_node_is_null(add))
        return (TSNode){0};
    uint32_t count = ts_node_named_child_count(add);
    if (count != 2 && (count != 3 ||
                      strcmp(ts_node_type(ts_node_named_child(add, 1)), "keyword_column") != 0))
        return (TSNode){0};
    TSNode column = ts_node_named_child(add, count - 1);
    if (strcmp(ts_node_type(column), "column_definition") != 0)
        return (TSNode){0};
    return column;
}

/* shortcut: the preceding same-file DDL can prove a plain table and simple
 * added columns; schema changes, table renames and ambiguous owners need replay. */
static bool cbm_sqlite_prior_columns(sqlite3_str *columns, const char *source, TSNode target,
                                     sqlite3 **db, int source_len, bool *strict) {
    TSNode object = cbm_find_child_by_kind(target, "object_reference");
    if (ts_node_is_null(object))
        return false;
    TSNode schema = ts_node_child_by_field_name(object, "schema", 6);
    bool explicit_main = cbm_sqlite_name_matches(schema, source, "main", 4);
    CBMSQLiteToken table;
    if ((!ts_node_is_null(schema) && !explicit_main) ||
        ts_node_named_child_count(object) != (explicit_main ? 2u : 1u) ||
        !cbm_sqlite_name_span(ts_node_child_by_field_name(object, "name", 4), source, &table))
        return false;
    TSNode current = ts_node_parent(target);
    TSNode root = ts_node_parent(current);
    if (ts_node_is_null(current) || ts_node_is_null(root) ||
        strcmp(ts_node_type(current), "statement") != 0 || strcmp(ts_node_type(root), "program") != 0)
        return false;
    bool found = false, temp_shadow = false;
    for (TSNode stmt = ts_node_named_child(root, 0); !ts_node_is_null(stmt) && !ts_node_eq(stmt, current);
         stmt = ts_node_next_named_sibling(stmt)) {
        if (ts_node_has_error(stmt))
            return false;
        if (ts_node_is_extra(stmt))
            continue;
        if (strcmp(ts_node_type(stmt), "statement") != 0)
            return false;
        CBMSQLiteScan s = {.source = source, .len = ts_node_end_byte(stmt),
                           .at = ts_node_start_byte(stmt)};
        cbm_sqlite_next(&s);
        if (cbm_sqlite_is(&s, "ATTACH") || cbm_sqlite_is(&s, "DETACH") ||
            cbm_sqlite_is(&s, "ROLLBACK") || cbm_sqlite_is(&s, "RENAME"))
            return false;
        if (cbm_sqlite_take(&s, "PRAGMA")) {
            if (s.token.kind != 'w' || cbm_sqlite_is(&s, "WRITABLE_SCHEMA"))
                return false;
            cbm_sqlite_next(&s);
            if (s.token.kind == '.')
                return false;
            continue;
        }
        TSNode ddl = ts_node_named_child(stmt, 0);
        if (ts_node_is_null(ddl))
            return false;
        const char *kind = ts_node_type(ddl);
        bool create = strcmp(kind, "create_table") == 0;
        bool alter = strcmp(kind, "alter_table") == 0;
        if (!create && !alter && strcmp(kind, "create_view") != 0 &&
            strcmp(kind, "drop_table") != 0 && strcmp(kind, "drop_view") != 0) {
            if (cbm_sqlite_is(&s, "ALTER") ||
                (cbm_sqlite_is(&s, "CREATE") && strcmp(kind, "create_trigger") != 0 &&
                 strcmp(kind, "create_index") != 0) ||
                (cbm_sqlite_is(&s, "DROP") && strcmp(kind, "drop_trigger") != 0 &&
                 strcmp(kind, "drop_index") != 0))
                return false;
            continue;
        }
        if (alter && !ts_node_is_null(cbm_find_child_by_kind(ddl, "rename_object")))
            return false;
        object = cbm_find_child_by_kind(ddl, "object_reference");
        if (ts_node_is_null(object))
            return false;
        if (!cbm_sqlite_name_matches(ts_node_child_by_field_name(object, "name", 4), source,
                                     source + table.start, table.end - table.start))
            continue;
        schema = ts_node_child_by_field_name(object, "schema", 6);
        bool qualified = !ts_node_is_null(schema);
        bool temp = !ts_node_is_null(cbm_find_child_by_kind(ddl, "keyword_temp")) ||
                    !ts_node_is_null(cbm_find_child_by_kind(ddl, "keyword_temporary"));
        bool temp_schema = cbm_sqlite_name_matches(schema, source, "temp", 4);
        if (ts_node_named_child_count(object) != (qualified ? 2u : 1u) ||
            (temp && qualified && !temp_schema))
            return false;
        if (explicit_main && (temp || temp_schema)) {
            temp_shadow = true;
            continue;
        }
        if (ts_node_named_child_count(ddl) != 4 ||
            (qualified && !cbm_sqlite_name_matches(schema, source, "main", 4)) ||
            (!qualified && !create && temp_shadow))
            return false;
        if (create && !found) {
            TSNode definitions = cbm_find_child_by_kind(ddl, "column_definitions");
            if (ts_node_is_null(definitions))
                return false;
            uint32_t start = ts_node_start_byte(definitions), end = ts_node_end_byte(definitions);
            if (end - start <= 2 || source[start] != '(' || source[end - 1] != ')' ||
                cbm_sqlite_prepare_default(db, source + start + 1, end - start - 2,
                                           true, NULL) != SQLITE_OK)
                return false;
            for (TSNode col = ts_node_named_child(definitions, 0); !ts_node_is_null(col);
                 col = ts_node_next_named_sibling(col)) {
                if (strcmp(ts_node_type(col), "column_definition") == 0 &&
                    !cbm_sqlite_append_column_name(columns, source, col))
                    return false;
            }
            found = sqlite3_str_length(columns) > 0;
            if (found && strict)
                *strict = cbm_sqlite_strict_compat(ddl, definitions, source, source_len, db, NULL);
        } else if (alter && found) {
            TSNode col = cbm_sqlite_added_column(cbm_find_child_by_kind(ddl, "add_column"));
            if (ts_node_is_null(col))
                return false;
            uint32_t n = ts_node_named_child_count(col);
            if (n != 1 && n != 2 && (n != 4 ||
                           strcmp(ts_node_type(ts_node_named_child(col, 2)), "keyword_default") != 0 ||
                           strcmp(ts_node_type(ts_node_named_child(col, 3)), "literal") != 0))
                return false;
            uint32_t start = ts_node_start_byte(col), end = ts_node_end_byte(col);
            if (cbm_sqlite_prepare_default(db, source + start, end - start, true, NULL) != SQLITE_OK ||
                !cbm_sqlite_append_column_name(columns, source, col))
                return false;
        } else {
            return false;
        }
    }
    return found;
}

static bool cbm_sqlite_check_added_column(TSNode alter, const char *source, uint32_t start,
                                          uint32_t end, sqlite3 **db) {
    int status = cbm_sqlite_prepare_default(db, source + start, end - start, true, NULL);
    if (status != SQLITE_ERROR)
        return status == SQLITE_OK;
    sqlite3_str *columns = sqlite3_str_new(*db);
    bool prior = cbm_sqlite_prior_columns(columns, source, alter, db, 0, NULL);
    if (prior)
        sqlite3_str_append(columns, source + start, (int)(end - start));
    int len = sqlite3_str_length(columns);
    char *list = sqlite3_str_finish(columns);
    bool ok = prior && list && cbm_sqlite_prepare_default(db, list, (uint32_t)len, true, NULL) == SQLITE_OK;
    sqlite3_free(list);
    return ok;
}

static bool cbm_sqlite_add_column_compat(TSNode add, const char *source, int source_len,
                                         sqlite3 **db, char *masked) {
    TSNode alter = ts_node_parent(add);
    if (ts_node_is_null(alter) || strcmp(ts_node_type(alter), "alter_table") != 0 ||
        ts_node_named_child_count(alter) != 4)
        return false;
    TSNode column = cbm_sqlite_added_column(add);
    if (ts_node_is_null(column) || ts_node_named_child_count(column) < 4 ||
        strcmp(ts_node_type(ts_node_named_child(column, 2)), "keyword_default") != 0)
        return false;
    TSNode expr = ts_node_named_child(column, 3);
    uint32_t children = ts_node_named_child_count(column);
    bool split = children == 5 && ts_node_is_error(expr) &&
                 strcmp(ts_node_type(ts_node_named_child(column, 4)), "list") == 0;
    uint32_t start = ts_node_start_byte(column), end = ts_node_end_byte(column);
    if (start >= end || end > (uint32_t)source_len ||
        !(split || (children == 4 && strcmp(ts_node_type(expr), "invocation") == 0 &&
                    ts_node_has_error(expr))))
        return false;
    CBMSQLiteScan s = {.source = source, .len = end, .at = ts_node_start_byte(expr)};
    CBMSQLiteToken value;
    cbm_sqlite_next(&s);
    if (s.token.kind != 'w' || !cbm_sqlite_identifier(&s, &value) ||
        !cbm_sqlite_take(&s, "CHECK") || s.token.kind != '(' ||
        !cbm_sqlite_check_added_column(alter, source, start, end, db))
        return false;
    memset(masked + value.start, '0', value.end - value.start);
    return true;
}

static bool cbm_sqlite_column_compat_source(TSNode root, const char *source,
                                            int source_len, char *masked) {
    sqlite3 *db = NULL;
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    bool changed = false;
    for (;;) {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        const char *kind = ts_node_type(node);
        if (ts_node_has_error(node) && strcmp(kind, "column_definitions") == 0) {
            TSNode table = ts_node_parent(node);
            if (!ts_node_is_null(table) && strcmp(ts_node_type(table), "create_table") == 0)
                changed |= cbm_sqlite_columns_compat(node, source, source_len, &db, masked);
        } else if (ts_node_has_error(node) && strcmp(kind, "add_column") == 0) {
            changed |= cbm_sqlite_add_column_compat(node, source, source_len, &db, masked);
        }
        if (ts_node_has_error(node) && ts_tree_cursor_goto_first_child(&cursor))
            continue;
        while (!ts_tree_cursor_goto_next_sibling(&cursor)) {
            if (!ts_tree_cursor_goto_parent(&cursor)) {
                ts_tree_cursor_delete(&cursor);
                sqlite3_close(db);
                return changed;
            }
        }
    }
}

static bool cbm_sqlite_default_syntax_error(sqlite3 **db, TSNode expr, const char *source,
                                            int source_len) {
    uint32_t start = ts_node_start_byte(expr), end = ts_node_end_byte(expr);
    if (ts_node_has_error(expr) || start >= end || end > (uint32_t)source_len)
        return false;
    int offset;
    int rc = cbm_sqlite_prepare_default(db, source + start, end - start, false, &offset);
    return rc == SQLITE_ERROR && offset >= 0;
}

static bool cbm_sqlite_has_generated_column(TSNode definitions) {
    uint32_t columns = ts_node_named_child_count(definitions);
    for (uint32_t i = 0; i < columns; i++) {
        TSNode column = ts_node_named_child(definitions, i);
        if (strcmp(ts_node_type(column), "column_definition") != 0)
            continue;
        uint32_t children = ts_node_named_child_count(column);
        for (uint32_t j = 0; j < children; j++) {
            if (strcmp(ts_node_type(ts_node_named_child(column, j)), "keyword_as") == 0)
                return true;
        }
    }
    return false;
}

static bool cbm_sqlite_typeless_add_error(TSNode add, const char *source, int source_len,
                                        bool dialect, sqlite3 **db) {
    TSNode alter = ts_node_parent(add);
    if (ts_node_is_null(alter) || ts_node_has_error(add) || strcmp(ts_node_type(alter), "alter_table") != 0 ||
        ts_node_named_child_count(alter) != 4 ||
        strcmp(ts_node_type(ts_node_named_child(add, 0)), "keyword_add") != 0)
        return false;
    TSNode column = cbm_sqlite_added_column(add);
    if (ts_node_is_null(column) || !ts_node_is_null(ts_node_child_by_field_name(column, "type", 4)) ||
        !ts_node_is_null(ts_node_child_by_field_name(column, "custom_type", 11)) ||
        !ts_node_is_null(cbm_find_child_by_kind(column, "keyword_as")))
        return false;
    if (dialect && (!ts_node_is_null(cbm_find_child_by_kind(column, "keyword_primary")) ||
                    !ts_node_is_null(cbm_find_child_by_kind(column, "keyword_unique"))))
        return true;
    bool strict = false;
    sqlite3_str *columns = sqlite3_str_new(*db);
    bool prior = cbm_sqlite_prior_columns(columns, source, alter, db, source_len, &strict);
    sqlite3_free(sqlite3_str_finish(columns));
    return prior && strict;
}

static bool cbm_sqlite_column_list_error(sqlite3 **db, TSNode definitions,
                                          const char *source, int source_len) {
    uint32_t start = ts_node_start_byte(definitions), end = ts_node_end_byte(definitions);
    if (start + 1 >= end || end > (uint32_t)source_len || source[start] != '(' ||
        source[end - 1] != ')' ||
        (!cbm_sqlite_has_autoincrement(source + start, end - start) &&
         !cbm_sqlite_has_generated_column(definitions)))
        return false;
    uint32_t list_start = start + 1, len = end - start - 2;
    char *masked = NULL;
    uint32_t columns = ts_node_named_child_count(definitions);
    for (uint32_t i = 0; i < columns; i++) {
        TSNode column = ts_node_named_child(definitions, i);
        if (strcmp(ts_node_type(column), "column_definition") != 0)
            continue;
        uint32_t children = ts_node_named_child_count(column);
        for (uint32_t j = 0; j + 1 < children; j++) {
            if (strcmp(ts_node_type(ts_node_named_child(column, j)), "keyword_default") != 0)
                continue;
            TSNode expr = ts_node_named_child(column, j + 1);
            uint32_t expr_start = ts_node_start_byte(expr), expr_end = ts_node_end_byte(expr);
            if (expr_start < list_start || expr_end > end - 1 ||
                !cbm_sqlite_default_syntax_error(db, expr, source, source_len))
                continue;
            if (!masked) {
                masked = malloc(len);
                if (!masked)
                    return false;
                memcpy(masked, source + list_start, len);
            }
            /* Diagnose this DEFAULT separately; still validate every sibling. */
            cbm_sqlite_mask(masked, expr_start - list_start, expr_end - list_start);
            masked[expr_start - list_start] = '0';
        }
    }
    int rc = cbm_sqlite_prepare_default(db, masked ? masked : source + list_start,
                                       len, true, NULL);
    free(masked);
    if (rc != SQLITE_ERROR)
        return false;
    /* The isolated database cannot resolve application extensions. */
    const char *error = sqlite3_errmsg(*db);
    return strncmp(error, "no such function:", sizeof("no such function:") - 1) != 0 &&
           strncmp(error, "no such collation sequence:",
                   sizeof("no such collation sequence:") - 1) != 0;
}

static void cbm_sqlite_diagnostics(TSNode root, const char *source, int source_len,
                                    void (*report)(TSNode, void *), void *arg) {
    if (!source || source_len <= 0 || ts_node_is_null(root) || !report)
        return;
    bool dialect = cbm_sqlite_dialect_evidence(source, source_len);
    sqlite3 *db = NULL;
    TSTreeCursor cursor = ts_tree_cursor_new(root);
    for (;;) {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        const char *kind = ts_node_type(node);
        if (strcmp(kind, "add_column") == 0 &&
            cbm_sqlite_typeless_add_error(node, source, source_len, dialect, &db))
            report(node, arg);
        if (dialect && strcmp(kind, "create_trigger") == 0) {
            bool sqlite_body = false;
            uint32_t children = ts_node_named_child_count(node);
            for (uint32_t i = 0; i < children; i++) {
                TSNode child = ts_node_named_child(node, i);
                if (strcmp(ts_node_type(child), "block") == 0 &&
                    ts_node_named_child_count(child) > 0 &&
                    strcmp(ts_node_type(ts_node_named_child(child, 0)), "keyword_begin") == 0)
                    sqlite_body = true;
            }
            CBMSQLiteScan s = {.source = source, .len = (uint32_t)source_len,
                               .at = ts_node_start_byte(node), .line = 1};
            cbm_sqlite_next(&s);
            CBMSQLiteScan prefix = s;
            if (sqlite_body && cbm_sqlite_take(&prefix, "CREATE")) {
                (void)(cbm_sqlite_take(&prefix, "TEMP") ||
                       cbm_sqlite_take(&prefix, "TEMPORARY"));
                CBMSQLiteTrigger trigger = {0};
                if (cbm_sqlite_is(&prefix, "TRIGGER") &&
                    !cbm_sqlite_trigger_name(&s, &trigger))
                    report(node, arg);
            }
        }
        /* The grammar accepts some invalid AUTOINCREMENT and generated clauses. */
        if (dialect && strcmp(kind, "column_definitions") == 0) {
            TSNode table = ts_node_parent(node);
            if (!ts_node_is_null(table) && strcmp(ts_node_type(table), "create_table") == 0 &&
                cbm_sqlite_column_list_error(&db, node, source, source_len))
                report(node, arg);
        }
        if (dialect && strcmp(kind, "column_definition") == 0) {
            TSNode definitions = ts_node_parent(node);
            TSNode table = ts_node_parent(definitions);
            if (ts_node_is_null(table) || strcmp(ts_node_type(table), "create_table") != 0)
                goto sqlite_default_next;
            uint32_t children = ts_node_named_child_count(node);
            for (uint32_t i = 0; i + 1 < children; i++) {
                if (strcmp(ts_node_type(ts_node_named_child(node, i)), "keyword_default") != 0)
                    continue;
                TSNode expr = ts_node_named_child(node, i + 1);
                if (cbm_sqlite_default_syntax_error(&db, expr, source, source_len))
                    report(expr, arg);
            }
        }
sqlite_default_next:
        if (ts_tree_cursor_goto_first_child(&cursor))
            continue;
        while (!ts_tree_cursor_goto_next_sibling(&cursor)) {
            if (!ts_tree_cursor_goto_parent(&cursor)) {
                ts_tree_cursor_delete(&cursor);
                sqlite3_close(db);
                return;
            }
        }
    }
}

static void cbm_sqlite_table_usage(CBMExtractCtx *ctx, const char *qn,
                                    uint32_t start, uint32_t end) {
    for (int i = 0; i < ctx->result->usages.count; i++) {
        CBMUsage *usage = &ctx->result->usages.items[i];
        if (usage->site_start_byte == start && usage->site_end_byte == end)
            return;
    }
    CBMUsage usage = {
        .ref_name = cbm_arena_strndup(ctx->arena, ctx->source + start, end - start),
        .enclosing_func_qn = qn,
        .site_start_byte = start,
        .site_end_byte = end,
    };
    cbm_usages_push(&ctx->result->usages, ctx->arena, usage);
}

static bool cbm_sqlite_trigger_table_visible(CBMExtractCtx *ctx, TSNode object, TSNode name) {
    TSNode schema = ts_node_child_by_field_name(object, "schema", 6);
    if (!ts_node_is_null(schema))
        return cbm_sqlite_name_matches(schema, ctx->source, "main", 4);
    TSNode parent = ts_node_parent(object);
    return strcmp(ts_node_type(parent), "relation") != 0 ||
           !cbm_sql_relation_is_cte(ctx, parent, name, ctx->root);
}

static void cbm_sqlite_body_tables(CBMExtractCtx *ctx, TSNode node,
                                    const CBMSQLiteTrigger *trigger, const char *qn) {
    if (ts_node_end_byte(node) <= trigger->start ||
        ts_node_start_byte(node) >= trigger->end)
        return;
    if (strcmp(ts_node_type(node), "object_reference") == 0) {
        const char *parent = ts_node_type(ts_node_parent(node));
        if (strcmp(parent, "relation") == 0 || strcmp(parent, "insert") == 0 ||
            strcmp(parent, "from") == 0) {
            TSNode name = ts_node_child_by_field_name(node, "name", 4);
            if (!ts_node_is_null(name) && cbm_sqlite_trigger_table_visible(ctx, node, name))
                cbm_sqlite_table_usage(ctx, qn, ts_node_start_byte(name), ts_node_end_byte(name));
        }
        return;
    }
    uint32_t children = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < children; i++)
        cbm_sqlite_body_tables(ctx, ts_node_named_child(node, i), trigger, qn);
}

static bool cbm_sqlite_in_trigger(uint32_t start, uint32_t end, const CBMSQLiteTrigger *t) {
    return end > start && start >= t->start && end <= t->end;
}

static unsigned cbm_sqlite_row_image(const char *source, uint32_t start, uint32_t end) {
    if (end - start == 5) {
        char open = source[start], close = source[end - 1];
        if (((open == '"' || open == '`' || open == '\'') && close == open) ||
            (open == '[' && close == ']')) {
            start++;
            end--;
        }
    }
    CBMSQLiteScan scan = {.source = source, .token = {start, end, 0, 'w'}};
    if (cbm_sqlite_is(&scan, "NEW"))
        return CBM_SQLITE_ROW_NEW;
    return cbm_sqlite_is(&scan, "OLD") ? CBM_SQLITE_ROW_OLD : 0;
}

static unsigned cbm_sqlite_node_row_image(const char *source, TSNode node) {
    return ts_node_is_null(node) ? 0 :
           cbm_sqlite_row_image(source, ts_node_start_byte(node), ts_node_end_byte(node));
}

/* Preserve offsets for SQLite row names the grammar cannot parse.
 * The lexer keeps comments and literal contents out of this pass. */
static void cbm_sqlite_project_row_names(const char *source, uint32_t start, uint32_t begin,
                                         uint32_t end, char *masked) {
    CBMSQLiteScan scan = {.source = source, .len = end, .at = start};
    CBMSQLiteToken previous = {0}, before_previous = {0}, third_previous = {0};
    bool body_started = false, select_statement = false;
    cbm_sqlite_next(&scan);
    while (scan.token.kind && scan.token.kind != '\x01') {
        CBMSQLiteToken token = scan.token;
        if (token.start >= begin && (!body_started || previous.kind == ';')) {
            body_started = true;
            select_statement = cbm_sqlite_is(&scan, "SELECT");
        }
        cbm_sqlite_next(&scan);
        if ((token.kind == 'q' || token.kind == 's') &&
            (source[token.start] == '[' || source[token.start] == '\'') &&
            cbm_sqlite_row_image(source, token.start, token.end)) {
            bool project = false;
            if (previous.kind != '.' && (previous.kind != 'w' || previous.end < token.start) &&
                scan.token.kind == '.') {
                CBMSQLiteScan after_dot = scan;
                CBMSQLiteToken column;
                cbm_sqlite_next(&after_dot);
                project = cbm_sqlite_identifier(&after_dot, &column);
            } else if (select_statement && scan.token.kind != '.') {
                /* shortcut: simple FROM/JOIN table aliases only, until the
                 * SQL grammar represents quoted aliases on other relations. */
                CBMSQLiteScan prefix = {.source = source, .token = previous};
                bool explicit_alias = cbm_sqlite_is(&prefix, "AS");
                CBMSQLiteToken table = explicit_alias ? before_previous : previous;
                prefix.token = explicit_alias ? third_previous : before_previous;
                project = (table.kind == 'w' || table.kind == 'q') &&
                          (cbm_sqlite_is(&prefix, "FROM") || cbm_sqlite_is(&prefix, "JOIN"));
            }
            if (project) {
                masked[token.start] = '"';
                masked[token.end - 1] = '"';
            }
        }
        third_previous = before_previous;
        before_previous = previous;
        previous = token;
    }
}

/* shortcut: combine compound SELECT arms until the grammar exposes each
 * arm's FROM clause as part of its own query node. */
static unsigned cbm_sqlite_shadowed_images(const char *source, TSNode node) {
    TSNode alias = ts_node_child_by_field_name(node, "alias", 5);
    unsigned images = cbm_sqlite_node_row_image(source, alias);
    if (strcmp(ts_node_type(node), "object_reference") == 0 &&
        strcmp(ts_node_type(ts_node_parent(node)), "field") != 0) {
        TSNode name = ts_node_child_by_field_name(node, "name", 4);
        images |= cbm_sqlite_node_row_image(source, name);
    }
    uint32_t n = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < n; i++) {
        TSNode child = ts_node_named_child(node, i);
        if (strcmp(ts_node_type(child), "subquery") != 0)
            images |= cbm_sqlite_shadowed_images(source, child);
    }
    return images;
}

static void cbm_sqlite_row_columns(CBMExtractCtx *ctx, TSNode node, unsigned row_images,
                                   unsigned visible, const char *table, const char *owner) {
    const char *kind = ts_node_type(node);
    /* SQLite checks the trigger row before looking in an enclosing query. */
    if (strcmp(kind, "subquery") == 0)
        visible = row_images & ~cbm_sqlite_shadowed_images(ctx->source, node);
    if (visible && strcmp(kind, "field") == 0) {
        TSNode qualifier = cbm_find_child_by_kind(node, "object_reference");
        if (!ts_node_is_null(qualifier) && ts_node_named_child_count(qualifier) == 1) {
            TSNode prefix = ts_node_child_by_field_name(qualifier, "name", 4);
            TSNode column = ts_node_child_by_field_name(node, "name", 4);
            if (!ts_node_is_null(column) && (visible & cbm_sqlite_node_row_image(ctx->source, prefix))) {
                CBMUsage usage = {
                    .ref_name = table, .enclosing_func_qn = owner,
                    .site_start_byte = ts_node_start_byte(column),
                    .site_end_byte = ts_node_end_byte(column),
                    .kind = CBM_USAGE_SQL_TRIGGER_COLUMN, .source_origin = CBM_SOURCE_ORIGIN_RAW,
                };
                cbm_usages_push(&ctx->result->usages, ctx->arena, usage);
            }
        }
        return;
    }
    uint32_t n = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < n; i++)
        cbm_sqlite_row_columns(ctx, ts_node_named_child(node, i), row_images, visible, table, owner);
}

static void cbm_sqlite_statement_columns(CBMExtractCtx *ctx, TSNode node,
                                          const CBMSQLiteTrigger *t, const char *table,
                                          const char *owner) {
    unsigned visible = t->row_images & ~cbm_sqlite_shadowed_images(ctx->source, node);
    cbm_sqlite_row_columns(ctx, node, t->row_images, visible, table, owner);
}

static void cbm_sqlite_native_trigger_columns(CBMExtractCtx *ctx, TSNode node,
                                               const CBMSQLiteTrigger *t, const char *table,
                                               const char *owner) {
    TSNode block = cbm_find_child_by_kind(node, "block");
    if (ts_node_is_null(block) || ts_node_start_byte(block) != t->begin)
        return;
    if (t->condition != UINT32_MAX) {
        TSNode when = cbm_find_child_by_kind(node, "keyword_when");
        TSNode condition = ts_node_is_null(when) ? when : ts_node_next_named_sibling(when);
        if (ts_node_is_null(condition) || ts_node_start_byte(condition) != t->condition ||
            ts_node_end_byte(condition) > t->begin)
            return;
        cbm_sqlite_statement_columns(ctx, condition, t, table, owner);
    }
    uint32_t n = ts_node_named_child_count(block);
    for (uint32_t i = 0; i < n; i++) {
        TSNode statement = ts_node_named_child(block, i);
        if (strcmp(ts_node_type(statement), "statement") == 0 &&
            ts_node_end_byte(statement) <= t->closing)
            cbm_sqlite_statement_columns(ctx, statement, t, table, owner);
    }
}

static void cbm_sqlite_trigger_columns(CBMExtractCtx *ctx, const CBMSQLiteTrigger *t,
                                       const char *owner) {
    CBMSQLiteScan trigger_schema = {.source = ctx->source, .token = t->schema};
    CBMSQLiteScan table_schema = {.source = ctx->source, .token = t->table_schema};
    /* shortcut: the same-file table map only proves unqualified main declarations. */
    if (!owner || t->temporary || t->instead_of ||
        (t->schema.end && !cbm_sqlite_is(&trigger_schema, "MAIN")) ||
        (t->table_schema.end && !cbm_sqlite_is(&table_schema, "MAIN")))
        return;
    /* The projected statements are children of the file, even for WHEN. */
    TSNode first = ts_node_first_named_child_for_byte(ctx->root, t->start);
    TSNode statement = first;
    for (; !ts_node_is_null(statement) && ts_node_start_byte(statement) < t->closing;
         statement = ts_node_next_named_sibling(statement)) {
        if (ts_node_has_error(statement))
            return;
    }
    const char *table = cbm_arena_strndup(ctx->arena, ctx->source + t->table.start,
                                         t->table.end - t->table.start);
    if (!table)
        return;
    if (t->update_of_end) {
        CBMSQLiteScan scan = {.source = ctx->source, .at = t->update_of, .len = t->update_of_end};
        for (cbm_sqlite_next(&scan); scan.token.kind; cbm_sqlite_next(&scan)) {
            if (scan.token.kind == ',')
                continue;
            CBMUsage usage = {
                .ref_name = table, .enclosing_func_qn = owner,
                .site_start_byte = scan.token.start, .site_end_byte = scan.token.end,
                .kind = CBM_USAGE_SQL_TRIGGER_OF_COLUMN, .source_origin = CBM_SOURCE_ORIGIN_RAW,
            };
            cbm_usages_push(&ctx->result->usages, ctx->arena, usage);
        }
    }
    for (statement = first; !ts_node_is_null(statement) && ts_node_start_byte(statement) < t->closing;
         statement = ts_node_next_named_sibling(statement)) {
        if (strcmp(ts_node_type(statement), "statement") != 0 ||
            !cbm_sqlite_in_trigger(ts_node_start_byte(statement), ts_node_end_byte(statement), t))
            continue;
        TSNode native = cbm_find_child_by_kind(statement, "create_trigger");
        if (!ts_node_is_null(native)) {
            if (ts_node_start_byte(native) == t->start)
                cbm_sqlite_native_trigger_columns(ctx, native, t, table, owner);
        } else {
            cbm_sqlite_statement_columns(ctx, statement, t, table, owner);
        }
    }
}

static void cbm_sqlite_extract_trigger(CBMExtractCtx *ctx, const CBMSQLiteTrigger *t) {
    const char *name = cbm_arena_strndup(ctx->arena, ctx->source + t->name.start,
                                        t->name.end - t->name.start);
    const char *schema = t->schema.end > t->schema.start
                             ? cbm_arena_strndup(ctx->arena, ctx->source + t->schema.start,
                                                t->schema.end - t->schema.start)
                             : t->temporary ? "temp" : "main";
    const char *qn =
        cbm_arena_sprintf(ctx->arena, "%s.%s.%s", ctx->module_qn, schema, name);
    CBMDefinition def = {
        .name = name,
        .qualified_name = qn,
        .label = "Function",
        .file_path = ctx->rel_path,
        .start_line = t->start_line,
        .end_line = t->end_line,
        .lines = (int)(t->end_line - t->start_line + 1),
        .is_exported = true,
        .is_test = ctx->result->is_test_file,
    };
    cbm_defs_push(&ctx->result->defs, ctx->arena, def);
    for (int i = 0; i < ctx->result->calls.count; i++) {
        CBMCall *call = &ctx->result->calls.items[i];
        if (cbm_sqlite_in_trigger(call->site_start_byte, call->site_end_byte, t))
            call->enclosing_func_qn = qn;
    }
    CBMUsageArray *usages = &ctx->result->usages;
    int kept = 0;
    for (int i = 0; i < usages->count; i++) {
        CBMUsage usage = usages->items[i];
        if (cbm_sqlite_in_trigger(usage.site_start_byte, usage.site_end_byte, t)) {
            TSNode name = ts_node_named_descendant_for_byte_range(ctx->root, usage.site_start_byte,
                                                                 usage.site_end_byte);
            TSNode parent = ts_node_parent(name);
            if (!ts_node_is_null(parent) && strcmp(ts_node_type(parent), "cte") == 0 &&
                ts_node_eq(name, cbm_find_child_by_kind(parent, "identifier")))
                continue;
            if (!ts_node_is_null(parent) && strcmp(ts_node_type(parent), "object_reference") == 0 &&
                ts_node_eq(name, ts_node_child_by_field_name(parent, "name", 4)) &&
                !cbm_sqlite_trigger_table_visible(ctx, parent, name))
                continue;
            usage.enclosing_func_qn = qn;
        }
        usages->items[kept++] = usage;
    }
    usages->count = kept;
    for (int i = 0; i < ctx->result->resolved_calls.count; i++) {
        CBMResolvedCall *call = &ctx->result->resolved_calls.items[i];
        if (cbm_sqlite_in_trigger(call->site_start_byte, call->site_end_byte, t))
            call->caller_qn = qn;
    }
    cbm_sqlite_table_usage(ctx, qn, t->table.start, t->table.end);
    cbm_sqlite_body_tables(ctx, ctx->root, t, qn);
    cbm_sqlite_trigger_columns(ctx, t, qn);
}

static bool cbm_sqlite_walk_triggers(const char *source, int source_len, char *masked,
                                      CBMExtractCtx *ctx) {
    if (!source || source_len <= 0)
        return false;
    CBMSQLiteScan s = {.source = source, .len = (uint32_t)source_len, .line = 1};
    cbm_sqlite_next(&s);
    bool changed = false, statement_start = true;
    while (s.token.kind && s.token.kind != '\x01') {
        CBMSQLiteScan candidate = s;
        CBMSQLiteTrigger trigger;
        if (statement_start && cbm_sqlite_is(&s, "CREATE") &&
            cbm_sqlite_trigger(&candidate, &trigger)) {
            if (masked) {
                uint32_t header_end = trigger.condition == UINT32_MAX
                                          ? trigger.begin + 5
                                          : trigger.condition;
                cbm_sqlite_mask(masked, trigger.start, header_end);
                if (trigger.condition != UINT32_MAX) {
                    memcpy(masked + trigger.start, "SELECT", 6);
                    uint32_t opening = trigger.start + 6;
                    while (opening < trigger.condition &&
                           (masked[opening] == '\r' || masked[opening] == '\n'))
                        opening++;
                    masked[opening] = '(';
                    cbm_sqlite_mask(masked, trigger.begin, trigger.begin + 5);
                    memcpy(masked + trigger.begin, ");", 2);
                }
                cbm_sqlite_mask(masked, trigger.closing, trigger.end);
                uint32_t qualifier_start = trigger.condition == UINT32_MAX ? trigger.begin + 5
                                                                           : trigger.condition;
                cbm_sqlite_project_row_names(source, qualifier_start, trigger.begin + 5,
                                              trigger.closing, masked);
            }
            if (ctx)
                cbm_sqlite_extract_trigger(ctx, &trigger);
            changed = true;
            s = candidate;
            statement_start = true;
            continue;
        }
        statement_start = s.token.kind == ';';
        cbm_sqlite_next(&s);
    }
    return changed;
}

static bool cbm_sqlite_trigger_compat_source(const char *source, int source_len, char *masked) {
    return cbm_sqlite_walk_triggers(source, source_len, masked, NULL);
}

static void cbm_extract_sqlite_triggers(CBMExtractCtx *ctx) {
    if (ctx->language == CBM_LANG_SQL)
        (void)cbm_sqlite_walk_triggers(ctx->source, ctx->source_len, NULL, ctx);
}

#endif
