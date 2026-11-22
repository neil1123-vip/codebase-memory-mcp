// Vendored tree-sitter grammar: html
// Each grammar compiled as separate unit (conflicting static symbols).
#include "vendored/grammars/html/parser.c"
#define tree_sitter_html_external_scanner_scan cbm_html_upstream_scan
#include "vendored/grammars/html/scanner.c"
#undef tree_sitter_html_external_scanner_scan

bool tree_sitter_html_external_scanner_scan(void *payload, TSLexer *lexer,
                                           const bool *valid_symbols) {
    Scanner *scanner = payload;
    if (valid_symbols[IMPLICIT_END_TAG] && scanner->tags.size > 0 &&
        array_back(&scanner->tags)->type == P) {
        while (iswspace(lexer->lookahead))
            skip(lexer);
        TagType parent = scanner->tags.size > 1
                             ? scanner->tags.contents[scanner->tags.size - 2].type : BODY;
        /* A paragraph may omit its end tag at EOF, except under these parents. */
        if (lexer->eof(lexer) && parent != A && parent != AUDIO && parent != DEL &&
            parent != INS && parent != MAP && parent != NOSCRIPT && parent != VIDEO &&
            parent != CUSTOM) {
            pop_tag(scanner);
            lexer->result_symbol = IMPLICIT_END_TAG;
            return true;
        }
    }
    return cbm_html_upstream_scan(payload, lexer, valid_symbols);
}
