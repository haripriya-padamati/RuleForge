#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>

#include "ast.h"
#include "lexer.h"

/* Parse a token array (must end with TOK_EOF) into an AST.
   On success: returns the Program. The caller frees it with ast_free().
   On failure: returns NULL and writes a message like
               "5:1: syntax error: expected ..." into err.
   The parser stops at the first error. */
Program *parse_program(const Token *tokens, int count, char *err, size_t err_len);

#endif
