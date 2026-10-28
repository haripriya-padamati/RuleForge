#ifndef LEXER_H
#define LEXER_H

#define MAX_TOKEN_TEXT 64

typedef enum {
    TOK_EOF,
    TOK_ROLE,
    TOK_RESOURCE,
    TOK_ACTION,
    TOK_TO,
    TOK_ALLOW,   /* allow / permit / grant */
    TOK_DENY,    /* deny / forbid / block  */
    TOK_ASSERT,  /* assert                 */
    TOK_CAN,     /* can                    */
    TOK_CANNOT,  /* cannot                 */
    TOK_NO,      /* no    (in "no role")   */
    TOK_EVERY,   /* every (in "every role")*/
    TOK_IDENT,
    TOK_SEMI,    /* ;  */
    TOK_COLON,   /* :  */
    TOK_STAR,    /* *  */
    TOK_ERROR    /* text holds the error message */
} TokenKind;

typedef struct {
    TokenKind kind;
    char text[MAX_TOKEN_TEXT];
    int line;
    int col;
} Token;

typedef struct {
    const char *src;  /* whole input text, NUL terminated */
    int pos;          /* index of next char to read       */
    int line;         /* current line, starts at 1        */
    int col;          /* current column, starts at 1      */
} Lexer;

/* Set up a lexer over a NUL-terminated string. */
void lexer_init(Lexer *lx, const char *src);

/* Return the next token. After the end, it keeps returning TOK_EOF. */
Token lexer_next(Lexer *lx);

/* Lex the whole input into a malloc'd array (last token is TOK_EOF).
   Sets *count. The caller must free() the array. Returns NULL on
   allocation failure. */
Token *lexer_tokenize_all(const char *src, int *count);

/* Printable name of a token kind, e.g. "ALLOW". */
const char *token_kind_name(TokenKind kind);

#endif
