#include "lexer.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- keyword and synonym table ---------- */

typedef struct {
    const char *word;   /* always lowercase */
    TokenKind kind;
} Keyword;

static const Keyword KEYWORDS[] = {
    {"role",     TOK_ROLE},
    {"resource", TOK_RESOURCE},
    {"action",   TOK_ACTION},
    {"to",       TOK_TO},
    /* synonyms: all of these become one canonical token */
    {"allow",    TOK_ALLOW},
    {"permit",   TOK_ALLOW},
    {"grant",    TOK_ALLOW},
    {"deny",     TOK_DENY},
    {"forbid",   TOK_DENY},
    {"block",    TOK_DENY},
    /* security assertions */
    {"assert",   TOK_ASSERT},
    {"can",      TOK_CAN},
    {"cannot",   TOK_CANNOT},
    {"no",       TOK_NO},
    {"every",    TOK_EVERY},
};

#define NUM_KEYWORDS ((int)(sizeof(KEYWORDS) / sizeof(KEYWORDS[0])))

/* Keywords are case-insensitive, names are not. Returns TOK_IDENT if the
   word is not a keyword. */
static TokenKind lookup_keyword(const char *word) {
    char lower[MAX_TOKEN_TEXT];
    size_t i;

    for (i = 0; word[i] != '\0' && i < MAX_TOKEN_TEXT - 1; i++) {
        lower[i] = (char)tolower((unsigned char)word[i]);
    }
    lower[i] = '\0';

    for (int k = 0; k < NUM_KEYWORDS; k++) {
        if (strcmp(lower, KEYWORDS[k].word) == 0) {
            return KEYWORDS[k].kind;
        }
    }
    return TOK_IDENT;
}

/* ---------- low-level character helpers ---------- */

/* Look at the current char without consuming it. Returns 0 at the end. */
static int peek(const Lexer *lx) {
    return (unsigned char)lx->src[lx->pos];
}

/* Consume one char and keep line/col up to date. */
static int advance(Lexer *lx) {
    int c = (unsigned char)lx->src[lx->pos];
    if (c == '\0') {
        return 0;
    }
    lx->pos++;
    if (c == '\n') {
        lx->line++;
        lx->col = 1;
    } else {
        lx->col++;
    }
    return c;
}

/* Skip spaces, tabs, newlines and '#' comments. */
static void skip_whitespace_and_comments(Lexer *lx) {
    for (;;) {
        int c = peek(lx);
        if (c != 0 && isspace(c)) {
            advance(lx);
        } else if (c == '#') {
            while (peek(lx) != '\n' && peek(lx) != 0) {
                advance(lx);
            }
        } else {
            break;
        }
    }
}

static Token make_token(TokenKind kind, const char *text, int line, int col) {
    Token t;
    memset(&t, 0, sizeof(t));
    t.kind = kind;
    t.line = line;
    t.col = col;
    strncpy(t.text, text, MAX_TOKEN_TEXT - 1);
    return t;
}

/* ---------- public API ---------- */

void lexer_init(Lexer *lx, const char *src) {
    lx->src = src;
    lx->pos = 0;
    lx->line = 1;
    lx->col = 1;
}

Token lexer_next(Lexer *lx) {
    skip_whitespace_and_comments(lx);

    int line = lx->line;
    int col = lx->col;
    int c = peek(lx);

    if (c == 0) {
        return make_token(TOK_EOF, "<eof>", line, col);
    }

    /* identifier or keyword: [A-Za-z_][A-Za-z0-9_]* */
    if (isalpha(c) || c == '_') {
        char buf[MAX_TOKEN_TEXT];
        int len = 0;
        int too_long = 0;

        while (isalnum(peek(lx)) || peek(lx) == '_') {
            int ch = advance(lx);
            if (len < MAX_TOKEN_TEXT - 1) {
                buf[len++] = (char)ch;
            } else {
                too_long = 1;   /* keep consuming so we skip the whole word */
            }
        }
        buf[len] = '\0';

        if (too_long) {
            return make_token(TOK_ERROR, "name is too long (max 63 characters)",
                              line, col);
        }
        return make_token(lookup_keyword(buf), buf, line, col);
    }

    /* single-character symbols */
    advance(lx);
    switch (c) {
        case ';': return make_token(TOK_SEMI,  ";", line, col);
        case ':': return make_token(TOK_COLON, ":", line, col);
        case '*': return make_token(TOK_STAR,  "*", line, col);
        default: {
            char msg[MAX_TOKEN_TEXT];
            if (isprint(c)) {
                snprintf(msg, sizeof(msg), "unexpected character '%c'", c);
            } else {
                snprintf(msg, sizeof(msg), "unexpected byte 0x%02X", c);
            }
            return make_token(TOK_ERROR, msg, line, col);
        }
    }
}

Token *lexer_tokenize_all(const char *src, int *count) {
    Lexer lx;
    int capacity = 64;
    int n = 0;
    Token *tokens = malloc((size_t)capacity * sizeof(Token));
    if (tokens == NULL) {
        return NULL;
    }

    lexer_init(&lx, src);
    for (;;) {
        if (n == capacity) {
            capacity *= 2;
            Token *bigger = realloc(tokens, (size_t)capacity * sizeof(Token));
            if (bigger == NULL) {
                free(tokens);
                return NULL;
            }
            tokens = bigger;
        }
        tokens[n] = lexer_next(&lx);
        n++;
        if (tokens[n - 1].kind == TOK_EOF) {
            break;
        }
    }

    *count = n;
    return tokens;
}

const char *token_kind_name(TokenKind kind) {
    switch (kind) {
        case TOK_EOF:      return "EOF";
        case TOK_ROLE:     return "ROLE";
        case TOK_RESOURCE: return "RESOURCE";
        case TOK_ACTION:   return "ACTION";
        case TOK_TO:       return "TO";
        case TOK_ALLOW:    return "ALLOW";
        case TOK_DENY:     return "DENY";
        case TOK_ASSERT:   return "ASSERT";
        case TOK_CAN:      return "CAN";
        case TOK_CANNOT:   return "CANNOT";
        case TOK_NO:       return "NO";
        case TOK_EVERY:    return "EVERY";
        case TOK_IDENT:    return "IDENT";
        case TOK_SEMI:     return "SEMI";
        case TOK_COLON:    return "COLON";
        case TOK_STAR:     return "STAR";
        case TOK_ERROR:    return "ERROR";
    }
    return "?";
}
