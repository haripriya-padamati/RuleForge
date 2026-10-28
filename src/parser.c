#include "parser.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------
   Grammar (one parse function per rule below):

     program      -> decl* (rule | assertion)*
     decl         -> "role" IDENT (":" IDENT)? ";"
                   | "resource" IDENT ";"
                   | "action" IDENT ";"
     rule         -> EFFECT IDENT "to" IDENT resource_ref ";"
     assertion    -> "assert" subject ("can" | "cannot") IDENT resource_ref ";"
     subject      -> IDENT | "every" "role" | "no" "role"
     resource_ref -> "*" | IDENT | IDENT "*"
   ------------------------------------------------------------------ */

typedef struct {
    const Token *tokens;
    int count;
    int pos;
    char *err;
    size_t err_len;
    int failed;
    int next_rule_id;
    int next_assert_id;
} Parser;

/* ---------- token access ---------- */

static const Token *current(const Parser *ps) {
    if (ps->pos >= ps->count) {
        return &ps->tokens[ps->count - 1];   /* the EOF token */
    }
    return &ps->tokens[ps->pos];
}

/* Return the current token and move forward. Never moves past EOF. */
static const Token *advance(Parser *ps) {
    const Token *t = current(ps);
    if (t->kind != TOK_EOF) {
        ps->pos++;
    }
    return t;
}

static int check(const Parser *ps, TokenKind kind) {
    return current(ps)->kind == kind;
}

static int is_decl_start(const Parser *ps) {
    TokenKind k = current(ps)->kind;
    return k == TOK_ROLE || k == TOK_RESOURCE || k == TOK_ACTION;
}

static int is_rule_start(const Parser *ps) {
    TokenKind k = current(ps)->kind;
    return k == TOK_ALLOW || k == TOK_DENY;
}

static int is_assertion_start(const Parser *ps) {
    return current(ps)->kind == TOK_ASSERT;
}

/* ---------- error reporting ---------- */

/* Record the FIRST error only. Later ones are ignored. */
static void fail_at(Parser *ps, const Token *at, const char *fmt, ...) {
    if (ps->failed) {
        return;
    }
    ps->failed = 1;

    int used = snprintf(ps->err, ps->err_len, "%d:%d: syntax error: ",
                        at->line, at->col);
    if (used < 0 || (size_t)used >= ps->err_len) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    vsnprintf(ps->err + used, ps->err_len - (size_t)used, fmt, args);
    va_end(args);
}

/* Describe a token for an error message. */
static void describe(const Token *t, char *buf, size_t n) {
    switch (t->kind) {
        case TOK_EOF:   snprintf(buf, n, "end of file");           break;
        case TOK_IDENT: snprintf(buf, n, "name '%s'", t->text);    break;
        case TOK_ERROR: snprintf(buf, n, "invalid input (%s)", t->text); break;
        default:        snprintf(buf, n, "'%s'", t->text);         break;
    }
}

/* Require the current token to be `kind`. Returns it, or NULL after
   recording an error such as: expected ';' ..., but found 'Deny'. */
static const Token *expect(Parser *ps, TokenKind kind, const char *what) {
    if (check(ps, kind)) {
        return advance(ps);
    }
    char found[MAX_TOKEN_TEXT + 32];
    describe(current(ps), found, sizeof(found));
    fail_at(ps, current(ps), "expected %s, but found %s", what, found);
    return NULL;
}

/* ---------- grammar rules ---------- */

/* resource_ref -> "*" | IDENT | IDENT "*" */
static int parse_resource_ref(Parser *ps, ResourceKind *kind, char *text) {
    if (check(ps, TOK_STAR)) {
        advance(ps);
        *kind = RES_ANY;
        text[0] = '\0';
        return 1;
    }

    const Token *id = expect(ps, TOK_IDENT, "a resource name or '*'");
    if (id == NULL) {
        return 0;
    }
    strncpy(text, id->text, AST_NAME_LEN - 1);
    text[AST_NAME_LEN - 1] = '\0';

    if (check(ps, TOK_STAR)) {
        advance(ps);
        *kind = RES_PREFIX;
    } else {
        *kind = RES_EXACT;
    }
    return 1;
}

/* rule -> EFFECT IDENT "to" IDENT resource_ref ";" */
static Node *parse_rule(Parser *ps) {
    const Token *effect = advance(ps);   /* ALLOW or DENY, checked by caller */

    const Token *role = expect(ps, TOK_IDENT, "a role name");
    if (role == NULL) {
        return NULL;
    }
    if (expect(ps, TOK_TO, "'to'") == NULL) {
        return NULL;
    }
    const Token *action = expect(ps, TOK_IDENT, "an action name");
    if (action == NULL) {
        return NULL;
    }

    ResourceKind res_kind;
    char res_text[AST_NAME_LEN];
    if (!parse_resource_ref(ps, &res_kind, res_text)) {
        return NULL;
    }
    if (expect(ps, TOK_SEMI, "';' at the end of the rule") == NULL) {
        return NULL;
    }

    NodeKind kind = (effect->kind == TOK_ALLOW) ? NODE_ALLOW_RULE : NODE_DENY_RULE;
    Rule *rule = rule_new(kind, ps->next_rule_id++, role->text, action->text,
                          res_kind, res_text, effect->line, effect->col);
    return AS_NODE(rule);
}

/* assertion -> "assert" subject ("can" | "cannot") IDENT resource_ref ";"
   subject   -> IDENT | "every" "role" | "no" "role"                     */
static Node *parse_assertion(Parser *ps) {
    const Token *kw = advance(ps);   /* ASSERT, checked by caller */

    AssertSubject subject = SUBJ_ROLE;
    const char *role = NULL;
    if (check(ps, TOK_EVERY) || check(ps, TOK_NO)) {
        subject = check(ps, TOK_EVERY) ? SUBJ_EVERY_ROLE : SUBJ_NO_ROLE;
        advance(ps);
        if (expect(ps, TOK_ROLE, "'role'") == NULL) {
            return NULL;
        }
    } else {
        const Token *r = expect(ps, TOK_IDENT, "a role name, 'every role' or 'no role'");
        if (r == NULL) {
            return NULL;
        }
        role = r->text;
    }

    int expect_allowed;
    if (subject == SUBJ_NO_ROLE) {
        if (expect(ps, TOK_CAN, "'can' after 'no role'") == NULL) {
            return NULL;
        }
        expect_allowed = 0;            /* "no role can X" = every role is denied */
    } else if (check(ps, TOK_CAN)) {
        advance(ps);
        expect_allowed = 1;
    } else if (check(ps, TOK_CANNOT)) {
        advance(ps);
        expect_allowed = 0;
    } else {
        expect(ps, TOK_CAN, "'can' or 'cannot'");
        return NULL;
    }

    const Token *action = expect(ps, TOK_IDENT, "an action name");
    if (action == NULL) {
        return NULL;
    }
    ResourceKind res_kind;
    char res_text[AST_NAME_LEN];
    if (!parse_resource_ref(ps, &res_kind, res_text)) {
        return NULL;
    }
    if (expect(ps, TOK_SEMI, "';' at the end of the assertion") == NULL) {
        return NULL;
    }

    Assertion *a = assertion_new(ps->next_assert_id++, subject, role, expect_allowed,
                                 action->text, res_kind, res_text, kw->line, kw->col);
    return AS_NODE(a);
}

/* decl -> "role" IDENT (":" IDENT)? ";" | "resource" IDENT ";" | "action" IDENT ";" */
static Node *parse_decl(Parser *ps) {
    const Token *keyword = advance(ps);   /* ROLE, RESOURCE or ACTION */

    const Token *name = expect(ps, TOK_IDENT, "a name");
    if (name == NULL) {
        return NULL;
    }

    switch (keyword->kind) {
        case TOK_ROLE: {
            const char *parent = NULL;
            if (check(ps, TOK_COLON)) {
                advance(ps);
                const Token *p = expect(ps, TOK_IDENT, "a parent role name");
                if (p == NULL) {
                    return NULL;
                }
                parent = p->text;
            }
            if (expect(ps, TOK_SEMI, "';' after the role declaration") == NULL) {
                return NULL;
            }
            return AS_NODE(role_decl_new(name->text, parent,
                                         keyword->line, keyword->col));
        }
        case TOK_RESOURCE:
            if (expect(ps, TOK_SEMI, "';' after the resource declaration") == NULL) {
                return NULL;
            }
            return AS_NODE(resource_decl_new(name->text, keyword->line, keyword->col));

        case TOK_ACTION:
            if (expect(ps, TOK_SEMI, "';' after the action declaration") == NULL) {
                return NULL;
            }
            return AS_NODE(action_decl_new(name->text, keyword->line, keyword->col));

        default:
            return NULL;   /* unreachable: caller checked is_decl_start */
    }
}

/* program -> decl* rule* */
Program *parse_program(const Token *tokens, int count, char *err, size_t err_len) {
    Parser ps;
    ps.tokens = tokens;
    ps.count = count;
    ps.pos = 0;
    ps.err = err;
    ps.err_len = err_len;
    ps.failed = 0;
    ps.next_rule_id = 1;
    ps.next_assert_id = 1;
    if (err_len > 0) {
        err[0] = '\0';
    }

    Program *prog = program_new();

    while (is_decl_start(&ps)) {
        Node *decl = parse_decl(&ps);
        if (decl == NULL) {
            ast_free(prog);
            return NULL;
        }
        program_add(prog, decl);
    }

    while (is_rule_start(&ps) || is_assertion_start(&ps)) {
        Node *rule = is_assertion_start(&ps) ? parse_assertion(&ps) : parse_rule(&ps);
        if (rule == NULL) {
            ast_free(prog);
            return NULL;
        }
        program_add(prog, rule);
    }

    if (!check(&ps, TOK_EOF)) {
        if (is_decl_start(&ps)) {
            fail_at(&ps, current(&ps),
                    "declarations must come before rules (move this '%s' "
                    "declaration above the first rule)", current(&ps)->text);
        } else {
            char found[MAX_TOKEN_TEXT + 32];
            describe(current(&ps), found, sizeof(found));
            fail_at(&ps, current(&ps),
                    "expected a declaration, a rule or an assertion, but found %s", found);
        }
        ast_free(prog);
        return NULL;
    }

    return prog;
}
