#include "ast.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- small helpers ---------- */

static void out_of_memory(void) {
    fprintf(stderr, "fatal: out of memory\n");
    exit(1);
}

static void *xcalloc(size_t size) {
    void *p = calloc(1, size);
    if (p == NULL) {
        out_of_memory();
    }
    return p;
}

static void init_node(Node *n, NodeKind kind, int line, int col) {
    n->kind = kind;
    n->line = line;
    n->col = col;
}

static void copy_name(char *dst, const char *src) {
    strncpy(dst, src, AST_NAME_LEN - 1);
    dst[AST_NAME_LEN - 1] = '\0';
}

/* ---------- constructors ---------- */

Program *program_new(void) {
    Program *p = xcalloc(sizeof(Program));
    init_node(AS_NODE(p), NODE_PROGRAM, 1, 1);
    return p;
}

void program_add(Program *p, Node *item) {
    if (p->count == p->capacity) {
        int new_capacity = p->capacity ? p->capacity * 2 : 16;
        Node **bigger = realloc(p->items, (size_t)new_capacity * sizeof(Node *));
        if (bigger == NULL) {
            out_of_memory();
        }
        p->items = bigger;
        p->capacity = new_capacity;
    }
    p->items[p->count++] = item;
}

RoleDecl *role_decl_new(const char *name, const char *parent, int line, int col) {
    RoleDecl *r = xcalloc(sizeof(RoleDecl));
    init_node(AS_NODE(r), NODE_ROLE_DECL, line, col);
    copy_name(r->name, name);
    if (parent != NULL) {
        r->has_parent = 1;
        copy_name(r->parent, parent);
    }
    return r;
}

ResourceDecl *resource_decl_new(const char *name, int line, int col) {
    ResourceDecl *r = xcalloc(sizeof(ResourceDecl));
    init_node(AS_NODE(r), NODE_RESOURCE_DECL, line, col);
    copy_name(r->name, name);
    return r;
}

ActionDecl *action_decl_new(const char *name, int line, int col) {
    ActionDecl *a = xcalloc(sizeof(ActionDecl));
    init_node(AS_NODE(a), NODE_ACTION_DECL, line, col);
    copy_name(a->name, name);
    return a;
}

Rule *rule_new(NodeKind kind, int rule_id, const char *role,
               const char *action, ResourceKind res_kind,
               const char *res_text, int line, int col) {
    assert(kind == NODE_ALLOW_RULE || kind == NODE_DENY_RULE);
    Rule *r = xcalloc(sizeof(Rule));
    init_node(AS_NODE(r), kind, line, col);
    r->rule_id = rule_id;
    copy_name(r->role, role);
    copy_name(r->action, action);
    r->res_kind = res_kind;
    copy_name(r->res_text, res_text);
    return r;
}

Assertion *assertion_new(int assert_id, AssertSubject subject, const char *role,
                         int expect_allowed, const char *action,
                         ResourceKind res_kind, const char *res_text,
                         int line, int col) {
    Assertion *a = xcalloc(sizeof(Assertion));
    init_node(AS_NODE(a), NODE_ASSERTION, line, col);
    a->assert_id = assert_id;
    a->subject = subject;
    if (role != NULL) {
        copy_name(a->role, role);
    }
    a->expect_allowed = expect_allowed;
    copy_name(a->action, action);
    a->res_kind = res_kind;
    copy_name(a->res_text, res_text);
    return a;
}

void assertion_to_text(const Assertion *a, char *buf, size_t len) {
    char res[AST_NAME_LEN + 2];
    switch (a->res_kind) {
        case RES_ANY:    snprintf(res, sizeof(res), "*");               break;
        case RES_PREFIX: snprintf(res, sizeof(res), "%s*", a->res_text); break;
        default:         snprintf(res, sizeof(res), "%s", a->res_text);  break;
    }
    switch (a->subject) {
        case SUBJ_NO_ROLE:
            snprintf(buf, len, "no role can %s %s", a->action, res);
            break;
        case SUBJ_EVERY_ROLE:
            snprintf(buf, len, "every role %s %s %s",
                     a->expect_allowed ? "can" : "cannot", a->action, res);
            break;
        default:
            snprintf(buf, len, "%s %s %s %s", a->role,
                     a->expect_allowed ? "can" : "cannot", a->action, res);
            break;
    }
}

/* ---------- dump ---------- */

static void print_resource(const Rule *r) {
    switch (r->res_kind) {
        case RES_ANY:    printf("*");              break;
        case RES_PREFIX: printf("%s*", r->res_text); break;
        case RES_EXACT:  printf("%s", r->res_text);  break;
    }
}

void ast_dump(const Program *p) {
    printf("Program (%d items)\n", p->count);

    for (int i = 0; i < p->count; i++) {
        Node *n = p->items[i];

        if (ISA(RoleDecl, n)) {
            RoleDecl *r = CAST(RoleDecl, n);
            if (r->has_parent) {
                printf("  RoleDecl     %s : %s", r->name, r->parent);
            } else {
                printf("  RoleDecl     %s", r->name);
            }
        } else if (ISA(ResourceDecl, n)) {
            ResourceDecl *r = CAST(ResourceDecl, n);
            printf("  ResourceDecl %s", r->name);
        } else if (ISA(ActionDecl, n)) {
            ActionDecl *a = CAST(ActionDecl, n);
            printf("  ActionDecl   %s", a->name);
        } else if (ISA(Assertion, n)) {
            Assertion *a = CAST(Assertion, n);
            char text[3 * AST_NAME_LEN + 32];
            assertion_to_text(a, text, sizeof(text));
            printf("  Assertion    A%d: %s", a->assert_id, text);
        } else {
            /* Rule covers both AllowRule and DenyRule */
            Rule *rule = DYN_CAST(Rule, n);
            if (rule == NULL) {
                printf("  <unknown node kind %d>", (int)n->kind);
            } else {
                const char *label = ISA(AllowRule, n) ? "AllowRule" : "DenyRule ";
                printf("  %s    #%d: %s -> %s on ", label, rule->rule_id,
                       rule->role, rule->action);
                print_resource(rule);
            }
        }
        printf("   (line %d)\n", n->line);
    }
}

/* ---------- free ---------- */

void ast_free(Program *p) {
    if (p == NULL) {
        return;
    }
    for (int i = 0; i < p->count; i++) {
        free(p->items[i]);
    }
    free(p->items);
    free(p);
}
