#include "sema.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- small helpers ---------- */

static void *xcalloc(size_t count, size_t size) {
    void *p = calloc(count ? count : 1, size);
    if (p == NULL) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(1);
    }
    return p;
}

static void copy_name(char *dst, const char *src) {
    strncpy(dst, src, AST_NAME_LEN - 1);
    dst[AST_NAME_LEN - 1] = '\0';
}

/* Diagnostics share one format with the parser:  path:line:col: error: ... */
static void report(Sema *s, const char *path, const char *level,
                   int line, int col, const char *fmt, ...) {
    fprintf(stderr, "%s:%d:%d: %s: ", path, line, col, level);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");

    if (strcmp(level, "error") == 0) {
        s->num_errors++;
    } else {
        s->num_warnings++;
    }
}

/* ---------- "did you mean ...?" ---------- */

/* Edit distance between two short strings (insert, delete, replace). */
static int edit_distance(const char *a, const char *b) {
    int la = (int)strlen(a);
    int lb = (int)strlen(b);
    int prev[AST_NAME_LEN + 1];
    int cur[AST_NAME_LEN + 1];

    for (int j = 0; j <= lb; j++) {
        prev[j] = j;
    }
    for (int i = 1; i <= la; i++) {
        cur[0] = i;
        for (int j = 1; j <= lb; j++) {
            int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            int best = prev[j - 1] + cost;          /* replace */
            if (prev[j] + 1 < best) best = prev[j] + 1;   /* delete  */
            if (cur[j - 1] + 1 < best) best = cur[j - 1] + 1; /* insert */
            cur[j] = best;
        }
        memcpy(prev, cur, sizeof(int) * (size_t)(lb + 1));
    }
    return prev[lb];
}

/* Find the closest declared name. Writes " (did you mean 'X'?)" into
   hint, or an empty string if nothing is close enough. */
static void suggest(const char *wrong, const SemaName *names, int n,
                    const SemaRole *roles, int num_roles,
                    char *hint, size_t hint_len) {
    const char *best = NULL;
    int best_dist = 3;      /* only suggest names at most 2 edits away */

    for (int i = 0; i < n; i++) {
        int d = edit_distance(wrong, names[i].name);
        if (d < best_dist) {
            best_dist = d;
            best = names[i].name;
        }
    }
    for (int i = 0; i < num_roles; i++) {
        int d = edit_distance(wrong, roles[i].name);
        if (d < best_dist) {
            best_dist = d;
            best = roles[i].name;
        }
    }

    if (best != NULL) {
        snprintf(hint, hint_len, " (did you mean '%s'?)", best);
    } else {
        hint[0] = '\0';
    }
}

/* ---------- lookups ---------- */

int sema_find_role(const Sema *s, const char *name) {
    for (int i = 0; i < s->num_roles; i++) {
        if (strcmp(s->roles[i].name, name) == 0) return i;
    }
    return -1;
}

static int find_name(const SemaName *names, int n, const char *name) {
    for (int i = 0; i < n; i++) {
        if (strcmp(names[i].name, name) == 0) return i;
    }
    return -1;
}

int sema_find_resource(const Sema *s, const char *name) {
    return find_name(s->resources, s->num_resources, name);
}

int sema_find_action(const Sema *s, const char *name) {
    return find_name(s->actions, s->num_actions, name);
}

/* ---------- pass 1: collect declarations ---------- */

static void collect_declarations(Sema *s, const Program *prog, const char *path) {
    int max = prog->count;
    s->roles     = xcalloc((size_t)max, sizeof(SemaRole));
    s->resources = xcalloc((size_t)max, sizeof(SemaName));
    s->actions   = xcalloc((size_t)max, sizeof(SemaName));

    for (int i = 0; i < prog->count; i++) {
        Node *n = prog->items[i];

        if (ISA(RoleDecl, n)) {
            RoleDecl *r = CAST(RoleDecl, n);
            int old = sema_find_role(s, r->name);
            if (old >= 0) {
                report(s, path, "error", n->line, n->col,
                       "role '%s' is already declared on line %d",
                       r->name, s->roles[old].line);
                continue;
            }
            SemaRole *dst = &s->roles[s->num_roles++];
            copy_name(dst->name, r->name);
            dst->parent = -1;          /* resolved in pass 2 */
            dst->line = n->line;
            dst->col = n->col;

        } else if (ISA(ResourceDecl, n)) {
            ResourceDecl *r = CAST(ResourceDecl, n);
            int old = sema_find_resource(s, r->name);
            if (old >= 0) {
                report(s, path, "error", n->line, n->col,
                       "resource '%s' is already declared on line %d",
                       r->name, s->resources[old].line);
                continue;
            }
            SemaName *dst = &s->resources[s->num_resources++];
            copy_name(dst->name, r->name);
            dst->line = n->line;
            dst->col = n->col;

        } else if (ISA(ActionDecl, n)) {
            ActionDecl *a = CAST(ActionDecl, n);
            int old = sema_find_action(s, a->name);
            if (old >= 0) {
                report(s, path, "error", n->line, n->col,
                       "action '%s' is already declared on line %d",
                       a->name, s->actions[old].line);
                continue;
            }
            SemaName *dst = &s->actions[s->num_actions++];
            copy_name(dst->name, a->name);
            dst->line = n->line;
            dst->col = n->col;
        }
    }
}

/* ---------- pass 2: parents, cycles, ancestor lists ---------- */

static void resolve_parents(Sema *s, const Program *prog, const char *path) {
    /* Link each role to its parent. Done after pass 1, so a parent may be
       declared below its child. */
    for (int i = 0; i < prog->count; i++) {
        RoleDecl *r = DYN_CAST(RoleDecl, prog->items[i]);
        if (r == NULL || !r->has_parent) {
            continue;
        }
        int self = sema_find_role(s, r->name);
        /* Skip duplicate declarations: only the first one counts. */
        if (self < 0 || s->roles[self].line != r->base.line) {
            continue;
        }
        int parent = sema_find_role(s, r->parent);
        if (parent < 0) {
            char hint[AST_NAME_LEN + 32];
            suggest(r->parent, NULL, 0, s->roles, s->num_roles, hint, sizeof(hint));
            report(s, path, "error", r->base.line, r->base.col,
                   "parent role '%s' of '%s' is not declared%s",
                   r->parent, r->name, hint);
            continue;
        }
        s->roles[self].parent = parent;
    }
}

/* Detect inheritance cycles (A : B, B : A) and report each one once. */
static void check_cycles(Sema *s, const char *path, int *in_cycle) {
    for (int start = 0; start < s->num_roles; start++) {
        /* Walk up at most num_roles steps. Coming back to `start` means
           start is on a cycle. */
        int cur = s->roles[start].parent;
        int steps = 0;
        while (cur >= 0 && cur != start && steps < s->num_roles) {
            cur = s->roles[cur].parent;
            steps++;
        }
        if (cur != start) {
            continue;
        }

        /* Report the cycle only from its first-declared member. */
        int first = start;
        for (int r = s->roles[start].parent; r != start; r = s->roles[r].parent) {
            if (r < first) first = r;
        }
        in_cycle[start] = 1;
        if (first != start) {
            continue;
        }

        char chain[512];
        size_t used = 0;
        int r = start;
        do {
            used += (size_t)snprintf(chain + used, sizeof(chain) - used,
                                     "%s -> ", s->roles[r].name);
            if (used >= sizeof(chain)) break;
            r = s->roles[r].parent;
        } while (r != start);
        if (used < sizeof(chain)) {
            snprintf(chain + used, sizeof(chain) - used, "%s", s->roles[start].name);
        }
        report(s, path, "error", s->roles[start].line, s->roles[start].col,
               "role inheritance cycle: %s", chain);
    }
}

static void build_ancestors(Sema *s, const int *in_cycle) {
    for (int i = 0; i < s->num_roles; i++) {
        SemaRole *role = &s->roles[i];
        role->ancestors = xcalloc((size_t)s->num_roles, sizeof(int));
        role->num_ancestors = 0;

        /* Walk up from the role itself. The step limit keeps roles that
           lead into a cycle from looping forever (the cycle is already
           reported as an error). */
        int cur = i;
        while (cur >= 0 && role->num_ancestors < s->num_roles) {
            role->ancestors[role->num_ancestors++] = cur;
            if (in_cycle[cur]) break;
            cur = s->roles[cur].parent;
        }
    }
}

/* ---------- pass 3: resolve and expand rules ---------- */

static int starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static void resolve_rules(Sema *s, const Program *prog, const char *path) {
    s->rules = xcalloc((size_t)prog->count, sizeof(ResolvedRule));

    for (int i = 0; i < prog->count; i++) {
        Rule *r = DYN_CAST(Rule, prog->items[i]);
        if (r == NULL) {
            continue;
        }
        int line = r->base.line;
        int col = r->base.col;
        int ok = 1;
        char hint[AST_NAME_LEN + 32];

        int role = sema_find_role(s, r->role);
        if (role < 0) {
            suggest(r->role, NULL, 0, s->roles, s->num_roles, hint, sizeof(hint));
            report(s, path, "error", line, col,
                   "rule #%d uses undeclared role '%s'%s", r->rule_id, r->role, hint);
            ok = 0;
        }

        int action = sema_find_action(s, r->action);
        if (action < 0) {
            suggest(r->action, s->actions, s->num_actions, NULL, 0, hint, sizeof(hint));
            report(s, path, "error", line, col,
                   "rule #%d uses undeclared action '%s'%s", r->rule_id, r->action, hint);
            ok = 0;
        }

        /* Expand the resource reference into a list of resource IDs. */
        int *res = xcalloc((size_t)s->num_resources, sizeof(int));
        int num_res = 0;

        switch (r->res_kind) {
            case RES_EXACT: {
                int id = sema_find_resource(s, r->res_text);
                if (id < 0) {
                    suggest(r->res_text, s->resources, s->num_resources, NULL, 0,
                            hint, sizeof(hint));
                    report(s, path, "error", line, col,
                           "rule #%d uses undeclared resource '%s'%s",
                           r->rule_id, r->res_text, hint);
                    ok = 0;
                } else {
                    res[num_res++] = id;
                }
                break;
            }
            case RES_PREFIX:
                for (int k = 0; k < s->num_resources; k++) {
                    if (starts_with(s->resources[k].name, r->res_text)) {
                        res[num_res++] = k;
                    }
                }
                if (num_res == 0) {
                    report(s, path, "warning", line, col,
                           "wildcard '%s*' in rule #%d matches no declared resource, "
                           "so the rule has no effect", r->res_text, r->rule_id);
                }
                break;
            case RES_ANY:
                for (int k = 0; k < s->num_resources; k++) {
                    res[num_res++] = k;
                }
                if (num_res == 0) {
                    report(s, path, "warning", line, col,
                           "wildcard '*' in rule #%d matches nothing because no "
                           "resources are declared", r->rule_id);
                }
                break;
        }

        if (!ok) {
            free(res);
            continue;
        }

        ResolvedRule *dst = &s->rules[s->num_rules++];
        switch (r->res_kind) {
            case RES_ANY:    snprintf(dst->res_pattern, sizeof(dst->res_pattern), "*"); break;
            case RES_PREFIX: snprintf(dst->res_pattern, sizeof(dst->res_pattern), "%s*", r->res_text); break;
            default:         snprintf(dst->res_pattern, sizeof(dst->res_pattern), "%s", r->res_text); break;
        }
        dst->rule_id = r->rule_id;
        dst->is_allow = ISA(AllowRule, prog->items[i]);
        dst->role = role;
        dst->action = action;
        dst->resources = res;
        dst->num_resources = num_res;
        dst->line = line;
        dst->col = col;
    }
}

/* ---------- pass 4: resolve and expand security assertions ---------- */

static void resolve_assertions(Sema *s, const Program *prog, const char *path) {
    s->assertions = xcalloc((size_t)prog->count, sizeof(ResolvedAssertion));

    for (int i = 0; i < prog->count; i++) {
        Assertion *a = DYN_CAST(Assertion, prog->items[i]);
        if (a == NULL) {
            continue;
        }
        int line = a->base.line;
        int col = a->base.col;
        int ok = 1;
        char hint[AST_NAME_LEN + 32];

        int role = -1;
        if (a->subject == SUBJ_ROLE) {
            role = sema_find_role(s, a->role);
            if (role < 0) {
                suggest(a->role, NULL, 0, s->roles, s->num_roles, hint, sizeof(hint));
                report(s, path, "error", line, col,
                       "assertion A%d uses undeclared role '%s'%s", a->assert_id, a->role, hint);
                ok = 0;
            }
        }

        int action = sema_find_action(s, a->action);
        if (action < 0) {
            suggest(a->action, s->actions, s->num_actions, NULL, 0, hint, sizeof(hint));
            report(s, path, "error", line, col,
                   "assertion A%d uses undeclared action '%s'%s", a->assert_id, a->action, hint);
            ok = 0;
        }

        int *res = xcalloc((size_t)s->num_resources, sizeof(int));
        int num_res = 0;
        if (a->res_kind == RES_EXACT) {
            int id = sema_find_resource(s, a->res_text);
            if (id < 0) {
                suggest(a->res_text, s->resources, s->num_resources, NULL, 0, hint, sizeof(hint));
                report(s, path, "error", line, col,
                       "assertion A%d uses undeclared resource '%s'%s",
                       a->assert_id, a->res_text, hint);
                ok = 0;
            } else {
                res[num_res++] = id;
            }
        } else {
            for (int k = 0; k < s->num_resources; k++) {
                if (a->res_kind == RES_ANY || starts_with(s->resources[k].name, a->res_text)) {
                    res[num_res++] = k;
                }
            }
            if (num_res == 0) {
                report(s, path, "warning", line, col,
                       "wildcard in assertion A%d matches no declared resource, "
                       "so it checks nothing", a->assert_id);
            }
        }

        if (!ok) {
            free(res);
            continue;
        }

        ResolvedAssertion *dst = &s->assertions[s->num_assertions++];
        dst->assert_id = a->assert_id;
        dst->all_roles = (a->subject != SUBJ_ROLE);
        dst->role = role;
        dst->expect_allowed = a->expect_allowed;
        dst->action = action;
        dst->resources = res;
        dst->num_resources = num_res;
        dst->line = line;
        dst->col = col;
        assertion_to_text(a, dst->text, sizeof(dst->text));
    }
}

void sema_suggest(const Sema *s, char kind, const char *wrong, char *hint, size_t len) {
    if (kind == 'r') {
        suggest(wrong, NULL, 0, s->roles, s->num_roles, hint, len);
    } else if (kind == 'R') {
        suggest(wrong, s->resources, s->num_resources, NULL, 0, hint, len);
    } else {
        suggest(wrong, s->actions, s->num_actions, NULL, 0, hint, len);
    }
}

/* ---------- public API ---------- */

Sema *sema_check(const Program *prog, const char *path) {
    Sema *s = xcalloc(1, sizeof(Sema));

    collect_declarations(s, prog, path);
    resolve_parents(s, prog, path);

    int *in_cycle = xcalloc((size_t)s->num_roles, sizeof(int));
    check_cycles(s, path, in_cycle);
    build_ancestors(s, in_cycle);
    free(in_cycle);

    resolve_rules(s, prog, path);
    resolve_assertions(s, prog, path);
    return s;
}

void sema_dump(const Sema *s) {
    printf("Symbol table\n");

    printf("  Roles (%d)\n", s->num_roles);
    for (int i = 0; i < s->num_roles; i++) {
        const SemaRole *r = &s->roles[i];
        char label[2 * AST_NAME_LEN + 4];
        if (r->parent >= 0) {
            snprintf(label, sizeof(label), "%s : %s", r->name, s->roles[r->parent].name);
        } else {
            snprintf(label, sizeof(label), "%s", r->name);
        }
        printf("    %2d  %-28s ancestors: ", i, label);
        for (int k = 0; k < r->num_ancestors; k++) {
            printf("%s%s", k ? ", " : "", s->roles[r->ancestors[k]].name);
        }
        printf("\n");
    }

    printf("  Resources (%d)\n", s->num_resources);
    for (int i = 0; i < s->num_resources; i++) {
        printf("    %2d  %s\n", i, s->resources[i].name);
    }

    printf("  Actions (%d)\n", s->num_actions);
    for (int i = 0; i < s->num_actions; i++) {
        printf("    %2d  %s\n", i, s->actions[i].name);
    }

    printf("\nResolved rules (%d)\n", s->num_rules);
    for (int i = 0; i < s->num_rules; i++) {
        const ResolvedRule *r = &s->rules[i];
        printf("  #%-2d %-5s role=%s(%d) action=%s(%d) resources=[",
               r->rule_id, r->is_allow ? "ALLOW" : "DENY",
               s->roles[r->role].name, r->role,
               s->actions[r->action].name, r->action);
        for (int k = 0; k < r->num_resources; k++) {
            int id = r->resources[k];
            printf("%s%s(%d)", k ? ", " : "", s->resources[id].name, id);
        }
        printf("]\n");
    }

    if (s->num_assertions > 0) {
        printf("\nAssertions (%d)\n", s->num_assertions);
        for (int i = 0; i < s->num_assertions; i++) {
            const ResolvedAssertion *a = &s->assertions[i];
            printf("  A%-2d %s  -> checks %s x %d resource(s)\n", a->assert_id, a->text,
                   a->all_roles ? "all roles" : s->roles[a->role].name, a->num_resources);
        }
    }
}

void sema_free(Sema *s) {
    if (s == NULL) {
        return;
    }
    for (int i = 0; i < s->num_roles; i++) {
        free(s->roles[i].ancestors);
    }
    for (int i = 0; i < s->num_rules; i++) {
        free(s->rules[i].resources);
    }
    for (int i = 0; i < s->num_assertions; i++) {
        free(s->assertions[i].resources);
    }
    free(s->assertions);
    free(s->roles);
    free(s->resources);
    free(s->actions);
    free(s->rules);
    free(s);
}
