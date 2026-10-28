#include "conflict.h"

#include <stdio.h>
#include <stdlib.h>

/* ---------- small helpers ---------- */

static void *xcalloc(size_t count, size_t size) {
    void *p = calloc(count ? count : 1, size);
    if (p == NULL) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(1);
    }
    return p;
}

/* Does the rule's resource list contain this resource? */
static int covers_resource(const ResolvedRule *r, int resource) {
    for (int k = 0; k < r->num_resources; k++) {
        if (r->resources[k] == resource) return 1;
    }
    return 0;
}

/* Is the rule's role the role itself or one of its ancestors? */
static int covers_role(const Sema *s, const ResolvedRule *r, int role) {
    const SemaRole *sr = &s->roles[role];
    for (int k = 0; k < sr->num_ancestors; k++) {
        if (sr->ancestors[k] == r->role) return 1;
    }
    return 0;
}

int rule_applies(const Sema *s, const ResolvedRule *r,
                 int role, int resource, int action) {
    return r->action == action
        && covers_resource(r, resource)
        && covers_role(s, r, role);
}

/* ---------- public API ---------- */

ConflictList *find_conflicts(const Sema *s) {
    ConflictList *cl = xcalloc(1, sizeof(ConflictList));
    int capacity = 16;
    cl->items = xcalloc((size_t)capacity, sizeof(Conflict));

    /* Scratch lists, reused for every combination. */
    AppliedRule *allows = xcalloc((size_t)s->num_rules, sizeof(AppliedRule));
    AppliedRule *denies = xcalloc((size_t)s->num_rules, sizeof(AppliedRule));

    for (int role = 0; role < s->num_roles; role++) {
        for (int res = 0; res < s->num_resources; res++) {
            for (int act = 0; act < s->num_actions; act++) {

                int na = 0, nd = 0;
                for (int i = 0; i < s->num_rules; i++) {
                    const ResolvedRule *r = &s->rules[i];
                    if (!rule_applies(s, r, role, res, act)) continue;

                    AppliedRule ar = { i, r->role };
                    if (r->is_allow) allows[na++] = ar;
                    else             denies[nd++] = ar;
                }

                if (na == 0 || nd == 0) {
                    continue;   /* no clash for this combination */
                }

                if (cl->count == capacity) {
                    capacity *= 2;
                    Conflict *bigger = realloc(cl->items, (size_t)capacity * sizeof(Conflict));
                    if (bigger == NULL) {
                        fprintf(stderr, "fatal: out of memory\n");
                        exit(1);
                    }
                    cl->items = bigger;
                }

                Conflict *c = &cl->items[cl->count++];
                c->role = role;
                c->resource = res;
                c->action = act;
                c->num_allows = na;
                c->num_denies = nd;
                c->allows = xcalloc((size_t)na, sizeof(AppliedRule));
                c->denies = xcalloc((size_t)nd, sizeof(AppliedRule));
                c->inherited = 0;
                for (int k = 0; k < na; k++) {
                    c->allows[k] = allows[k];
                    if (allows[k].via != role) c->inherited = 1;
                }
                for (int k = 0; k < nd; k++) {
                    c->denies[k] = denies[k];
                    if (denies[k].via != role) c->inherited = 1;
                }

                if (c->inherited) cl->num_inherited++;
                else              cl->num_direct++;
            }
        }
    }

    free(allows);
    free(denies);
    return cl;
}

static void print_applied(const Sema *s, const AppliedRule *ar, int role) {
    const ResolvedRule *r = &s->rules[ar->rule];
    printf("      %-5s #%d (line %d) ", r->is_allow ? "Allow" : "Deny",
           r->rule_id, r->line);
    if (ar->via == role) {
        printf("written for %s\n", s->roles[ar->via].name);
    } else {
        printf("inherited from %s\n", s->roles[ar->via].name);
    }
}

void conflicts_print(const ConflictList *cl, const Sema *s, const char *path) {
    printf("Conflicts\n");
    if (cl->count == 0) {
        printf("  none: no combination has both an Allow and a Deny rule\n");
        return;
    }

    for (int i = 0; i < cl->count; i++) {
        const Conflict *c = &cl->items[i];

        /* Point at the rule written last, since that is usually the one
           that introduced the clash. */
        int line = 0, col = 0;
        for (int k = 0; k < c->num_allows; k++) {
            const ResolvedRule *r = &s->rules[c->allows[k].rule];
            if (r->line > line) { line = r->line; col = r->col; }
        }
        for (int k = 0; k < c->num_denies; k++) {
            const ResolvedRule *r = &s->rules[c->denies[k].rule];
            if (r->line > line) { line = r->line; col = r->col; }
        }

        printf("  %s:%d:%d: %s conflict: (%s, %s, %s)\n", path, line, col,
               c->inherited ? "hidden" : "direct",
               s->roles[c->role].name,
               s->resources[c->resource].name,
               s->actions[c->action].name);
        for (int k = 0; k < c->num_allows; k++) print_applied(s, &c->allows[k], c->role);
        for (int k = 0; k < c->num_denies; k++) print_applied(s, &c->denies[k], c->role);
    }

    printf("  %d conflict(s): %d direct, %d hidden through inheritance\n",
           cl->count, cl->num_direct, cl->num_inherited);
    printf("  (Deny overrides Allow, so in each case above access is denied.)\n");
}

void conflicts_free(ConflictList *cl) {
    if (cl == NULL) {
        return;
    }
    for (int i = 0; i < cl->count; i++) {
        free(cl->items[i].allows);
        free(cl->items[i].denies);
    }
    free(cl->items);
    free(cl);
}
