#include "fix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SHOWN_CHANGES 6
#define MAX_SHOWN_PAIRS   4

static void *xcalloc(size_t count, size_t size) {
    void *p = calloc(count ? count : 1, size);
    if (p == NULL) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(1);
    }
    return p;
}

/* ---------- grouping conflicts ---------- */

typedef struct {
    int  action;
    int *allow_rules;  int num_allow;   /* indexes into Sema.rules */
    int *deny_rules;   int num_deny;
    int *roles;        int *res;  int num_pairs;   /* the clashing (role, resource) pairs */
} Group;

static int cmp_int(const void *a, const void *b) {
    return *(const int *)a - *(const int *)b;
}

/* Sorted list of rule indexes from an AppliedRule array. */
static int *rule_list(const AppliedRule *ar, int n) {
    int *out = xcalloc((size_t)n, sizeof(int));
    for (int i = 0; i < n; i++) out[i] = ar[i].rule;
    qsort(out, (size_t)n, sizeof(int), cmp_int);
    return out;
}

static int same_list(const int *a, int na, const int *b, int nb) {
    if (na != nb) return 0;
    for (int i = 0; i < na; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static Group *build_groups(const ConflictList *cl, int *num_groups) {
    Group *groups = xcalloc((size_t)cl->count, sizeof(Group));
    int n = 0;
    for (int i = 0; i < cl->count; i++) {
        const Conflict *c = &cl->items[i];
        int *al = rule_list(c->allows, c->num_allows);
        int *dl = rule_list(c->denies, c->num_denies);

        Group *g = NULL;
        for (int k = 0; k < n; k++) {
            if (groups[k].action == c->action &&
                same_list(groups[k].allow_rules, groups[k].num_allow, al, c->num_allows) &&
                same_list(groups[k].deny_rules, groups[k].num_deny, dl, c->num_denies)) {
                g = &groups[k];
                break;
            }
        }
        if (g == NULL) {
            g = &groups[n++];
            g->action = c->action;
            g->allow_rules = al; g->num_allow = c->num_allows;
            g->deny_rules = dl;  g->num_deny = c->num_denies;
            g->roles = xcalloc((size_t)cl->count, sizeof(int));
            g->res = xcalloc((size_t)cl->count, sizeof(int));
        } else {
            free(al);
            free(dl);
        }
        g->roles[g->num_pairs] = c->role;
        g->res[g->num_pairs] = c->resource;
        g->num_pairs++;
    }
    *num_groups = n;
    return groups;
}

static void free_groups(Group *groups, int n) {
    for (int i = 0; i < n; i++) {
        free(groups[i].allow_rules);
        free(groups[i].deny_rules);
        free(groups[i].roles);
        free(groups[i].res);
    }
    free(groups);
}

static int group_has_resource(const Group *g, int res) {
    for (int i = 0; i < g->num_pairs; i++) if (g->res[i] == res) return 1;
    return 0;
}

static int in_list(const int *list, int n, int x) {
    for (int i = 0; i < n; i++) if (list[i] == x) return 1;
    return 0;
}

/* ---------- writing a narrowed rule back as source ---------- */

/* Print the resource part of a rule covering exactly `res` (non-empty):
   "*" if it is every resource, "Prefix*" if a common prefix matches
   exactly this set, otherwise NULL (caller writes one rule each). */
static int compact_pattern(const Sema *s, const int *res, int n, char *out, size_t len) {
    if (n == s->num_resources) {
        snprintf(out, len, "*");
        return 1;
    }
    if (n == 1) {
        snprintf(out, len, "%s", s->resources[res[0]].name);
        return 1;
    }
    /* Longest common prefix of the names. */
    char prefix[AST_NAME_LEN];
    snprintf(prefix, sizeof(prefix), "%s", s->resources[res[0]].name);
    for (int i = 1; i < n; i++) {
        const char *name = s->resources[res[i]].name;
        size_t k = 0;
        while (prefix[k] != '\0' && prefix[k] == name[k]) k++;
        prefix[k] = '\0';
    }
    if (prefix[0] == '\0') return 0;
    /* The prefix must match exactly this set and nothing else. */
    int matches = 0;
    for (int k = 0; k < s->num_resources; k++) {
        if (strncmp(s->resources[k].name, prefix, strlen(prefix)) == 0) matches++;
    }
    if (matches != n) return 0;
    snprintf(out, len, "%s*", prefix);
    return 1;
}

static void print_narrowed_rule(const Sema *s, const ResolvedRule *orig,
                                const int *res, int n) {
    if (n == 0) {
        printf("      delete rule #%d (line %d)\n", orig->rule_id, orig->line);
        return;
    }
    const char *effect = orig->is_allow ? "Allow" : "Deny";
    const char *role = s->roles[orig->role].name;
    const char *action = s->actions[orig->action].name;
    char pattern[AST_NAME_LEN + 2];
    if (compact_pattern(s, res, n, pattern, sizeof(pattern))) {
        printf("      change rule #%d (line %d) to:  %s %s to %s %s;\n",
               orig->rule_id, orig->line, effect, role, action, pattern);
        return;
    }
    printf("      replace rule #%d (line %d) with:\n", orig->rule_id, orig->line);
    for (int i = 0; i < n; i++) {
        printf("        %s %s to %s %s;\n", effect, role, action, s->resources[res[i]].name);
    }
}

/* ---------- trying a fix ---------- */

/* Build a copy of the rules where every rule in `targets` loses the
   group's resources, re-analyse, and report the effect. */
static void try_fix(const Sema *s, const DecisionTable *t, const Group *g,
                    const int *targets, int num_targets) {
    ResolvedRule *rules = xcalloc((size_t)s->num_rules, sizeof(ResolvedRule));
    for (int i = 0; i < s->num_rules; i++) {
        rules[i] = s->rules[i];
        rules[i].resources = xcalloc((size_t)s->num_resources, sizeof(int));
        rules[i].num_resources = 0;
        int narrow = in_list(targets, num_targets, i);
        for (int k = 0; k < s->rules[i].num_resources; k++) {
            int res = s->rules[i].resources[k];
            if (narrow && group_has_resource(g, res)) continue;
            rules[i].resources[rules[i].num_resources++] = res;
        }
    }

    /* Show the new rule text. */
    for (int k = 0; k < num_targets; k++) {
        int i = targets[k];
        print_narrowed_rule(s, &s->rules[i], rules[i].resources, rules[i].num_resources);
    }

    /* Re-analyse the modified policy. */
    Sema modified = *s;
    modified.rules = rules;
    DecisionTable *nt = table_build(&modified);
    ConflictList *ncl = find_conflicts(&modified);

    int still = 0;
    for (int p = 0; p < g->num_pairs; p++) {
        for (int c = 0; c < ncl->count; c++) {
            if (ncl->items[c].role == g->roles[p] && ncl->items[c].resource == g->res[p] &&
                ncl->items[c].action == g->action) still = 1;
        }
    }

    int changes = 0, reason_only = 0;
    for (int i = 0; i < t->num_entries; i++) {
        if (t->entries[i].allowed != nt->entries[i].allowed) changes++;
        else if (t->entries[i].rule_id != nt->entries[i].rule_id) reason_only++;
    }

    printf("      check: %s", still ? "conflict NOT removed" : "conflict removed");
    if (changes == 0) {
        printf(", no access decision changes");
    } else {
        printf(", %d access decision(s) change:", changes);
    }
    printf("\n");

    int shown = 0;
    for (int role = 0; role < s->num_roles; role++) {
        for (int res = 0; res < s->num_resources; res++) {
            for (int act = 0; act < s->num_actions; act++) {
                int idx = table_index(t, role, res, act);
                Decision a = t->entries[idx], b = nt->entries[idx];
                if (a.allowed == b.allowed) continue;
                if (shown < MAX_SHOWN_CHANGES) {
                    printf("        %s %s %s: %s #%d -> %s #%d\n", s->roles[role].name,
                           s->actions[act].name, s->resources[res].name,
                           a.allowed ? "ALLOW" : "DENY", a.rule_id,
                           b.allowed ? "ALLOW" : "DENY", b.rule_id);
                }
                shown++;
            }
        }
    }
    if (shown > MAX_SHOWN_CHANGES) {
        printf("        ... and %d more\n", shown - MAX_SHOWN_CHANGES);
    }
    if (ncl->count > 0) {
        printf("      conflicts left in the policy after this fix: %d\n", ncl->count);
    }

    conflicts_free(ncl);
    table_free(nt);
    for (int i = 0; i < s->num_rules; i++) free(rules[i].resources);
    free(rules);
}

static void print_rule_ids(const int *idx, int n, const Sema *s) {
    for (int i = 0; i < n; i++) {
        printf("%s#%d", i ? ", " : "", s->rules[idx[i]].rule_id);
    }
}

void fixes_print(const ConflictList *cl, const Sema *s, const DecisionTable *t) {
    if (cl->count == 0) {
        return;
    }
    int num_groups = 0;
    Group *groups = build_groups(cl, &num_groups);

    printf("\nSuggested fixes (each one re-checked by the compiler)\n");
    for (int gi = 0; gi < num_groups; gi++) {
        const Group *g = &groups[gi];

        printf("  Conflict group %d: Allow ", gi + 1);
        print_rule_ids(g->allow_rules, g->num_allow, s);
        printf(" vs Deny ");
        print_rule_ids(g->deny_rules, g->num_deny, s);
        printf(" on '%s' for ", s->actions[g->action].name);
        for (int p = 0; p < g->num_pairs && p < MAX_SHOWN_PAIRS; p++) {
            printf("%s(%s, %s)", p ? ", " : "", s->roles[g->roles[p]].name,
                   s->resources[g->res[p]].name);
        }
        if (g->num_pairs > MAX_SHOWN_PAIRS) {
            printf(" +%d more", g->num_pairs - MAX_SHOWN_PAIRS);
        }
        printf("\n");

        printf("    Fix A - keep access denied (drop the part of the Allow that never takes effect):\n");
        try_fix(s, t, g, g->allow_rules, g->num_allow);

        printf("    Fix B - grant access (narrow the Deny):\n");
        try_fix(s, t, g, g->deny_rules, g->num_deny);
    }

    free_groups(groups, num_groups);
}
