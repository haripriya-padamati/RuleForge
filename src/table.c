#include "table.h"

#include "conflict.h"   /* rule_applies() */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int table_index(const DecisionTable *t, int role, int resource, int action) {
    return (role * t->num_resources + resource) * t->num_actions + action;
}

DecisionTable *table_build(const Sema *s) {
    DecisionTable *t = calloc(1, sizeof(DecisionTable));
    if (t == NULL) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(1);
    }
    t->num_roles = s->num_roles;
    t->num_resources = s->num_resources;
    t->num_actions = s->num_actions;
    t->num_entries = s->num_roles * s->num_resources * s->num_actions;
    t->entries = calloc((size_t)(t->num_entries ? t->num_entries : 1), sizeof(Decision));
    if (t->entries == NULL) {
        fprintf(stderr, "fatal: out of memory\n");
        exit(1);
    }

    for (int role = 0; role < s->num_roles; role++) {
        for (int res = 0; res < s->num_resources; res++) {
            for (int act = 0; act < s->num_actions; act++) {

                int first_allow = 0;    /* lowest rule_id, 0 = none */
                int first_deny = 0;
                for (int i = 0; i < s->num_rules; i++) {
                    const ResolvedRule *r = &s->rules[i];
                    if (!rule_applies(s, r, role, res, act)) continue;

                    int *slot = r->is_allow ? &first_allow : &first_deny;
                    if (*slot == 0 || r->rule_id < *slot) {
                        *slot = r->rule_id;
                    }
                }

                Decision d;
                if (first_deny) {               /* deny overrides allow */
                    d.allowed = 0;
                    d.rule_id = first_deny;
                } else if (first_allow) {
                    d.allowed = 1;
                    d.rule_id = first_allow;
                } else {                        /* nothing applies */
                    d.allowed = 0;
                    d.rule_id = 0;
                }
                t->entries[table_index(t, role, res, act)] = d;
            }
        }
    }
    return t;
}

Decision table_get(const DecisionTable *t, int role, int resource, int action) {
    Decision none = { 0, 0 };
    if (role < 0 || role >= t->num_roles ||
        resource < 0 || resource >= t->num_resources ||
        action < 0 || action >= t->num_actions) {
        return none;
    }
    return t->entries[table_index(t, role, resource, action)];
}

void table_print(const DecisionTable *t, const Sema *s) {
    printf("Decision table (%d roles x %d resources x %d actions = %d entries)\n",
           t->num_roles, t->num_resources, t->num_actions, t->num_entries);
    printf("  ALLOW #n / DENY #n = decided by rule n,  deny - = no rule applies\n\n");

    /* Column widths: role names, action names, then one per resource. */
    int role_w = 4, act_w = 6;
    for (int i = 0; i < s->num_roles; i++) {
        int len = (int)strlen(s->roles[i].name);
        if (len > role_w) role_w = len;
    }
    for (int i = 0; i < s->num_actions; i++) {
        int len = (int)strlen(s->actions[i].name);
        if (len > act_w) act_w = len;
    }

    printf("  %-*s  %-*s", role_w, "Role", act_w, "Action");
    for (int res = 0; res < s->num_resources; res++) {
        int w = (int)strlen(s->resources[res].name);
        if (w < 9) w = 9;
        printf("  %-*s", w, s->resources[res].name);
    }
    printf("\n");

    for (int role = 0; role < t->num_roles; role++) {
        for (int act = 0; act < t->num_actions; act++) {
            printf("  %-*s  %-*s", role_w, act == 0 ? s->roles[role].name : "",
                   act_w, s->actions[act].name);
            for (int res = 0; res < t->num_resources; res++) {
                int w = (int)strlen(s->resources[res].name);
                if (w < 9) w = 9;
                Decision d = table_get(t, role, res, act);
                char cell[24];
                if (d.rule_id == 0) {
                    snprintf(cell, sizeof(cell), "deny -");
                } else {
                    snprintf(cell, sizeof(cell), "%s #%d",
                             d.allowed ? "ALLOW" : "DENY", d.rule_id);
                }
                printf("  %-*s", w, cell);
            }
            printf("\n");
        }
    }
}

void table_free(DecisionTable *t) {
    if (t == NULL) {
        return;
    }
    free(t->entries);
    free(t);
}
