#include "explain.h"

#include "conflict.h"   /* rule_applies() */

#include <string.h>

int explain_rule_index(const Sema *s, int rule_id) {
    for (int i = 0; i < s->num_rules; i++) {
        if (s->rules[i].rule_id == rule_id) return i;
    }
    return -1;
}

void explain_rule_text(const Sema *s, const ResolvedRule *r, char *buf, size_t len) {
    snprintf(buf, len, "%s %s to %s %s;", r->is_allow ? "Allow" : "Deny",
             s->roles[r->role].name, s->actions[r->action].name, r->res_pattern);
}

void explain_reach(const Sema *s, int role, int owner, char *buf, size_t len) {
    if (role == owner) {
        snprintf(buf, len, "written for %s", s->roles[role].name);
        return;
    }
    /* Walk up the parent chain from role until the rule's owner. */
    size_t used = (size_t)snprintf(buf, len, "inherited via %s", s->roles[role].name);
    int cur = role;
    int steps = 0;
    while (cur != owner && cur >= 0 && steps < s->num_roles && used < len) {
        cur = s->roles[cur].parent;
        if (cur < 0) break;
        used += (size_t)snprintf(buf + used, len - used, " -> %s", s->roles[cur].name);
        steps++;
    }
}

static void print_rule_line(FILE *out, const Sema *s, const char *indent,
                            const char *label, int rule_index, int role) {
    const ResolvedRule *r = &s->rules[rule_index];
    char text[3 * AST_NAME_LEN + 32];
    char reach[512];
    explain_rule_text(s, r, text, sizeof(text));
    explain_reach(s, role, r->role, reach, sizeof(reach));
    fprintf(out, "%s  %s rule #%d (line %d): %s\n", indent, label, r->rule_id, r->line, text);
    fprintf(out, "%s    %s\n", indent, reach);
}

void explain_print(FILE *out, const Sema *s, const DecisionTable *t,
                   int role, int resource, int action, const char *indent) {
    Decision d = table_get(t, role, resource, action);
    fprintf(out, "%s%s %s %s -> %s\n", indent, s->roles[role].name,
            s->actions[action].name, s->resources[resource].name,
            d.allowed ? "ALLOWED" : "DENIED");

    if (d.rule_id == 0) {
        fprintf(out, "%s  no rule gives %s '%s' access to %s, so it is denied by default\n",
                indent, s->roles[role].name, s->actions[action].name,
                s->resources[resource].name);
        return;
    }

    int decider = explain_rule_index(s, d.rule_id);
    print_rule_line(out, s, indent, "decided by", decider, role);

    /* Rules of the losing kind that also apply were overridden. */
    for (int i = 0; i < s->num_rules; i++) {
        const ResolvedRule *r = &s->rules[i];
        if (r->is_allow == d.allowed) continue;
        if (!rule_applies(s, r, role, resource, action)) continue;
        print_rule_line(out, s, indent, "overridden (deny overrides allow):", i, role);
    }
}

void explain_who_can(FILE *out, const Sema *s, const DecisionTable *t,
                     int resource, int action) {
    fprintf(out, "Who can %s %s?\n", s->actions[action].name, s->resources[resource].name);

    int allowed_count = 0;
    /* Allowed roles first, then denied ones. */
    for (int pass = 1; pass >= 0; pass--) {
        for (int role = 0; role < s->num_roles; role++) {
            Decision d = table_get(t, role, resource, action);
            if (d.allowed != pass) continue;
            allowed_count += d.allowed;

            char reason[700];
            if (d.rule_id == 0) {
                snprintf(reason, sizeof(reason), "no rule applies (default deny)");
            } else {
                const ResolvedRule *r = &s->rules[explain_rule_index(s, d.rule_id)];
                char reach[512];
                explain_reach(s, role, r->role, reach, sizeof(reach));
                snprintf(reason, sizeof(reason), "by rule #%d (line %d), %s",
                         r->rule_id, r->line, reach);
            }
            fprintf(out, "  %-8s %-16s %s\n", d.allowed ? "ALLOWED" : "DENIED",
                    s->roles[role].name, reason);
        }
    }
    fprintf(out, "  %d of %d role(s) allowed\n", allowed_count, s->num_roles);
}
