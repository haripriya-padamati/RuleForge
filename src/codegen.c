#include "codegen.h"

#include <stdio.h>

/* Print a string inside LLVM quotes. Backslashes (Windows paths) and
   quotes must be written as hex escapes: \5C and \22. */
static void emit_llvm_string(FILE *out, const char *text) {
    fputc('"', out);
    for (const char *p = text; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '\\' || c == '"' || c < 32 || c > 126) {
            fprintf(out, "\\%02X", c);
        } else {
            fputc(c, out);
        }
    }
    fputc('"', out);
}

/* Comment block listing the integer ID of every name, so a reader of the
   .ll file (and the C test program in Step 8) knows what 0, 1, 2 mean. */
static void emit_id_comments(FILE *out, const Sema *s) {
    fprintf(out, "; Role IDs:\n");
    for (int i = 0; i < s->num_roles; i++) {
        fprintf(out, ";   %d = %s\n", i, s->roles[i].name);
    }
    fprintf(out, "; Resource IDs:\n");
    for (int i = 0; i < s->num_resources; i++) {
        fprintf(out, ";   %d = %s\n", i, s->resources[i].name);
    }
    fprintf(out, "; Action IDs:\n");
    for (int i = 0; i < s->num_actions; i++) {
        fprintf(out, ";   %d = %s\n", i, s->actions[i].name);
    }
    fprintf(out, "\n");
}

/* @decision_table = internal constant [N x %Decision] [ ... ] */
static void emit_table(FILE *out, const Sema *s, const DecisionTable *t) {
    fprintf(out, "; Decision table from Step 6. Deny overrides allow; no rule = { false, 0 }.\n");
    fprintf(out, "; index = (role * %d + resource) * %d + action\n",
            t->num_resources, t->num_actions);

    if (t->num_entries == 0) {
        fprintf(out, "@decision_table = internal constant [0 x %%Decision] zeroinitializer\n\n");
        return;
    }

    fprintf(out, "@decision_table = internal constant [%d x %%Decision] [\n", t->num_entries);
    for (int role = 0; role < t->num_roles; role++) {
        for (int res = 0; res < t->num_resources; res++) {
            for (int act = 0; act < t->num_actions; act++) {
                int idx = table_index(t, role, res, act);
                Decision d = t->entries[idx];
                int last = (idx == t->num_entries - 1);
                fprintf(out, "  %%Decision { i1 %s, i32 %d }%s ; [%d] %s, %s, %s\n",
                        d.allowed ? "true" : "false", d.rule_id,
                        last ? " " : ",", idx,
                        s->roles[role].name, s->resources[res].name,
                        s->actions[act].name);
            }
        }
    }
    fprintf(out, "]\n\n");
}

/* define %Decision @checkAccess(i32 %role, i32 %res, i32 %act) */
static void emit_check_access(FILE *out, const DecisionTable *t) {
    fprintf(out,
        "; Returns { allowed, rule_id } for one request.\n"
        "; Any ID outside the declared range gets { false, 0 } (default deny).\n"
        "define %%Decision @checkAccess(i32 %%role, i32 %%res, i32 %%act) {\n"
        "entry:\n"
        "  ; unsigned compare, so negative IDs are also out of range\n"
        "  %%role.ok = icmp ult i32 %%role, %d\n"
        "  %%res.ok = icmp ult i32 %%res, %d\n"
        "  %%act.ok = icmp ult i32 %%act, %d\n"
        "  %%ok.1 = and i1 %%role.ok, %%res.ok\n"
        "  %%in.range = and i1 %%ok.1, %%act.ok\n"
        "  br i1 %%in.range, label %%lookup, label %%out.of.range\n"
        "\n"
        "out.of.range:\n"
        "  ret %%Decision { i1 false, i32 0 }\n"
        "\n"
        "lookup:\n"
        "  ; index = (role * %d + res) * %d + act\n"
        "  %%t.1 = mul i32 %%role, %d\n"
        "  %%t.2 = add i32 %%t.1, %%res\n"
        "  %%t.3 = mul i32 %%t.2, %d\n"
        "  %%index = add i32 %%t.3, %%act\n"
        "  %%index.64 = zext i32 %%index to i64\n"
        "  %%entry.ptr = getelementptr inbounds [%d x %%Decision], ptr @decision_table, i64 0, i64 %%index.64\n"
        "  %%decision = load %%Decision, ptr %%entry.ptr\n"
        "  ret %%Decision %%decision\n"
        "}\n\n",
        t->num_roles, t->num_resources, t->num_actions,
        t->num_resources, t->num_actions,
        t->num_resources, t->num_actions,
        t->num_entries);
}

/* define i32 @checkAccessPacked(...) : (rule_id << 1) | allowed */
static void emit_packed_wrapper(FILE *out) {
    fprintf(out,
        "; Same answer packed into one i32 for C callers:\n"
        ";   allowed = result & 1,  rule_id = result >> 1\n"
        "define i32 @checkAccessPacked(i32 %%role, i32 %%res, i32 %%act) {\n"
        "entry:\n"
        "  %%d = call %%Decision @checkAccess(i32 %%role, i32 %%res, i32 %%act)\n"
        "  %%allowed = extractvalue %%Decision %%d, 0\n"
        "  %%rule.id = extractvalue %%Decision %%d, 1\n"
        "  %%allowed.32 = zext i1 %%allowed to i32\n"
        "  %%rule.shifted = shl i32 %%rule.id, 1\n"
        "  %%packed = or i32 %%rule.shifted, %%allowed.32\n"
        "  ret i32 %%packed\n"
        "}\n");
}

int codegen_emit(const Sema *s, const DecisionTable *t,
                 const char *source_path, const char *out_path) {
    FILE *out = fopen(out_path, "w");
    if (out == NULL) {
        return 0;
    }

    fprintf(out, "; Generated by RuleForge from %s\n", source_path);
    fprintf(out, "; ModuleID = 'ruleforge'\n");
    fprintf(out, "source_filename = ");
    emit_llvm_string(out, source_path);
    fprintf(out, "\n\n");

    emit_id_comments(out, s);

    fprintf(out, "; decision = { allowed bit, ID of the deciding rule }\n");
    fprintf(out, "%%Decision = type { i1, i32 }\n\n");

    emit_table(out, s, t);
    emit_check_access(out, t);
    emit_packed_wrapper(out);

    int ok = (ferror(out) == 0);
    if (fclose(out) != 0) {
        ok = 0;
    }
    return ok;
}

/* ---------- Step 8: C header ---------- */

/* enum { PREFIX_name = 0, ..., COUNT_NAME = n }; */
static void emit_id_enum(FILE *out, const char *prefix, const char *count_name,
                         int n, const char *(*name_of)(const Sema *, int),
                         const Sema *s) {
    fprintf(out, "enum {\n");
    for (int i = 0; i < n; i++) {
        fprintf(out, "    %s_%s = %d,\n", prefix, name_of(s, i), i);
    }
    fprintf(out, "    %s = %d\n};\n\n", count_name, n);
}

/* static const char *const NAME[] = { "a", "b" };  (never empty) */
static void emit_name_array(FILE *out, const char *array_name, int n,
                            const char *(*name_of)(const Sema *, int),
                            const Sema *s) {
    fprintf(out, "static const char *const %s[] = {", array_name);
    if (n == 0) {
        fprintf(out, " 0 ");   /* C does not allow an empty initializer */
    }
    for (int i = 0; i < n; i++) {
        fprintf(out, "%s\"%s\"", i ? ", " : " ", name_of(s, i));
    }
    fprintf(out, " };\n");
}

static const char *role_name(const Sema *s, int i)     { return s->roles[i].name; }
static const char *resource_name(const Sema *s, int i) { return s->resources[i].name; }
static const char *action_name(const Sema *s, int i)   { return s->actions[i].name; }

int codegen_emit_header(const Sema *s, const DecisionTable *t,
                        const char *source_path, const char *out_path) {
    FILE *out = fopen(out_path, "w");
    if (out == NULL) {
        return 0;
    }

    fprintf(out, "/* Generated by RuleForge from %s. Do not edit.\n", source_path);
    fprintf(out, "   Include this in a C program and link it with the compiled .ll/.o\n");
    fprintf(out, "   to call the policy, e.g. checkAccessPacked(ROLE_x, RESOURCE_y, ACTION_z). */\n\n");
    fprintf(out, "#ifndef RULEFORGE_POLICY_H\n#define RULEFORGE_POLICY_H\n\n");

    fprintf(out, "/* ID of every declared name (same numbers as in the IR) */\n");
    emit_id_enum(out, "ROLE", "RULEFORGE_NUM_ROLES", s->num_roles, role_name, s);
    emit_id_enum(out, "RESOURCE", "RULEFORGE_NUM_RESOURCES", s->num_resources, resource_name, s);
    emit_id_enum(out, "ACTION", "RULEFORGE_NUM_ACTIONS", s->num_actions, action_name, s);

    fprintf(out, "/* Names, for printing results */\n");
    emit_name_array(out, "RULEFORGE_ROLE_NAMES", s->num_roles, role_name, s);
    emit_name_array(out, "RULEFORGE_RESOURCE_NAMES", s->num_resources, resource_name, s);
    emit_name_array(out, "RULEFORGE_ACTION_NAMES", s->num_actions, action_name, s);
    fprintf(out, "\n");

    fprintf(out, "/* Step 6 decision table: { allowed, rule_id } per combination,\n");
    fprintf(out, "   index = (role * RULEFORGE_NUM_RESOURCES + resource) * RULEFORGE_NUM_ACTIONS + action */\n");
    fprintf(out, "static const int RULEFORGE_EXPECTED[][2] = {\n");
    if (t->num_entries == 0) {
        fprintf(out, "    { 0, 0 }   /* placeholder: the policy has no entries */\n");
    }
    for (int i = 0; i < t->num_entries; i++) {
        fprintf(out, "    { %d, %d }%s\n", t->entries[i].allowed, t->entries[i].rule_id,
                i == t->num_entries - 1 ? "" : ",");
    }
    fprintf(out, "};\n\n");

    fprintf(out, "/* The compiled policy function (defined in the generated .ll).\n");
    fprintf(out, "   Result: allowed = result & 1, deciding rule = result >> 1 */\n");
    fprintf(out, "int checkAccessPacked(int role, int resource, int action);\n\n");
    fprintf(out, "#endif\n");

    int ok = (ferror(out) == 0);
    if (fclose(out) != 0) {
        ok = 0;
    }
    return ok;
}
