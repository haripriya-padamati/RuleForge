#ifndef SEMA_H
#define SEMA_H

#include <stddef.h>

#include "ast.h"

/* ------------------------------------------------------------------
   Step 4: symbol table and rule expansion.

   Every declared name gets a small integer ID (its index in the
   matching array). Later steps (conflict finder, decision table,
   codegen) work only with these IDs, never with strings.
   ------------------------------------------------------------------ */

/* One declared role. */
typedef struct {
    char name[AST_NAME_LEN];
    int  parent;          /* role ID of the parent, or -1 if none        */
    int  line;
    int  col;
    int *ancestors;       /* itself first, then parent, grandparent, ... */
    int  num_ancestors;
} SemaRole;

/* One declared resource or action. */
typedef struct {
    char name[AST_NAME_LEN];
    int  line;
    int  col;
} SemaName;

/* One rule after every name is resolved to an ID and every
   wildcard is expanded into the list of resources it matches. */
typedef struct {
    int  rule_id;         /* same number as in the AST (1, 2, 3 ...) */
    int  is_allow;        /* 1 = Allow, 0 = Deny                     */
    int  role;            /* role ID                                 */
    int  action;          /* action ID                               */
    int *resources;       /* resource IDs this rule applies to       */
    int  num_resources;
    int  line;
    int  col;
    char res_pattern[AST_NAME_LEN + 2];  /* as written: "Salary_*", "*", ... */
} ResolvedRule;

/* One security assertion after name resolution and wildcard expansion. */
typedef struct {
    int  assert_id;       /* A1, A2, ... in file order                   */
    int  all_roles;       /* 1 for "every role" / "no role"              */
    int  role;            /* role ID when all_roles == 0                 */
    int  expect_allowed;  /* 1 = must be allowed, 0 = must be denied     */
    int  action;
    int *resources;
    int  num_resources;
    int  line;
    int  col;
    char text[3 * AST_NAME_LEN + 32];   /* e.g. "Intern cannot write Salary_*" */
} ResolvedAssertion;

typedef struct {
    SemaRole     *roles;
    int           num_roles;
    SemaName     *resources;
    int           num_resources;
    SemaName     *actions;
    int           num_actions;
    ResolvedRule *rules;
    int           num_rules;
    ResolvedAssertion *assertions;
    int           num_assertions;

    int           num_errors;
    int           num_warnings;
} Sema;

/* Check the program and build the symbol table.
   Diagnostics are printed to stderr as  path:line:col: error: ...
   Always returns a Sema (NULL only if out of memory). The caller must
   check num_errors: if it is > 0, the result must not be used by later
   steps. Free it with sema_free(). */
Sema *sema_check(const Program *prog, const char *path);

/* Print the symbol table and the resolved rules as readable text. */
void  sema_dump(const Sema *s);

void  sema_free(Sema *s);

/* Suggest the closest declared name of one kind ('r'ole, 'R'esource,
   'a'ction): writes " (did you mean 'X'?)" or an empty string. */
void  sema_suggest(const Sema *s, char kind, const char *wrong, char *hint, size_t len);

/* Look up a name. Returns its ID, or -1 if it is not declared. */
int   sema_find_role(const Sema *s, const char *name);
int   sema_find_resource(const Sema *s, const char *name);
int   sema_find_action(const Sema *s, const char *name);

#endif
