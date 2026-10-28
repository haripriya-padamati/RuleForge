#ifndef TABLE_H
#define TABLE_H

#include "sema.h"

/* ------------------------------------------------------------------
   Step 6: decision table.

   For every (role, resource, action) we store the final answer:
     allowed  : 1 = allow, 0 = deny
     rule_id  : the rule that decided it, or 0 if no rule applied

   Policy:
     - if any Deny rule applies  -> {0, that Deny's rule_id}
     - else if any Allow applies -> {1, that Allow's rule_id}
     - else                      -> {0, 0}   (default deny)
   When several rules of the winning kind apply, the lowest rule_id
   (the one written first) is reported.

   Everything is stored in ONE flat array. The index of a combination is
       (role * num_resources + resource) * num_actions + action
   This exact layout is what Step 7 emits as an LLVM global array.
   ------------------------------------------------------------------ */

typedef struct {
    int allowed;    /* becomes i1  in LLVM IR */
    int rule_id;    /* becomes i32 in LLVM IR */
} Decision;

typedef struct {
    Decision *entries;      /* num_roles * num_resources * num_actions */
    int       num_entries;
    int       num_roles;
    int       num_resources;
    int       num_actions;
} DecisionTable;

/* Build the table. Only call this when sema->num_errors == 0. */
DecisionTable *table_build(const Sema *s);

/* Flat index of a combination (no range check). */
int table_index(const DecisionTable *t, int role, int resource, int action);

/* Look up one combination. Out-of-range IDs give {0, 0}, the same
   answer checkAccess will give in Step 7. */
Decision table_get(const DecisionTable *t, int role, int resource, int action);

/* Print the table as a grid: one row per (role, action),
   one column per resource. */
void table_print(const DecisionTable *t, const Sema *s);

void table_free(DecisionTable *t);

#endif
