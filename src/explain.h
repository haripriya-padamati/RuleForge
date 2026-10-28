#ifndef EXPLAIN_H
#define EXPLAIN_H

#include <stdio.h>

#include "sema.h"
#include "table.h"

/* ------------------------------------------------------------------
   Explainable decisions (provenance).

   For any (role, resource, action) this module says WHY the answer is
   what it is: the deciding rule, the inheritance path through which
   that rule reaches the role, and the rules it overrode. It is used by
   --explain, --who-can, assertion counterexamples and fix suggestions.
   ------------------------------------------------------------------ */

/* Index into s->rules of the rule with this rule_id, or -1. */
int  explain_rule_index(const Sema *s, int rule_id);

/* A rule as source text, e.g. "Deny Employee to read Salary_Records;" */
void explain_rule_text(const Sema *s, const ResolvedRule *r, char *buf, size_t len);

/* How a rule written for `owner` reaches `role`:
   "written for Manager"  or  "inherited via Manager -> Employee" */
void explain_reach(const Sema *s, int role, int owner, char *buf, size_t len);

/* Print a full explanation of one decision, every line starting with
   `indent`:
     Manager read Salary_Records -> DENIED
       decided by rule #1 (line 11): Deny Employee to read Salary_Records;
         inherited via Manager -> Employee
       overridden (deny overrides allow): rule #2 (line 12): Allow Manager to read Salary_*; */
void explain_print(FILE *out, const Sema *s, const DecisionTable *t,
                   int role, int resource, int action, const char *indent);

/* --who-can: list every role with its answer and the reason. */
void explain_who_can(FILE *out, const Sema *s, const DecisionTable *t,
                     int resource, int action);

#endif
