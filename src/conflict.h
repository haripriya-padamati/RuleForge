#ifndef CONFLICT_H
#define CONFLICT_H

#include "sema.h"

/* ------------------------------------------------------------------
   Step 5: conflict finder.

   For every (role, resource, action) combination we collect the rules
   that apply to it. A rule applies when:
     - its role is the role itself OR one of the role's ancestors,
     - its expanded resource list contains the resource,
     - its action is the action.
   If at least one Allow and at least one Deny apply, that combination
   is a conflict, and the combination itself is the witness.
   ------------------------------------------------------------------ */

/* One rule that applies to a combination, and how it got there. */
typedef struct {
    int rule;       /* index into Sema.rules                          */
    int via;        /* role ID the rule was written for. If it differs
                       from the conflict's role, the rule was inherited */
} AppliedRule;

typedef struct {
    int role;
    int resource;
    int action;

    AppliedRule *allows;
    int          num_allows;
    AppliedRule *denies;
    int          num_denies;

    int inherited;  /* 1 if any of the clashing rules came from an ancestor,
                       i.e. the conflict is hidden behind inheritance      */
} Conflict;

typedef struct {
    Conflict *items;
    int       count;
    int       num_direct;
    int       num_inherited;
} ConflictList;

/* 1 if rule r applies to (role, resource, action), counting inheritance.
   Shared by the conflict finder and the decision table (Step 6). */
int rule_applies(const Sema *s, const ResolvedRule *r,
                 int role, int resource, int action);

/* Check every combination. Only call this when sema->num_errors == 0. */
ConflictList *find_conflicts(const Sema *s);

/* Print one line per conflict plus a summary, e.g.
   path:17:1: conflict: (HR_Manager, Salary_Records, write)
       Allow #4 (line 17) for HR_Manager
       Deny  #3 (line 16) inherited from Employee                     */
void conflicts_print(const ConflictList *cl, const Sema *s, const char *path);

void conflicts_free(ConflictList *cl);

#endif
