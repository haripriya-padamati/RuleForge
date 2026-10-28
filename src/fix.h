#ifndef FIX_H
#define FIX_H

#include "conflict.h"
#include "sema.h"
#include "table.h"

/* ------------------------------------------------------------------
   Verified fix suggestions for conflicts.

   Conflicts that share the same Allow rules, Deny rules and action are
   grouped. For each group two repairs are proposed, written as real
   rules the user can paste into the policy:

     Fix A - keep access denied: remove the conflicting resources from
             the Allow rule(s), i.e. drop the part that never takes effect
     Fix B - grant access:       remove the conflicting resources from
             the Deny rule(s)

   Every suggestion is verified by the compiler before it is shown: the
   modified policy is analysed again (decision table + conflict search),
   and the output states that the conflict is gone and lists exactly
   which access decisions the fix would change.
   ------------------------------------------------------------------ */

void fixes_print(const ConflictList *cl, const Sema *s, const DecisionTable *t);

#endif
