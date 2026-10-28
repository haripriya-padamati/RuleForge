#ifndef VERIFY_H
#define VERIFY_H

#include "sema.h"
#include "table.h"

/* ------------------------------------------------------------------
   Static verification of security assertions.

     assert Intern cannot write Salary_*;
     assert every role can read Public_Notice;
     assert no role can delete Server_Logs;

   Each assertion is checked against EVERY case it covers (every role
   in scope x every matching resource), using the decision table the
   compiler built. The policy space is finite, so this check is
   complete: a PROVED assertion holds for every possible request.
   A violated assertion is a compile error, reported with a
   counterexample and the rule + inheritance path that causes it.
   ------------------------------------------------------------------ */

/* Prints a PROVED/FAILED line per assertion to stdout and the details
   of each failure to stderr (path:line:col: error: ...).
   Returns the number of failed assertions. */
int verify_assertions(const Sema *s, const DecisionTable *t, const char *path);

#endif
