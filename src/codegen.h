#ifndef CODEGEN_H
#define CODEGEN_H

#include "sema.h"
#include "table.h"

/* ------------------------------------------------------------------
   Step 7: LLVM IR generator.

   Writes a textual LLVM IR module (.ll) containing:

     %Decision = type { i1, i32 }          ; allowed bit + deciding rule ID

     @decision_table                       ; the Step 6 table, as a
                                           ; constant global array

     define %Decision @checkAccess(i32 %role, i32 %res, i32 %act)
         ; 1. range-check the three inputs (one branch)
         ; 2. out of range  -> return { false, 0 }
         ; 3. in range      -> index = (role*R + res)*A + act,
         ;                     load the entry and return it

     define i32 @checkAccessPacked(i32, i32, i32)
         ; same answer packed into one i32: (rule_id << 1) | allowed
         ; Returning a struct by value to C can hit ABI differences,
         ; so C callers use this one.

   The IR uses opaque pointers ("ptr"), so it needs LLVM 15 or newer.
   It can be checked with:   llvm-as file.ll -o NUL      (Windows)
                             opt -passes=verify file.ll -disable-output
   ------------------------------------------------------------------ */

/* Write the module to out_path. source_path is only used for the
   source_filename line and comments. Returns 1 on success, 0 if the
   file cannot be written. */
int codegen_emit(const Sema *s, const DecisionTable *t,
                 const char *source_path, const char *out_path);

/* Step 8: write a C header for programs that call the compiled policy.
   It contains:
     - an enum of IDs per name:  ROLE_Manager, RESOURCE_Salary_Records,
       ACTION_read, plus RULEFORGE_NUM_ROLES / _RESOURCES / _ACTIONS
     - the names as strings, for printing
     - RULEFORGE_EXPECTED: the Step 6 decision table, in the same order
       as the IR table, so a test can compare the compiled function
       against what the compiler intended
     - the prototype of checkAccessPacked
   Returns 1 on success, 0 if the file cannot be written. */
int codegen_emit_header(const Sema *s, const DecisionTable *t,
                        const char *source_path, const char *out_path);

#endif
