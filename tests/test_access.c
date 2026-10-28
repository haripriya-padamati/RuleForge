/* Step 8: run the compiled policy from a real C program.

   Works with ANY .rf file. RuleForge writes two things:
     x.ll  - the compiled policy (checkAccess / checkAccessPacked)
     x.h   - IDs, names and the decision table the compiler intended
   This program calls the compiled checkAccessPacked for every
   (role, resource, action) and compares each answer with the table.
   It also checks that out-of-range IDs are always denied.

   Build and run (Windows PowerShell, MinGW gcc + clang):
     .\ruleforge.exe tests\hidden_conflict.rf -o tests\out\policy.ll --header tests\out\policy.h
     clang -c tests\out\policy.ll -o tests\out\policy.o --target=x86_64-w64-windows-gnu
     gcc -include tests\out\policy.h tests\test_access.c tests\out\policy.o -o tests\out\check.exe
     .\tests\out\check.exe
   (run_tests.ps1 does all of this for every test file and picks the
   right --target for your gcc automatically.) */

#ifndef RULEFORGE_POLICY_H
#error "Compile with: gcc -include <generated header>.h tests/test_access.c <policy>.o"
#endif

#include <limits.h>
#include <stdio.h>

static void describe(int packed, char *buf, size_t n) {
    int allowed = packed & 1;
    int rule = packed >> 1;
    if (rule == 0) {
        snprintf(buf, n, "%s (no rule)", allowed ? "ALLOW" : "DENY");
    } else {
        snprintf(buf, n, "%s (rule %d)", allowed ? "ALLOW" : "DENY", rule);
    }
}

int main(void) {
    int total = 0, correct = 0;

    printf("Calling the compiled checkAccess for every combination:\n\n");
    printf("  %-14s %-18s %-8s %-18s %-18s %s\n",
           "Role", "Resource", "Action", "Compiled answer", "Expected", "Check");

    for (int role = 0; role < RULEFORGE_NUM_ROLES; role++) {
        for (int res = 0; res < RULEFORGE_NUM_RESOURCES; res++) {
            for (int act = 0; act < RULEFORGE_NUM_ACTIONS; act++) {
                int idx = (role * RULEFORGE_NUM_RESOURCES + res) * RULEFORGE_NUM_ACTIONS + act;
                int got = checkAccessPacked(role, res, act);
                int want = (RULEFORGE_EXPECTED[idx][1] << 1) | RULEFORGE_EXPECTED[idx][0];

                char got_s[32], want_s[32];
                describe(got, got_s, sizeof(got_s));
                describe(want, want_s, sizeof(want_s));
                int ok = (got == want);
                printf("  %-14s %-18s %-8s %-18s %-18s %s\n",
                       RULEFORGE_ROLE_NAMES[role], RULEFORGE_RESOURCE_NAMES[res],
                       RULEFORGE_ACTION_NAMES[act], got_s, want_s, ok ? "OK" : "WRONG");
                total++;
                correct += ok;
            }
        }
    }

    /* Requests with IDs that do not exist must be denied with rule 0. */
    int bad_requests[][3] = {
        { -1, 0, 0 },
        { RULEFORGE_NUM_ROLES, 0, 0 },
        { 0, RULEFORGE_NUM_RESOURCES, 0 },
        { 0, 0, RULEFORGE_NUM_ACTIONS },
        { 1000, 1000, 1000 },
        { INT_MIN, INT_MAX, -5 }
    };
    int num_bad = (int)(sizeof(bad_requests) / sizeof(bad_requests[0]));
    int bad_denied = 0;
    printf("\nOut-of-range requests (must be denied):\n");
    for (int i = 0; i < num_bad; i++) {
        int got = checkAccessPacked(bad_requests[i][0], bad_requests[i][1], bad_requests[i][2]);
        char got_s[32];
        describe(got, got_s, sizeof(got_s));
        printf("  checkAccess(%d, %d, %d) -> %s  %s\n", bad_requests[i][0],
               bad_requests[i][1], bad_requests[i][2], got_s, got == 0 ? "OK" : "WRONG");
        bad_denied += (got == 0);
    }

    int pass = (correct == total) && (bad_denied == num_bad);
    printf("\nRESULT: %s - %d/%d combinations correct, %d/%d out-of-range requests denied\n",
           pass ? "PASS" : "FAIL", correct, total, bad_denied, num_bad);
    return pass ? 0 : 1;
}