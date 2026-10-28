#include "verify.h"

#include "explain.h"

#include <stdio.h>

#define MAX_SHOWN_COUNTEREXAMPLES 2

int verify_assertions(const Sema *s, const DecisionTable *t, const char *path) {
    printf("Security assertions (%d)\n", s->num_assertions);
    if (s->num_assertions == 0) {
        printf("  none in this file\n");
        return 0;
    }

    int failed = 0;
    for (int i = 0; i < s->num_assertions; i++) {
        const ResolvedAssertion *a = &s->assertions[i];
        int first_role = a->all_roles ? 0 : a->role;
        int last_role = a->all_roles ? s->num_roles - 1 : a->role;

        /* Check every case the assertion covers. */
        int cases = 0, violations = 0;
        for (int role = first_role; role <= last_role; role++) {
            for (int k = 0; k < a->num_resources; k++) {
                Decision d = table_get(t, role, a->resources[k], a->action);
                cases++;
                if (d.allowed != a->expect_allowed) violations++;
            }
        }

        if (violations == 0) {
            printf("  PROVED  A%d (line %d): %s   [all %d case(s) checked]\n",
                   a->assert_id, a->line, a->text, cases);
            continue;
        }

        failed++;
        printf("  FAILED  A%d (line %d): %s   [%d of %d case(s) violate it]\n",
               a->assert_id, a->line, a->text, violations, cases);
        fflush(stdout);

        fprintf(stderr, "%s:%d:%d: error: assertion A%d failed: %s\n",
                path, a->line, a->col, a->assert_id, a->text);
        int shown = 0;
        for (int role = first_role; role <= last_role && shown < MAX_SHOWN_COUNTEREXAMPLES; role++) {
            for (int k = 0; k < a->num_resources && shown < MAX_SHOWN_COUNTEREXAMPLES; k++) {
                Decision d = table_get(t, role, a->resources[k], a->action);
                if (d.allowed == a->expect_allowed) continue;
                fprintf(stderr, "  counterexample:\n");
                explain_print(stderr, s, t, role, a->resources[k], a->action, "    ");
                shown++;
            }
        }
        if (violations > shown) {
            fprintf(stderr, "  (and %d more counterexample(s))\n", violations - shown);
        }
    }

    printf("  %d proved, %d failed\n", s->num_assertions - failed, failed);
    return failed;
}
