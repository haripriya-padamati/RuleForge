#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ast.h"
#include "lexer.h"
#include "parser.h"
#include "sema.h"
#include "conflict.h"
#include "table.h"
#include "codegen.h"
#include "explain.h"
#include "fix.h"
#include "verify.h"

/* Read a whole file into a malloc'd, NUL-terminated string. */
static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc((size_t)size + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }

    size_t got = fread(buf, 1, (size_t)size, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

/* tests/x.rf -> tests/x.ll  (anything else: append .ll) */
static void default_output_path(const char *in, char *out, size_t n) {
    size_t len = strlen(in);
    if (len >= 3 && strcmp(in + len - 3, ".rf") == 0) {
        snprintf(out, n, "%.*s.ll", (int)(len - 3), in);
    } else {
        snprintf(out, n, "%s.ll", in);
    }
}

static void print_tokens(const Token *tokens, int count) {
    printf("%-8s %-10s %s\n", "LINE:COL", "KIND", "TEXT");
    for (int i = 0; i < count; i++) {
        char pos[24];
        snprintf(pos, sizeof(pos), "%d:%d", tokens[i].line, tokens[i].col);
        printf("%-8s %-10s %s\n", pos, token_kind_name(tokens[i].kind),
               tokens[i].text);
    }
    printf("\n");
}

/* --steps mode: print a heading before each step's output. */
static int g_steps = 0;

static void banner(int step, const char *name) {
    if (!g_steps) return;
    printf("\n==================================================\n");
    printf(" STEP %d: %s\n", step, name);
    printf("==================================================\n");
}

/* Print a text file as it is (used for the input and the generated .ll). */
static void print_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return;
    char line[512];
    int n = 1;
    while (fgets(line, sizeof(line), f) != NULL) {
        printf("%3d | %s", n++, line);
    }
    fclose(f);
    printf("\n");
}

int main(int argc, char **argv) {
    const char *path = NULL;
    const char *out_path = NULL;
    const char *header_path = NULL;
    int show_tokens = 0;
    const char *explain_args[3] = { NULL, NULL, NULL };   /* role action resource */
    const char *who_can_args[2] = { NULL, NULL };         /* action resource      */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tokens") == 0) {
            show_tokens = 1;
        } else if (strcmp(argv[i], "--steps") == 0) {
            g_steps = 1;
            show_tokens = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (strcmp(argv[i], "--header") == 0 && i + 1 < argc) {
            header_path = argv[++i];
        } else if (strcmp(argv[i], "--explain") == 0 && i + 3 < argc) {
            explain_args[0] = argv[++i];
            explain_args[1] = argv[++i];
            explain_args[2] = argv[++i];
        } else if (strcmp(argv[i], "--who-can") == 0 && i + 2 < argc) {
            who_can_args[0] = argv[++i];
            who_can_args[1] = argv[++i];
        } else if (path == NULL) {
            path = argv[i];
        } else {
            path = NULL;
            break;
        }
    }
    if (path == NULL) {
        fprintf(stderr,
                "usage: %s [--steps] [--tokens] [-o out.ll] [--header out.h] <file.rf>\n"
                "       %s --explain <role> <action> <resource> <file.rf>\n"
                "       %s --who-can <action> <resource> <file.rf>\n",
                argv[0], argv[0], argv[0]);
        return 2;
    }
    /* Query mode: analyse the policy, answer one question, print nothing else. */
    int query = (explain_args[0] != NULL || who_can_args[0] != NULL);
    if (query) {
        g_steps = 0;
        show_tokens = 0;
    }

    char *src = read_file(path);
    if (src == NULL) {
        fprintf(stderr, "error: cannot read '%s'\n", path);
        return 2;
    }

    /* Step 1: the input, written in the RuleForge grammar */
    banner(1, "INPUT FILE (written in the RuleForge grammar)");
    if (g_steps) {
        print_file(path);
    }

    /* Step 2: lexer */
    banner(2, "LEXER - tokens");
    int count = 0;
    Token *tokens = lexer_tokenize_all(src, &count);
    if (tokens == NULL) {
        fprintf(stderr, "error: out of memory\n");
        free(src);
        return 2;
    }

    if (show_tokens) {
        print_tokens(tokens, count);
    }
    fflush(stdout);   /* keep error messages after the output above */

    int lex_errors = 0;
    for (int i = 0; i < count; i++) {
        if (tokens[i].kind == TOK_ERROR) {
            fprintf(stderr, "%s:%d:%d: lexical error: %s\n", path,
                    tokens[i].line, tokens[i].col, tokens[i].text);
            lex_errors++;
        }
    }
    if (lex_errors > 0) {
        free(tokens);
        free(src);
        return 1;
    }

    /* Step 3: parser */
    banner(3, "PARSER - abstract syntax tree (AST)");
    fflush(stdout);
    char err[256];
    Program *prog = parse_program(tokens, count, err, sizeof(err));
    if (prog == NULL) {
        fprintf(stderr, "%s:%s\n", path, err);
        free(tokens);
        free(src);
        return 1;
    }

    if (!query) {
        ast_dump(prog);
        printf("\n");
    }
    fflush(stdout);   /* so Step 4 messages appear after the AST dump */

    /* Step 4: symbol table, name checks, wildcard expansion */
    banner(4, "SEMANTIC ANALYSIS - symbol table");
    fflush(stdout);
    Sema *sema = sema_check(prog, path);
    if (sema->num_errors > 0) {
        fprintf(stderr, "%d error(s), %d warning(s)\n",
                sema->num_errors, sema->num_warnings);
        sema_free(sema);
        ast_free(prog);
        free(tokens);
        free(src);
        return 1;
    }

    if (!query) {
        sema_dump(sema);
        printf("\n");
    }

    /* Step 5: conflict finder + verified fix suggestions */
    banner(5, "CONFLICT DETECTION + FIX SUGGESTIONS");
    ConflictList *conflicts = find_conflicts(sema);
    DecisionTable *table = table_build(sema);
    if (!query) {
        conflicts_print(conflicts, sema, path);
        fixes_print(conflicts, sema, table);
        printf("\n");
    }

    /* Step 6: decision table (deny overrides allow, default deny) */
    banner(6, "DECISION TABLE");
    if (!query) {
        table_print(table, sema);
        printf("\n");
    }

    int status = 0;

    if (query) {
        /* --explain / --who-can: answer from the decision table */
        char hint[AST_NAME_LEN + 32];
        int role = -1, action, resource;
        int bad = 0;
        const char *action_name = explain_args[0] ? explain_args[1] : who_can_args[0];
        const char *resource_name = explain_args[0] ? explain_args[2] : who_can_args[1];
        if (explain_args[0] != NULL) {
            role = sema_find_role(sema, explain_args[0]);
            if (role < 0) {
                sema_suggest(sema, 'r', explain_args[0], hint, sizeof(hint));
                fprintf(stderr, "error: unknown role '%s'%s\n", explain_args[0], hint);
                bad = 1;
            }
        }
        action = sema_find_action(sema, action_name);
        if (action < 0) {
            sema_suggest(sema, 'a', action_name, hint, sizeof(hint));
            fprintf(stderr, "error: unknown action '%s'%s\n", action_name, hint);
            bad = 1;
        }
        resource = sema_find_resource(sema, resource_name);
        if (resource < 0) {
            sema_suggest(sema, 'R', resource_name, hint, sizeof(hint));
            fprintf(stderr, "error: unknown resource '%s'%s\n", resource_name, hint);
            bad = 1;
        }
        if (bad) {
            status = 1;
        } else if (explain_args[0] != NULL) {
            explain_print(stdout, sema, table, role, resource, action, "");
        } else {
            explain_who_can(stdout, sema, table, resource, action);
        }
    } else {
        /* Step 7: static verification of security assertions */
        banner(7, "STATIC VERIFICATION - security assertions");
        int failed = verify_assertions(sema, table, path);
        printf("\n");
        fflush(stdout);
        if (failed > 0) {
            fprintf(stderr, "%d assertion(s) failed - no code generated\n", failed);
            status = 1;
        } else {
            /* Step 8: LLVM IR generator */
            banner(8, "LLVM IR GENERATION");
            char default_out[1024];
            if (out_path == NULL) {
                default_output_path(path, default_out, sizeof(default_out));
                out_path = default_out;
            }
            int wrote = codegen_emit(sema, table, path, out_path);
            if (wrote) {
                printf("LLVM IR written to %s\n", out_path);
                if (g_steps) {
                    printf("\n");
                    print_file(out_path);
                }
            } else {
                fprintf(stderr, "error: cannot write '%s'\n", out_path);
            }

            /* C header with IDs and expected answers (used by tests/test_access.c) */
            if (wrote && header_path != NULL) {
                if (codegen_emit_header(sema, table, path, header_path)) {
                    if (g_steps) {
                        printf("C header written to %s\n", header_path);
                    }
                } else {
                    fprintf(stderr, "error: cannot write '%s'\n", header_path);
                    wrote = 0;
                }
            }
            status = wrote ? 0 : 1;
        }
    }

    table_free(table);
    conflicts_free(conflicts);
    sema_free(sema);
    ast_free(prog);
    free(tokens);
    free(src);
    return status;
}
