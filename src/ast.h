#ifndef AST_H
#define AST_H

#include <assert.h>
#include <stddef.h>

#define AST_NAME_LEN 64

/* ------------------------------------------------------------------
   Node kinds. Every node stores one of these as its first field.
   This tag is what makes RTTI possible in C.
   ------------------------------------------------------------------ */
typedef enum {
    NODE_PROGRAM,
    NODE_ROLE_DECL,
    NODE_RESOURCE_DECL,
    NODE_ACTION_DECL,
    NODE_ALLOW_RULE,
    NODE_DENY_RULE,
    NODE_ASSERTION
} NodeKind;

/* "Base class". Every concrete node struct has a Node as its FIRST member,
   so a pointer to any node can safely be treated as a Node *. */
typedef struct {
    NodeKind kind;
    int line;
    int col;
} Node;

/* program -> decl* rule*   (items are stored in file order) */
typedef struct {
    Node base;
    Node **items;
    int count;
    int capacity;
} Program;

/* role Manager : Employee;   (parent is optional) */
typedef struct {
    Node base;
    char name[AST_NAME_LEN];
    int has_parent;
    char parent[AST_NAME_LEN];
} RoleDecl;

/* resource Salary_Records; */
typedef struct {
    Node base;
    char name[AST_NAME_LEN];
} ResourceDecl;

/* action read; */
typedef struct {
    Node base;
    char name[AST_NAME_LEN];
} ActionDecl;

/* How a rule names its resource:
   RES_EXACT  -> Salary_Records
   RES_PREFIX -> Salary_*        (res_text holds "Salary_")
   RES_ANY    -> *               (res_text is empty)              */
typedef enum {
    RES_EXACT,
    RES_PREFIX,
    RES_ANY
} ResourceKind;

/* Allow/Deny rule: <effect> <role> to <action> <resource>;
   AllowRule and DenyRule share one layout. Only base.kind differs. */
typedef struct {
    Node base;
    int rule_id;                 /* 1, 2, 3 ... in file order */
    char role[AST_NAME_LEN];
    char action[AST_NAME_LEN];
    ResourceKind res_kind;
    char res_text[AST_NAME_LEN];
} Rule;

typedef Rule AllowRule;
typedef Rule DenyRule;

/* Security assertion, checked statically by the compiler:
     assert Intern cannot write Salary_*;
     assert every role can read Public_Notice;
     assert no role can delete Server_Logs;           */
typedef enum {
    SUBJ_ROLE,        /* one named role            */
    SUBJ_EVERY_ROLE,  /* "every role"              */
    SUBJ_NO_ROLE      /* "no role" (always "can")  */
} AssertSubject;

typedef struct {
    Node base;
    int assert_id;               /* 1, 2, 3 ... in file order        */
    AssertSubject subject;
    char role[AST_NAME_LEN];     /* only for SUBJ_ROLE               */
    int expect_allowed;          /* 1 = "can", 0 = "cannot"/"no role" */
    char action[AST_NAME_LEN];
    ResourceKind res_kind;
    char res_text[AST_NAME_LEN];
} Assertion;

/* ------------------------------------------------------------------
   LLVM-style RTTI, done by hand.
   Each type has a classof() that answers "is this node of my type?".
   Rule is a small hierarchy: Rule covers both AllowRule and DenyRule,
   exactly like LLVM's range-style classof().
   ------------------------------------------------------------------ */
static inline int Program_classof(const Node *n)      { return n->kind == NODE_PROGRAM; }
static inline int RoleDecl_classof(const Node *n)     { return n->kind == NODE_ROLE_DECL; }
static inline int ResourceDecl_classof(const Node *n) { return n->kind == NODE_RESOURCE_DECL; }
static inline int ActionDecl_classof(const Node *n)   { return n->kind == NODE_ACTION_DECL; }
static inline int AllowRule_classof(const Node *n)    { return n->kind == NODE_ALLOW_RULE; }
static inline int DenyRule_classof(const Node *n)     { return n->kind == NODE_DENY_RULE; }
static inline int Assertion_classof(const Node *n)    { return n->kind == NODE_ASSERTION; }
static inline int Rule_classof(const Node *n) {
    return n->kind == NODE_ALLOW_RULE || n->kind == NODE_DENY_RULE;
}

/* ISA(Type, n)      -> 1 if n is a Type, else 0
   CAST(Type, n)     -> n as a Type *   (asserts that ISA is true)
   DYN_CAST(Type, n) -> n as a Type *, or NULL if it is not a Type
   AS_NODE(x)        -> any concrete node pointer as a Node *
   Note: n is evaluated more than once, so do not pass expressions
   with side effects (like p++).                                      */
#define ISA(Type, n)      (Type##_classof((const Node *)(n)))
#define CAST(Type, n)     (assert(ISA(Type, n)), (Type *)(n))
#define DYN_CAST(Type, n) (ISA(Type, n) ? (Type *)(n) : (Type *)0)
#define AS_NODE(x)        (&(x)->base)

/* ------------------------------------------------------------------
   Constructors and helpers (implemented in ast.c)
   ------------------------------------------------------------------ */
Program      *program_new(void);
void          program_add(Program *p, Node *item);

/* parent may be NULL when the role has no parent */
RoleDecl     *role_decl_new(const char *name, const char *parent, int line, int col);
ResourceDecl *resource_decl_new(const char *name, int line, int col);
ActionDecl   *action_decl_new(const char *name, int line, int col);

/* kind must be NODE_ALLOW_RULE or NODE_DENY_RULE */
Rule         *rule_new(NodeKind kind, int rule_id, const char *role,
                       const char *action, ResourceKind res_kind,
                       const char *res_text, int line, int col);

/* subject: SUBJ_ROLE needs role; for SUBJ_NO_ROLE expect_allowed is 0 */
Assertion    *assertion_new(int assert_id, AssertSubject subject, const char *role,
                            int expect_allowed, const char *action,
                            ResourceKind res_kind, const char *res_text,
                            int line, int col);

/* Write an assertion back as source text, e.g. "Intern cannot write Salary_*" */
void          assertion_to_text(const Assertion *a, char *buf, size_t len);

/* Print the tree as indented text. */
void          ast_dump(const Program *p);

/* Free the program and every node inside it. */
void          ast_free(Program *p);

#endif
