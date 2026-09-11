// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The call-graph corpus for whole-program type propagation.
//
// Three calls, in the two shapes that matter: a callee that types itself from
// its own field accesses, a caller that only forwards the pointer, and a leaf
// that only forwards it further. Built with `-fno-inline` so the chain survives.
//
// The point is the **edges**. A call reaches the propagation pass in two forms —
// as a statement, and, once the optimizer folds a single-use result into its
// consumer, as an expression inside that consumer. Reading only the first saw
// one edge of three here, and a pass that propagates along a graph that is not
// the program's propagates nothing and reports success.

#include <stdint.h>
#define EXPORT __attribute__((visibility("default")))
struct node { uint64_t id; uint64_t weight; uint64_t tag; };

/* Types itself: it dereferences fields. */
static uint64_t knows(struct node *n) { return n->id * 3 + n->weight + n->tag; }
/* Cannot type itself: it only passes the pointer on. Only propagation FROM the
   callee can say what it is. */
static uint64_t blind_caller(struct node *n) { return knows(n) + 1; }
EXPORT uint64_t tf_backward(struct node *n) { return blind_caller(n) + 2; }

/* The other direction: the caller knows, the callee only passes it further. */
static uint64_t blind_leaf(struct node *n, uint64_t k) { return (uint64_t)(uintptr_t)n + k; }
EXPORT uint64_t tf_forward(struct node *n) { return blind_leaf(n, n->id + n->weight); }

/* --- the other call shape: through the PLT ---------------------------------
 *
 * The functions above are `static`, so the compiler calls them directly. An
 * **exported** function is different: in a shared object the linker routes even
 * a call to the image's own function through the PLT, so that `LD_PRELOAD` can
 * interpose. The call then reads `call <stub>`, and a pass that keys on the
 * callee's address sees an edge into a thunk with no body and drops it.
 *
 * That is not a corner: it is how every `-fPIC` shared library calls itself, so
 * it was most of the call graph of every real Linux target. These three exist so
 * that shape is in the corpus rather than only in the wild. */

uint64_t tf_plt_leaf(struct node *n);
uint64_t tf_plt_mid(struct node *n);

uint64_t tf_plt_leaf(struct node *n) { return n->id * 5 + n->weight; }
uint64_t tf_plt_mid(struct node *n) { return tf_plt_leaf(n) + 1; }
uint64_t tf_plt_root(struct node *n) { return tf_plt_mid(n) + 2; }
