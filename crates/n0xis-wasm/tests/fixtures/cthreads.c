// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// C11 atomics and threads, as `clang -pthread` compiles them for wasm32:
// `_Atomic` variables of 8, 16, 32 and 64 bits, atomic loads and stores,
// `atomic_fetch_add`, `_sub`, `_and`, `_or` and `_xor`, `atomic_exchange`,
// `atomic_compare_exchange_strong`, `atomic_thread_fence`, the wait and notify
// builtins, `_Thread_local` variables (one initialised, one not) and
// initialised static data. `build.sh` compiles it at -O2 into a module that
// imports a shared memory; the linker adds the functions that initialise the
// memory and the thread-local block.
//
// Every function this file defines is defined on one line of the form
//     <type> <name>(<parameters>) { <body> }
// whose first word is one of the types below (u8, u16, u32, u64, i32, void),
// so a test finds them all by scanning for that shape.

#include <stdatomic.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef int i32;
typedef long long i64;

_Atomic u8 flag8;
_Atomic u16 count16 = 3;
_Atomic u32 count32 = 7;
_Atomic u64 count64 = 0x123456789ULL;
_Thread_local u32 per_thread = 5;
_Thread_local u64 per_thread_total;
u32 shared_table[4] = { 10, 20, 30, 40 };
static const u32 weights[4] = { 1, 2, 3, 4 };

u8 load8(void) { return atomic_load(&flag8); }
u16 load16(void) { return atomic_load(&count16); }
u32 load32(void) { return atomic_load(&count32); }
u64 load64(void) { return atomic_load(&count64); }
void store8(u8 v) { atomic_store(&flag8, v); }
void store16(u16 v) { atomic_store(&count16, v); }
void store32(u32 v) { atomic_store(&count32, v); }
void store64(u64 v) { atomic_store(&count64, v); }
u8 add8(u8 v) { return atomic_fetch_add(&flag8, v); }
u16 sub16(u16 v) { return atomic_fetch_sub(&count16, v); }
u32 and32(u32 v) { return atomic_fetch_and(&count32, v); }
u64 or64(u64 v) { return atomic_fetch_or(&count64, v); }
u32 xor32(u32 v) { return atomic_fetch_xor(&count32, v); }
u64 add64(u64 v) { return atomic_fetch_add(&count64, v); }
u16 exchange16(u16 v) { return atomic_exchange(&count16, v); }
u64 exchange64(u64 v) { return atomic_exchange(&count64, v); }
u8 swap8(u8 expected, u8 desired) { atomic_compare_exchange_strong(&flag8, &expected, desired); return expected; }
u32 swap32(u32 expected, u32 desired) { atomic_compare_exchange_strong(&count32, &expected, desired); return expected; }
u64 swap64(u64 expected, u64 desired) { atomic_compare_exchange_strong(&count64, &expected, desired); return expected; }
void fence(void) { atomic_thread_fence(memory_order_seq_cst); }
i32 wait32(i32 *address, i32 expected, i64 timeout) { return __builtin_wasm_memory_atomic_wait32(address, expected, timeout); }
i32 wait64(i64 *address, i64 expected, i64 timeout) { return __builtin_wasm_memory_atomic_wait64(address, expected, timeout); }
u32 notify(i32 *address, u32 count) { return __builtin_wasm_memory_atomic_notify(address, count); }
u32 bump_thread_local(u32 by) { per_thread += by; per_thread_total += by; return per_thread + shared_table[by & 3] + weights[by & 3]; }
