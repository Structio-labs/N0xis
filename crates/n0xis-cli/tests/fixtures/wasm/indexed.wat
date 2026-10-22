;; Copyright (c) 2026 Tymofii Kosovskyi
;; SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
;;
;; Every way code names a function by index, planted: a call and a tail call
;; to an imported function (an index, no body), a call and a tail call to a
;; defined one, a `ref.func`, and an element segment; names that are not
;; identifiers (`a-b` beside `a_b`, `legalstub$x`); a function exported
;; under two names (`twice`, `twice_alias`); and a `br_table` of 40 labels,
;; an instruction of 42 bytes.
(module
  (import "env" "imp" (func $imp (param i32) (result i32)))
  (table 4 funcref)
  (elem (i32.const 0) $target $imp)
  (func $target (param i32) (result i32) (local.get 0))
  (func $"a-b" (export "caller") (param i32) (result i32)
    (drop (call $imp (local.get 0)))
    (drop (call $target (local.get 0)))
    (drop (ref.func $target))
    (return_call $target (local.get 0)))
  (func $a_b (param i32) (result i32)
    (return_call $imp (local.get 0)))
  (func $"legalstub$x" (export "twice") (export "twice_alias") (param i32) (result i32)
    (call_indirect (param i32) (result i32) (local.get 0) (i32.const 0)))
  (func $switch (param i32) (result i32)
    (block
      (br_table 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 (local.get 0)))
    (i32.const 7))
  (elem declare func $target)
)
