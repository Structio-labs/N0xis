;; Copyright (c) 2026 Tymofii Kosovskyi
;; SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
;;
;; Typed function references and tail calls, kept to what wabt also reads
;; (concrete heap types and the abstract `func` and `extern`): `return_call`
;; (to a definition and to an import), `return_call_indirect` on table 0 and on
;; another table, `call_ref`, `return_call_ref`, `ref.as_non_null`,
;; `br_on_null`, `br_on_non_null`, `ref.func`, `ref.null` of a concrete type,
;; typed `select` with reference types, a table of `(ref null 1)` and a
;; non-null table of `(ref 1)` each with an initial value (the `0x40 0x00`
;; table form), a `table.copy` from the second into the first (destination
;; and source differ, so a reader that exchanged them is caught), globals of typed reference types, element segments of forms 5,
;; 6 and 7 with a concrete reference type, and parameters and locals of
;; `(ref null 1)`, `(ref 1)`, `(ref func)` and `(ref extern)`.
;;
;; Function bodies are written one canonical instruction per line (see
;; `src/instr.rs`); `tests/instructions.rs` reads them back from here.
(module $refs
  (type $binary (func (param i32 i32) (result i32)))
  (type $unary (func (param i32) (result i32)))
  (type $apply (func (param (ref null 1) i32) (result i32)))
  (type $pick (func (param (ref null 1) (ref 1) (ref func) (ref extern) i32) (result i32)))
  (import "env" "unary" (func $imported (type $unary)))
  (table $plain 4 funcref)
  (table $nullable 2 (ref null $unary) (ref.null 1))
  (table $non_null 2 (ref $unary) (ref.func 2))
  (global $maybe (mut (ref null $unary)) (ref.null 1))
  (global $always (ref $unary) (ref.func 3))
  (global $any_function (ref func) (ref.func 1))
  (export "pick" (func $pick))
  (export "always" (global $always))
  (elem $passive (ref null $unary) (item ref.func 2) (item ref.null 1))
  (elem $active (table $nullable) (i32.const 0) (ref $unary) (item ref.func 2) (item ref.func 3))
  (elem $declared declare (ref $binary) (item ref.func 1))

  (func $add (type $binary) (param $a i32) (param $b i32) (result i32)
    local.get 0
    local.get 1
    i32.add
  )

  (func $double (type $unary) (param $n i32) (result i32)
    local.get 0
    i32.const 2
    i32.mul
  )

  (func $triple (type $unary) (param $n i32) (result i32)
    local.get 0
    i32.const 3
    i32.mul
  )

  (func $countdown (type $unary) (param $n i32) (result i32)
    local.get 0
    i32.eqz
    if (result i32)
      i32.const 0
    else
      local.get 0
      i32.const 1
      i32.sub
      return_call 4
    end
  )

  (func $forward (type $unary) (param $n i32) (result i32)
    local.get 0
    return_call 0
  )

  (func $indirect (type $binary) (param $n i32) (param $slot i32) (result i32)
    local.get 1
    i32.eqz
    if
      local.get 0
      i32.const 0
      return_call_indirect 0 (type 1)
    end
    local.get 0
    local.get 1
    return_call_indirect 1 (type 1)
  )

  (func $apply (type $apply) (param $f (ref null 1)) (param $n i32) (result i32)
    local.get 1
    local.get 0
    call_ref 1
    local.get 0
    return_call_ref 1
  )

  (func $pick (type $pick) (param $maybe (ref null 1)) (param $sure (ref 1)) (param $some (ref func)) (param $outside (ref extern)) (param $n i32) (result i32) (local $chosen (ref null 1)) (local $known (ref 1)) (local $any (ref func)) (local $kept (ref extern))
    block
      local.get 0
      br_on_null 0
      local.set 6
    end
    block (result (ref 1))
      local.get 0
      br_on_non_null 0
      local.get 1
    end
    local.set 6
    local.get 0
    ref.as_non_null
    local.set 6
    local.get 0
    ref.null 1
    local.get 4
    select (result (ref null 1))
    local.set 5
    ref.func 2
    local.get 2
    local.get 4
    select (result (ref func))
    local.set 7
    ref.func 3
    ref.null func
    local.get 4
    select (result funcref)
    drop
    local.get 3
    local.set 8
    i32.const 0
    i32.const 0
    i32.const 1
    table.copy 1 2
    local.get 4
    local.get 6
    call_ref 1
  )
)
