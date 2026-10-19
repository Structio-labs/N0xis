;; Copyright (c) 2026 Tymofii Kosovskyi
;; SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
;;
;; The module's structure, not its instruction set: an import of every kind,
;; the function, table, memory and global index spaces with imports ahead of
;; definitions, a 64-bit memory with an offset past 4 GiB, three memories in
;; use, a 64-bit table, all eight element segment forms and all three data
;; segment forms, a start function, an export of every kind, multiple results,
;; a typed `select`, and names for everything the name section can name.
;;
;; Function bodies are written one canonical instruction per line (see
;; `src/instr.rs`); `tests/instructions.rs` reads them back from here.
(module $shapes
  (type $pair (func (param i32) (result i32 i64)))
  (type $none (func))
  (type $unary (func (param f64) (result f64)))
  (type $addr64 (func (param i64) (result i32)))
  (import "env" "pair" (func $imported_pair (type $pair)))
  (import "env" "unary" (func $imported_unary (type $unary)))
  (import "env" "table" (table $imported_table 4 16 funcref))
  (import "env" "memory" (memory $imported_memory 1))
  (import "env" "counter" (global $imported_counter (mut i64)))
  (import "env" "scale" (global $imported_scale f32))
  (memory $wide i64 1 65536)
  (memory $second 2)
  (table $refs 3 externref)
  (table $wide_table i64 2 8 funcref)
  (global $state (mut i32) (i32.const 42))
  (global $vector v128 (v128.const i32x4 0x00000001 0x00000002 0x00000003 0x00000004))
  (global $entry funcref (ref.func $multi))
  (global $nothing externref (ref.null extern))
  (export "multi" (func $multi))
  (export "refs" (table $refs))
  (export "wide" (memory $wide))
  (export "state" (global $state))
  (export "imported_again" (func $imported_pair))
  (start $init)
  (elem $form0 (i32.const 0) func $multi $init)
  (elem $form1 func $multi)
  (elem $form2 (table $wide_table) (i64.const 1) func $init)
  (elem $form3 declare func $wide_access)
  (elem $form4 (i32.const 2) funcref (ref.func $multi) (ref.null func))
  (elem $form5 funcref (ref.func $init) (ref.null func))
  (elem $form6 (table $refs) (i32.const 0) externref (ref.null extern))
  (elem $form7 declare funcref (ref.func $init))
  (data $form0_data (i32.const 8) "abc")
  (data $passive_data "passive")
  (data $second_data (memory $second) (i32.const 16) "xyz")
  (data $far_data (memory $wide) (i64.const 4294967300) "far")

  (func $init (type $none)
    i32.const 1
    global.set 2
  )

  (func $multi (type $pair) (param $seed i32) (result i32 i64) (local $wide_local i64) (local $vec v128)
    local.get 0
    block $outer (type 0)
      i64.extend_i32_u
      local.set 1
      local.get 1
      i32.wrap_i64
      local.get 1
    end
    local.set 1
    i32.const 7
    local.get 0
    select (result i32)
    local.get 1
  )

  (func $wide_access (type $addr64) (param $address i64) (result i32) (local $sum i32) (local $lanes v128)
    local.get 0
    i32.load 1 offset=4294967300 align=4
    local.get 0
    i64.load8_u 1 offset=0 align=1
    i32.wrap_i64
    i32.add
    i32.const 64
    i32.load16_s 2 offset=4 align=2
    i32.add
    local.set 1
    local.get 0
    local.get 1
    i32.store 1 offset=8 align=4
    i32.const 16
    i32.const 0
    v128.load 2 offset=32 align=16
    v128.load32_lane 2 offset=4 align=4 3
    local.set 2
    i32.const 0
    local.get 2
    v128.store 2 offset=48 align=16
    memory.size 1
    drop
    i64.const 1
    memory.grow 1
    drop
    i32.const 1
    memory.grow 2
    drop
    i64.const 0
    i32.const 0
    i32.const 4
    memory.copy 1 2
    i32.const 0
    i32.const 255
    i32.const 4
    memory.fill 2
    i32.const 0
    i32.const 0
    i32.const 3
    memory.init 2 2
    i32.const 0
    i32.const 0
    i32.const 3
    memory.init 0
    i64.const 0
    table.get 2
    drop
    table.size 2
    drop
    local.get 1
  )
)
