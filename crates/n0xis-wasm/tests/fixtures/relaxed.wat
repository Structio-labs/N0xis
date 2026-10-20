;; Copyright (c) 2026 Tymofii Kosovskyi
;; SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
;;
;; Relaxed SIMD: the twenty opcodes of the 0xFD space from 0x100 to 0x113, each
;; once, in opcode order; each code is a two-byte LEB128 after the prefix. None
;; has an immediate. The first function drops every result; the second feeds
;; each result into the next instruction.
;;
;; Function bodies are written one canonical instruction per line (see
;; `src/instr.rs`); `tests/instructions.rs` reads them back from here.
(module $relaxed
  (type $lanes (func (param v128 v128 v128) (result v128)))

  (func $each (type $lanes) (param $a v128) (param $b v128) (param $c v128) (result v128)
    local.get 0
    local.get 1
    i8x16.relaxed_swizzle
    drop
    local.get 0
    i32x4.relaxed_trunc_f32x4_s
    drop
    local.get 0
    i32x4.relaxed_trunc_f32x4_u
    drop
    local.get 0
    i32x4.relaxed_trunc_f64x2_s_zero
    drop
    local.get 0
    i32x4.relaxed_trunc_f64x2_u_zero
    drop
    local.get 0
    local.get 1
    local.get 2
    f32x4.relaxed_madd
    drop
    local.get 0
    local.get 1
    local.get 2
    f32x4.relaxed_nmadd
    drop
    local.get 0
    local.get 1
    local.get 2
    f64x2.relaxed_madd
    drop
    local.get 0
    local.get 1
    local.get 2
    f64x2.relaxed_nmadd
    drop
    local.get 0
    local.get 1
    local.get 2
    i8x16.relaxed_laneselect
    drop
    local.get 0
    local.get 1
    local.get 2
    i16x8.relaxed_laneselect
    drop
    local.get 0
    local.get 1
    local.get 2
    i32x4.relaxed_laneselect
    drop
    local.get 0
    local.get 1
    local.get 2
    i64x2.relaxed_laneselect
    drop
    local.get 0
    local.get 1
    f32x4.relaxed_min
    drop
    local.get 0
    local.get 1
    f32x4.relaxed_max
    drop
    local.get 0
    local.get 1
    f64x2.relaxed_min
    drop
    local.get 0
    local.get 1
    f64x2.relaxed_max
    drop
    local.get 0
    local.get 1
    i16x8.relaxed_q15mulr_s
    drop
    local.get 0
    local.get 1
    i16x8.relaxed_dot_i8x16_i7x16_s
    drop
    local.get 0
    local.get 1
    local.get 2
    i32x4.relaxed_dot_i8x16_i7x16_add_s
  )

  (func $chained (type $lanes) (param $a v128) (param $b v128) (param $c v128) (result v128)
    local.get 0
    i32x4.relaxed_trunc_f32x4_u
    local.get 1
    i8x16.relaxed_swizzle
    local.get 1
    local.get 2
    f64x2.relaxed_nmadd
    local.get 2
    f32x4.relaxed_max
    i32x4.relaxed_trunc_f64x2_s_zero
    local.get 0
    local.get 2
    i32x4.relaxed_dot_i8x16_i7x16_add_s
  )
)
