;; Copyright (c) 2026 Tymofii Kosovskyi
;; SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
;;
;; Every opcode of the 128-bit SIMD space (prefix 0xFD), each at least once,
;; with lane indices across their ranges and memory arguments both aligned and
;; unaligned. Opcodes from 0x80 up are two-byte LEB128 codes after the prefix.
;;
;; Function bodies are written one canonical instruction per line (see
;; `src/instr.rs`); `tests/instructions.rs` reads them back from here. The run
;; was laid out with the operand types of wabt's opcode table, so that the
;; module validates; its names and immediates are the ones written here.
(module
  (memory 1)
  (func (param i32 i64 f32 f64 v128)
    local.get 0
    v128.load offset=16 align=1
    drop
    local.get 0
    v128.load8x8_s offset=32 align=8
    drop
    local.get 0
    v128.load8x8_u offset=48 align=1
    drop
    local.get 0
    v128.load16x4_s offset=64 align=8
    drop
    local.get 0
    v128.load16x4_u offset=80 align=1
    drop
    local.get 0
    v128.load32x2_s offset=96 align=8
    drop
    local.get 0
    v128.load32x2_u offset=112 align=1
    drop
    local.get 0
    v128.load8_splat offset=128 align=1
    drop
    local.get 0
    v128.load16_splat offset=144 align=1
    drop
    local.get 0
    v128.load32_splat offset=160 align=4
    drop
    local.get 0
    v128.load64_splat offset=176 align=1
    drop
    local.get 0
    local.get 4
    v128.store offset=192 align=16
    v128.const i32x4 0x03020100 0x07060504 0x0b0a0908 0x0f0e0d0c
    drop
    v128.const i32x4 0xffffffff 0x80000000 0x00000000 0x7fffffff
    drop
    local.get 4
    local.get 4
    i8x16.shuffle 0 17 2 19 4 21 6 23 8 25 10 27 12 29 14 31
    drop
    local.get 4
    local.get 4
    i8x16.swizzle
    drop
    local.get 0
    i8x16.splat
    drop
    local.get 0
    i16x8.splat
    drop
    local.get 0
    i32x4.splat
    drop
    local.get 1
    i64x2.splat
    drop
    local.get 2
    f32x4.splat
    drop
    local.get 3
    f64x2.splat
    drop
    local.get 4
    i8x16.extract_lane_s 14
    drop
    local.get 4
    i8x16.extract_lane_u 3
    drop
    local.get 4
    local.get 0
    i8x16.replace_lane 8
    drop
    local.get 4
    i16x8.extract_lane_s 5
    drop
    local.get 4
    i16x8.extract_lane_u 2
    drop
    local.get 4
    local.get 0
    i16x8.replace_lane 7
    drop
    local.get 4
    i32x4.extract_lane 0
    drop
    local.get 4
    local.get 0
    i32x4.replace_lane 1
    drop
    local.get 4
    i64x2.extract_lane 0
    drop
    local.get 4
    local.get 1
    i64x2.replace_lane 1
    drop
    local.get 4
    f32x4.extract_lane 0
    drop
    local.get 4
    local.get 2
    f32x4.replace_lane 1
    drop
    local.get 4
    f64x2.extract_lane 0
    drop
    local.get 4
    local.get 3
    f64x2.replace_lane 1
    drop
    local.get 4
    local.get 4
    i8x16.eq
    drop
    local.get 4
    local.get 4
    i8x16.ne
    drop
    local.get 4
    local.get 4
    i8x16.lt_s
    drop
    local.get 4
    local.get 4
    i8x16.lt_u
    drop
    local.get 4
    local.get 4
    i8x16.gt_s
    drop
    local.get 4
    local.get 4
    i8x16.gt_u
    drop
    local.get 4
    local.get 4
    i8x16.le_s
    drop
    local.get 4
    local.get 4
    i8x16.le_u
    drop
    local.get 4
    local.get 4
    i8x16.ge_s
    drop
    local.get 4
    local.get 4
    i8x16.ge_u
    drop
    local.get 4
    local.get 4
    i16x8.eq
    drop
    local.get 4
    local.get 4
    i16x8.ne
    drop
    local.get 4
    local.get 4
    i16x8.lt_s
    drop
    local.get 4
    local.get 4
    i16x8.lt_u
    drop
    local.get 4
    local.get 4
    i16x8.gt_s
    drop
    local.get 4
    local.get 4
    i16x8.gt_u
    drop
    local.get 4
    local.get 4
    i16x8.le_s
    drop
    local.get 4
    local.get 4
    i16x8.le_u
    drop
    local.get 4
    local.get 4
    i16x8.ge_s
    drop
    local.get 4
    local.get 4
    i16x8.ge_u
    drop
    local.get 4
    local.get 4
    i32x4.eq
    drop
    local.get 4
    local.get 4
    i32x4.ne
    drop
    local.get 4
    local.get 4
    i32x4.lt_s
    drop
    local.get 4
    local.get 4
    i32x4.lt_u
    drop
    local.get 4
    local.get 4
    i32x4.gt_s
    drop
    local.get 4
    local.get 4
    i32x4.gt_u
    drop
    local.get 4
    local.get 4
    i32x4.le_s
    drop
    local.get 4
    local.get 4
    i32x4.le_u
    drop
    local.get 4
    local.get 4
    i32x4.ge_s
    drop
    local.get 4
    local.get 4
    i32x4.ge_u
    drop
    local.get 4
    local.get 4
    f32x4.eq
    drop
    local.get 4
    local.get 4
    f32x4.ne
    drop
    local.get 4
    local.get 4
    f32x4.lt
    drop
    local.get 4
    local.get 4
    f32x4.gt
    drop
    local.get 4
    local.get 4
    f32x4.le
    drop
    local.get 4
    local.get 4
    f32x4.ge
    drop
    local.get 4
    local.get 4
    f64x2.eq
    drop
    local.get 4
    local.get 4
    f64x2.ne
    drop
    local.get 4
    local.get 4
    f64x2.lt
    drop
    local.get 4
    local.get 4
    f64x2.gt
    drop
    local.get 4
    local.get 4
    f64x2.le
    drop
    local.get 4
    local.get 4
    f64x2.ge
    drop
    local.get 4
    v128.not
    drop
    local.get 4
    local.get 4
    v128.and
    drop
    local.get 4
    local.get 4
    v128.andnot
    drop
    local.get 4
    local.get 4
    v128.or
    drop
    local.get 4
    local.get 4
    v128.xor
    drop
    local.get 4
    local.get 4
    local.get 4
    v128.bitselect
    drop
    local.get 4
    v128.any_true
    drop
    local.get 0
    local.get 4
    v128.load8_lane offset=1360 align=1 15
    drop
    local.get 0
    local.get 4
    v128.load16_lane offset=1376 align=2 2
    drop
    local.get 0
    local.get 4
    v128.load32_lane offset=1392 align=1 1
    drop
    local.get 0
    local.get 4
    v128.load64_lane offset=1408 align=8 0
    drop
    local.get 0
    local.get 4
    v128.store8_lane offset=1424 align=1 11
    local.get 0
    local.get 4
    v128.store16_lane offset=1440 align=2 6
    local.get 0
    local.get 4
    v128.store32_lane offset=1456 align=1 1
    local.get 0
    local.get 4
    v128.store64_lane offset=1472 align=8 0
    local.get 0
    v128.load32_zero offset=1488 align=1
    drop
    local.get 0
    v128.load64_zero offset=1504 align=8
    drop
    local.get 4
    f32x4.demote_f64x2_zero
    drop
    local.get 4
    f64x2.promote_low_f32x4
    drop
    local.get 4
    i8x16.abs
    drop
    local.get 4
    i8x16.neg
    drop
    local.get 4
    i8x16.popcnt
    drop
    local.get 4
    i8x16.all_true
    drop
    local.get 4
    i8x16.bitmask
    drop
    local.get 4
    local.get 4
    i8x16.narrow_i16x8_s
    drop
    local.get 4
    local.get 4
    i8x16.narrow_i16x8_u
    drop
    local.get 4
    local.get 0
    i8x16.shl
    drop
    local.get 4
    local.get 0
    i8x16.shr_s
    drop
    local.get 4
    local.get 0
    i8x16.shr_u
    drop
    local.get 4
    local.get 4
    i8x16.add
    drop
    local.get 4
    local.get 4
    i8x16.add_sat_s
    drop
    local.get 4
    local.get 4
    i8x16.add_sat_u
    drop
    local.get 4
    local.get 4
    i8x16.sub
    drop
    local.get 4
    local.get 4
    i8x16.sub_sat_s
    drop
    local.get 4
    local.get 4
    i8x16.sub_sat_u
    drop
    local.get 4
    local.get 4
    i8x16.min_s
    drop
    local.get 4
    local.get 4
    i8x16.min_u
    drop
    local.get 4
    local.get 4
    i8x16.max_s
    drop
    local.get 4
    local.get 4
    i8x16.max_u
    drop
    local.get 4
    local.get 4
    i8x16.avgr_u
    drop
    local.get 4
    i16x8.extadd_pairwise_i8x16_s
    drop
    local.get 4
    i16x8.extadd_pairwise_i8x16_u
    drop
    local.get 4
    i32x4.extadd_pairwise_i16x8_s
    drop
    local.get 4
    i32x4.extadd_pairwise_i16x8_u
    drop
    local.get 4
    i16x8.abs
    drop
    local.get 4
    i16x8.neg
    drop
    local.get 4
    local.get 4
    i16x8.q15mulr_sat_s
    drop
    local.get 4
    i16x8.all_true
    drop
    local.get 4
    i16x8.bitmask
    drop
    local.get 4
    local.get 4
    i16x8.narrow_i32x4_s
    drop
    local.get 4
    local.get 4
    i16x8.narrow_i32x4_u
    drop
    local.get 4
    i16x8.extend_low_i8x16_s
    drop
    local.get 4
    i16x8.extend_high_i8x16_s
    drop
    local.get 4
    i16x8.extend_low_i8x16_u
    drop
    local.get 4
    i16x8.extend_high_i8x16_u
    drop
    local.get 4
    local.get 0
    i16x8.shl
    drop
    local.get 4
    local.get 0
    i16x8.shr_s
    drop
    local.get 4
    local.get 0
    i16x8.shr_u
    drop
    local.get 4
    local.get 4
    i16x8.add
    drop
    local.get 4
    local.get 4
    i16x8.add_sat_s
    drop
    local.get 4
    local.get 4
    i16x8.add_sat_u
    drop
    local.get 4
    local.get 4
    i16x8.sub
    drop
    local.get 4
    local.get 4
    i16x8.sub_sat_s
    drop
    local.get 4
    local.get 4
    i16x8.sub_sat_u
    drop
    local.get 4
    local.get 4
    i16x8.mul
    drop
    local.get 4
    local.get 4
    i16x8.min_s
    drop
    local.get 4
    local.get 4
    i16x8.min_u
    drop
    local.get 4
    local.get 4
    i16x8.max_s
    drop
    local.get 4
    local.get 4
    i16x8.max_u
    drop
    local.get 4
    local.get 4
    i16x8.avgr_u
    drop
    local.get 4
    local.get 4
    i16x8.extmul_low_i8x16_s
    drop
    local.get 4
    local.get 4
    i16x8.extmul_high_i8x16_s
    drop
    local.get 4
    local.get 4
    i16x8.extmul_low_i8x16_u
    drop
    local.get 4
    local.get 4
    i16x8.extmul_high_i8x16_u
    drop
    local.get 4
    i32x4.abs
    drop
    local.get 4
    i32x4.neg
    drop
    local.get 4
    i32x4.all_true
    drop
    local.get 4
    i32x4.bitmask
    drop
    local.get 4
    i32x4.extend_low_i16x8_s
    drop
    local.get 4
    i32x4.extend_high_i16x8_s
    drop
    local.get 4
    i32x4.extend_low_i16x8_u
    drop
    local.get 4
    i32x4.extend_high_i16x8_u
    drop
    local.get 4
    local.get 0
    i32x4.shl
    drop
    local.get 4
    local.get 0
    i32x4.shr_s
    drop
    local.get 4
    local.get 0
    i32x4.shr_u
    drop
    local.get 4
    local.get 4
    i32x4.add
    drop
    local.get 4
    local.get 4
    i32x4.sub
    drop
    local.get 4
    local.get 4
    i32x4.mul
    drop
    local.get 4
    local.get 4
    i32x4.min_s
    drop
    local.get 4
    local.get 4
    i32x4.min_u
    drop
    local.get 4
    local.get 4
    i32x4.max_s
    drop
    local.get 4
    local.get 4
    i32x4.max_u
    drop
    local.get 4
    local.get 4
    i32x4.dot_i16x8_s
    drop
    local.get 4
    local.get 4
    i32x4.extmul_low_i16x8_s
    drop
    local.get 4
    local.get 4
    i32x4.extmul_high_i16x8_s
    drop
    local.get 4
    local.get 4
    i32x4.extmul_low_i16x8_u
    drop
    local.get 4
    local.get 4
    i32x4.extmul_high_i16x8_u
    drop
    local.get 4
    i64x2.abs
    drop
    local.get 4
    i64x2.neg
    drop
    local.get 4
    i64x2.all_true
    drop
    local.get 4
    i64x2.bitmask
    drop
    local.get 4
    i64x2.extend_low_i32x4_s
    drop
    local.get 4
    i64x2.extend_high_i32x4_s
    drop
    local.get 4
    i64x2.extend_low_i32x4_u
    drop
    local.get 4
    i64x2.extend_high_i32x4_u
    drop
    local.get 4
    local.get 0
    i64x2.shl
    drop
    local.get 4
    local.get 0
    i64x2.shr_s
    drop
    local.get 4
    local.get 0
    i64x2.shr_u
    drop
    local.get 4
    local.get 4
    i64x2.add
    drop
    local.get 4
    local.get 4
    i64x2.sub
    drop
    local.get 4
    local.get 4
    i64x2.mul
    drop
    local.get 4
    local.get 4
    i64x2.eq
    drop
    local.get 4
    local.get 4
    i64x2.ne
    drop
    local.get 4
    local.get 4
    i64x2.lt_s
    drop
    local.get 4
    local.get 4
    i64x2.gt_s
    drop
    local.get 4
    local.get 4
    i64x2.le_s
    drop
    local.get 4
    local.get 4
    i64x2.ge_s
    drop
    local.get 4
    local.get 4
    i64x2.extmul_low_i32x4_s
    drop
    local.get 4
    local.get 4
    i64x2.extmul_high_i32x4_s
    drop
    local.get 4
    local.get 4
    i64x2.extmul_low_i32x4_u
    drop
    local.get 4
    local.get 4
    i64x2.extmul_high_i32x4_u
    drop
    local.get 4
    f32x4.ceil
    drop
    local.get 4
    f32x4.floor
    drop
    local.get 4
    f32x4.trunc
    drop
    local.get 4
    f32x4.nearest
    drop
    local.get 4
    f64x2.ceil
    drop
    local.get 4
    f64x2.floor
    drop
    local.get 4
    f64x2.trunc
    drop
    local.get 4
    f64x2.nearest
    drop
    local.get 4
    f32x4.abs
    drop
    local.get 4
    f32x4.neg
    drop
    local.get 4
    f32x4.sqrt
    drop
    local.get 4
    local.get 4
    f32x4.add
    drop
    local.get 4
    local.get 4
    f32x4.sub
    drop
    local.get 4
    local.get 4
    f32x4.mul
    drop
    local.get 4
    local.get 4
    f32x4.div
    drop
    local.get 4
    local.get 4
    f32x4.min
    drop
    local.get 4
    local.get 4
    f32x4.max
    drop
    local.get 4
    local.get 4
    f32x4.pmin
    drop
    local.get 4
    local.get 4
    f32x4.pmax
    drop
    local.get 4
    f64x2.abs
    drop
    local.get 4
    f64x2.neg
    drop
    local.get 4
    f64x2.sqrt
    drop
    local.get 4
    local.get 4
    f64x2.add
    drop
    local.get 4
    local.get 4
    f64x2.sub
    drop
    local.get 4
    local.get 4
    f64x2.mul
    drop
    local.get 4
    local.get 4
    f64x2.div
    drop
    local.get 4
    local.get 4
    f64x2.min
    drop
    local.get 4
    local.get 4
    f64x2.max
    drop
    local.get 4
    local.get 4
    f64x2.pmin
    drop
    local.get 4
    local.get 4
    f64x2.pmax
    drop
    local.get 4
    i32x4.trunc_sat_f32x4_s
    drop
    local.get 4
    i32x4.trunc_sat_f32x4_u
    drop
    local.get 4
    f32x4.convert_i32x4_s
    drop
    local.get 4
    f32x4.convert_i32x4_u
    drop
    local.get 4
    i32x4.trunc_sat_f64x2_s_zero
    drop
    local.get 4
    i32x4.trunc_sat_f64x2_u_zero
    drop
    local.get 4
    f64x2.convert_low_i32x4_s
    drop
    local.get 4
    f64x2.convert_low_i32x4_u
    drop
  )
)
