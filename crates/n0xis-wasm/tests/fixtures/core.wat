;; Copyright (c) 2026 Tymofii Kosovskyi
;; SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
;;
;; Every opcode of the instruction set outside the SIMD space, each at least
;; once: control, parametric, variable, table, memory, numeric, reference, the
;; saturating truncations and bulk memory, with immediates at their edges
;; (the extremes of each constant, every float class, a 32-bit offset at its
;; maximum, unaligned accesses, block types of all three kinds).
;;
;; Function bodies are written one canonical instruction per line (see
;; `src/instr.rs`); `tests/instructions.rs` reads them back from here. The
;; numeric run was laid out with the operand types of wabt's opcode table, so
;; that the module validates; its names and immediates are the ones written
;; here.
(module
  (type (;0;) (func))
  (type (;1;) (func (param i32) (result i32 i32)))
  (type (;2;) (func (param i32 i32) (result i32)))
  (type (;3;) (func (param i32 i64 f32 f64)))
  (memory 1 2)
  (table 4 8 funcref)
  (table 2 externref)
  (global (mut i32) (i32.const 0))
  (global (mut i64) (i64.const 0))
  (elem (i32.const 0) func 1 2)
  (elem func 1)
  (data (i32.const 0) "\00\01\02\03")
  (data "passive")

  (func (;0;) (type 2) (param i32 i32) (result i32)
    block
      nop
    end
    block (result i32)
      i32.const 1
    end
    drop
    local.get 0
    block (type 1)
      i32.const 6
    end
    drop
    drop
    loop
      local.get 0
      br_if 0
    end
    loop (result i64)
      i64.const 0
    end
    drop
    local.get 0
    if
      nop
    else
      nop
    end
    local.get 0
    if (result i32)
      i32.const 1
    else
      i32.const 2
    end
    drop
    local.get 1
    local.get 0
    if (type 1)
      i32.const 3
    else
      i32.const 4
    end
    drop
    drop
    local.get 0
    if
      unreachable
    end
    block
      block
        block
          local.get 0
          br_table 0 1 2 1
        end
        br 1
      end
      br 0
    end
    block
      local.get 0
      br_table 0
    end
    local.get 0
    local.get 1
    call 1
    drop
    local.get 0
    local.get 1
    i32.const 0
    call_indirect 0 (type 2)
    drop
    i32.const 7
    i32.const 8
    local.get 0
    select
    drop
    i64.const 7
    i64.const 8
    local.get 0
    select (result i64)
    drop
    ref.null extern
    ref.null extern
    local.get 0
    select (result externref)
    drop
    local.get 0
    local.set 1
    local.get 1
    local.tee 0
    drop
    global.get 0
    global.set 0
    global.get 1
    global.set 1
    local.get 0
    return
  )

  (func (;1;) (type 2) (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
  )

  (func (;2;) (type 3) (param i32 i64 f32 f64)
    i32.const 0
    drop
    i32.const -1
    drop
    i32.const 63
    drop
    i32.const -64
    drop
    i32.const 64
    drop
    i32.const -2147483648
    drop
    i32.const 2147483647
    drop
    i64.const 0
    drop
    i64.const -1
    drop
    i64.const -9223372036854775808
    drop
    i64.const 9223372036854775807
    drop
    i64.const 81985529216486895
    drop
    f32.const 0x1.8p+0
    drop
    f32.const -0x0p+0
    drop
    f32.const 0x0p+0
    drop
    f32.const 0x1p-149
    drop
    f32.const 0x1.fffffcp-127
    drop
    f32.const 0x1.fffffep+127
    drop
    f32.const inf
    drop
    f32.const -inf
    drop
    f32.const nan:0x400000
    drop
    f32.const -nan:0x1
    drop
    f64.const 0x1p+0
    drop
    f64.const -0x1.921fb54442d18p+1
    drop
    f64.const 0x1p-1074
    drop
    f64.const 0x1.fffffffffffffp+1023
    drop
    f64.const -inf
    drop
    f64.const nan:0x8000000000000
    drop
    f64.const -nan:0xfffffffffffff
    drop
    local.get 0
    i32.eqz
    drop
    local.get 0
    local.get 0
    i32.eq
    drop
    local.get 0
    local.get 0
    i32.ne
    drop
    local.get 0
    local.get 0
    i32.lt_s
    drop
    local.get 0
    local.get 0
    i32.lt_u
    drop
    local.get 0
    local.get 0
    i32.gt_s
    drop
    local.get 0
    local.get 0
    i32.gt_u
    drop
    local.get 0
    local.get 0
    i32.le_s
    drop
    local.get 0
    local.get 0
    i32.le_u
    drop
    local.get 0
    local.get 0
    i32.ge_s
    drop
    local.get 0
    local.get 0
    i32.ge_u
    drop
    local.get 1
    i64.eqz
    drop
    local.get 1
    local.get 1
    i64.eq
    drop
    local.get 1
    local.get 1
    i64.ne
    drop
    local.get 1
    local.get 1
    i64.lt_s
    drop
    local.get 1
    local.get 1
    i64.lt_u
    drop
    local.get 1
    local.get 1
    i64.gt_s
    drop
    local.get 1
    local.get 1
    i64.gt_u
    drop
    local.get 1
    local.get 1
    i64.le_s
    drop
    local.get 1
    local.get 1
    i64.le_u
    drop
    local.get 1
    local.get 1
    i64.ge_s
    drop
    local.get 1
    local.get 1
    i64.ge_u
    drop
    local.get 2
    local.get 2
    f32.eq
    drop
    local.get 2
    local.get 2
    f32.ne
    drop
    local.get 2
    local.get 2
    f32.lt
    drop
    local.get 2
    local.get 2
    f32.gt
    drop
    local.get 2
    local.get 2
    f32.le
    drop
    local.get 2
    local.get 2
    f32.ge
    drop
    local.get 3
    local.get 3
    f64.eq
    drop
    local.get 3
    local.get 3
    f64.ne
    drop
    local.get 3
    local.get 3
    f64.lt
    drop
    local.get 3
    local.get 3
    f64.gt
    drop
    local.get 3
    local.get 3
    f64.le
    drop
    local.get 3
    local.get 3
    f64.ge
    drop
    local.get 0
    i32.clz
    drop
    local.get 0
    i32.ctz
    drop
    local.get 0
    i32.popcnt
    drop
    local.get 0
    local.get 0
    i32.add
    drop
    local.get 0
    local.get 0
    i32.sub
    drop
    local.get 0
    local.get 0
    i32.mul
    drop
    local.get 0
    local.get 0
    i32.div_s
    drop
    local.get 0
    local.get 0
    i32.div_u
    drop
    local.get 0
    local.get 0
    i32.rem_s
    drop
    local.get 0
    local.get 0
    i32.rem_u
    drop
    local.get 0
    local.get 0
    i32.and
    drop
    local.get 0
    local.get 0
    i32.or
    drop
    local.get 0
    local.get 0
    i32.xor
    drop
    local.get 0
    local.get 0
    i32.shl
    drop
    local.get 0
    local.get 0
    i32.shr_s
    drop
    local.get 0
    local.get 0
    i32.shr_u
    drop
    local.get 0
    local.get 0
    i32.rotl
    drop
    local.get 0
    local.get 0
    i32.rotr
    drop
    local.get 1
    i64.clz
    drop
    local.get 1
    i64.ctz
    drop
    local.get 1
    i64.popcnt
    drop
    local.get 1
    local.get 1
    i64.add
    drop
    local.get 1
    local.get 1
    i64.sub
    drop
    local.get 1
    local.get 1
    i64.mul
    drop
    local.get 1
    local.get 1
    i64.div_s
    drop
    local.get 1
    local.get 1
    i64.div_u
    drop
    local.get 1
    local.get 1
    i64.rem_s
    drop
    local.get 1
    local.get 1
    i64.rem_u
    drop
    local.get 1
    local.get 1
    i64.and
    drop
    local.get 1
    local.get 1
    i64.or
    drop
    local.get 1
    local.get 1
    i64.xor
    drop
    local.get 1
    local.get 1
    i64.shl
    drop
    local.get 1
    local.get 1
    i64.shr_s
    drop
    local.get 1
    local.get 1
    i64.shr_u
    drop
    local.get 1
    local.get 1
    i64.rotl
    drop
    local.get 1
    local.get 1
    i64.rotr
    drop
    local.get 2
    f32.abs
    drop
    local.get 2
    f32.neg
    drop
    local.get 2
    f32.ceil
    drop
    local.get 2
    f32.floor
    drop
    local.get 2
    f32.trunc
    drop
    local.get 2
    f32.nearest
    drop
    local.get 2
    f32.sqrt
    drop
    local.get 2
    local.get 2
    f32.add
    drop
    local.get 2
    local.get 2
    f32.sub
    drop
    local.get 2
    local.get 2
    f32.mul
    drop
    local.get 2
    local.get 2
    f32.div
    drop
    local.get 2
    local.get 2
    f32.min
    drop
    local.get 2
    local.get 2
    f32.max
    drop
    local.get 2
    local.get 2
    f32.copysign
    drop
    local.get 3
    f64.abs
    drop
    local.get 3
    f64.neg
    drop
    local.get 3
    f64.ceil
    drop
    local.get 3
    f64.floor
    drop
    local.get 3
    f64.trunc
    drop
    local.get 3
    f64.nearest
    drop
    local.get 3
    f64.sqrt
    drop
    local.get 3
    local.get 3
    f64.add
    drop
    local.get 3
    local.get 3
    f64.sub
    drop
    local.get 3
    local.get 3
    f64.mul
    drop
    local.get 3
    local.get 3
    f64.div
    drop
    local.get 3
    local.get 3
    f64.min
    drop
    local.get 3
    local.get 3
    f64.max
    drop
    local.get 3
    local.get 3
    f64.copysign
    drop
    local.get 1
    i32.wrap_i64
    drop
    local.get 2
    i32.trunc_f32_s
    drop
    local.get 2
    i32.trunc_f32_u
    drop
    local.get 3
    i32.trunc_f64_s
    drop
    local.get 3
    i32.trunc_f64_u
    drop
    local.get 0
    i64.extend_i32_s
    drop
    local.get 0
    i64.extend_i32_u
    drop
    local.get 2
    i64.trunc_f32_s
    drop
    local.get 2
    i64.trunc_f32_u
    drop
    local.get 3
    i64.trunc_f64_s
    drop
    local.get 3
    i64.trunc_f64_u
    drop
    local.get 0
    f32.convert_i32_s
    drop
    local.get 0
    f32.convert_i32_u
    drop
    local.get 1
    f32.convert_i64_s
    drop
    local.get 1
    f32.convert_i64_u
    drop
    local.get 3
    f32.demote_f64
    drop
    local.get 0
    f64.convert_i32_s
    drop
    local.get 0
    f64.convert_i32_u
    drop
    local.get 1
    f64.convert_i64_s
    drop
    local.get 1
    f64.convert_i64_u
    drop
    local.get 2
    f64.promote_f32
    drop
    local.get 2
    i32.reinterpret_f32
    drop
    local.get 3
    i64.reinterpret_f64
    drop
    local.get 0
    f32.reinterpret_i32
    drop
    local.get 1
    f64.reinterpret_i64
    drop
    local.get 0
    i32.extend8_s
    drop
    local.get 0
    i32.extend16_s
    drop
    local.get 1
    i64.extend8_s
    drop
    local.get 1
    i64.extend16_s
    drop
    local.get 1
    i64.extend32_s
    drop
    local.get 2
    i32.trunc_sat_f32_s
    drop
    local.get 2
    i32.trunc_sat_f32_u
    drop
    local.get 3
    i32.trunc_sat_f64_s
    drop
    local.get 3
    i32.trunc_sat_f64_u
    drop
    local.get 2
    i64.trunc_sat_f32_s
    drop
    local.get 2
    i64.trunc_sat_f32_u
    drop
    local.get 3
    i64.trunc_sat_f64_s
    drop
    local.get 3
    i64.trunc_sat_f64_u
    drop
  )

  (func (;3;) (type 3) (param i32 i64 f32 f64)
    local.get 0
    i32.load offset=0 align=4
    drop
    local.get 0
    i64.load offset=8 align=8
    drop
    local.get 0
    f32.load offset=16 align=1
    drop
    local.get 0
    f64.load offset=24 align=8
    drop
    local.get 0
    i32.load8_s offset=1 align=1
    drop
    local.get 0
    i32.load8_u offset=4294967295 align=1
    drop
    local.get 0
    i32.load16_s offset=2 align=2
    drop
    local.get 0
    i32.load16_u offset=3 align=1
    drop
    local.get 0
    i64.load8_s offset=4 align=1
    drop
    local.get 0
    i64.load8_u offset=5 align=1
    drop
    local.get 0
    i64.load16_s offset=6 align=2
    drop
    local.get 0
    i64.load16_u offset=7 align=1
    drop
    local.get 0
    i64.load32_s offset=8 align=4
    drop
    local.get 0
    i64.load32_u offset=9 align=2
    drop
    local.get 0
    local.get 0
    i32.store offset=10 align=1
    local.get 0
    local.get 1
    i64.store offset=11 align=8
    local.get 0
    local.get 2
    f32.store offset=12 align=4
    local.get 0
    local.get 3
    f64.store offset=13 align=2
    local.get 0
    local.get 0
    i32.store8 offset=14 align=1
    local.get 0
    local.get 0
    i32.store16 offset=15 align=2
    local.get 0
    local.get 1
    i64.store8 offset=16 align=1
    local.get 0
    local.get 1
    i64.store16 offset=17 align=1
    local.get 0
    local.get 1
    i64.store32 offset=18 align=4
    memory.size
    drop
    i32.const 1
    memory.grow
    drop
    local.get 0
    i32.const 0
    i32.const 4
    memory.fill
    local.get 0
    i32.const 0
    i32.const 4
    memory.copy
    local.get 0
    i32.const 0
    i32.const 4
    memory.init 1
    data.drop 1
  )

  (func (;4;) (type 0)
    i32.const 0
    table.get 0
    drop
    i32.const 0
    ref.null func
    table.set 0
    i32.const 1
    table.get 1
    drop
    table.size 0
    drop
    ref.null func
    i32.const 1
    table.grow 0
    drop
    i32.const 0
    ref.null func
    i32.const 1
    table.fill 0
    i32.const 0
    i32.const 1
    i32.const 1
    table.copy 0 0
    i32.const 0
    i32.const 1
    i32.const 1
    table.copy 1 1
    i32.const 0
    i32.const 0
    i32.const 1
    table.init 0 1
    elem.drop 1
    ref.func 1
    ref.is_null
    drop
    ref.null extern
    ref.is_null
    drop
  )
)
