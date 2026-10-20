;; Copyright (c) 2026 Tymofii Kosovskyi
;; SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
;;
;; Threads: every opcode of the atomic space (prefix 0xFE, all 67), each at
;; least once, over four memories: an imported shared memory (memory 0), a
;; shared 64-bit memory (1), a memory that is not shared (2) and a shared memory
;; defined here (3). Every atomic access states its natural alignment, which
;; validation requires; the memory index is in the memory argument whenever it
;; is not 0. The 64-bit memory has atomic offsets past 4 GiB, up to 2^64 - 4,
;; and the 32-bit ones an offset of 2^32 - 1. `memory.atomic.notify`,
;; `memory.atomic.wait32` and `memory.atomic.wait64` are used on all four
;; memories, and `atomic.fence` (its reserved byte is in the file, not in the
;; text) twice.
;;
;; Function bodies are written one canonical instruction per line (see
;; `src/instr.rs`); `tests/instructions.rs` reads them back from here.
(module $threads
  (type $sync (func (param i32 i64) (result i32)))
  (type $access (func (param i32 i64)))
  (type $wide_access (func (param i64 i64) (result i64)))
  (type $narrow_access (func (param i32) (result i32)))
  (import "env" "memory" (memory $imported 1 16 shared))
  (memory $wide i64 1 65536 shared)
  (memory $private 1 2)
  (memory $own 1 1 shared)
  (export "wide" (memory $wide))
  (export "sync" (func $sync))

  (func $sync (type $sync) (param $address i32) (param $expected i64) (result i32)
    local.get 0
    i32.const 1
    memory.atomic.notify offset=0 align=4
    drop
    local.get 0
    i32.const 0
    i64.const -1
    memory.atomic.wait32 offset=4 align=4
    drop
    local.get 0
    local.get 1
    i64.const 1000000
    memory.atomic.wait64 offset=8 align=8
    drop
    atomic.fence
    i64.const 0
    i32.const 2
    memory.atomic.notify 1 offset=4294967296 align=4
    drop
    i64.const 0
    i32.const 7
    i64.const 0
    memory.atomic.wait32 1 offset=4294967300 align=4
    drop
    i64.const 0
    local.get 1
    i64.const 0
    memory.atomic.wait64 1 offset=4294967304 align=8
    drop
    local.get 0
    i32.const 3
    memory.atomic.notify 2 offset=16 align=4
    drop
    local.get 0
    i32.const 0
    i64.const 0
    memory.atomic.wait32 2 offset=20 align=4
    drop
    local.get 0
    local.get 1
    i64.const 0
    memory.atomic.wait64 2 offset=24 align=8
    drop
    atomic.fence
    local.get 0
    i32.const -1
    memory.atomic.notify 3 offset=32 align=4
    drop
    local.get 0
    i32.const 0
    i64.const -1
    memory.atomic.wait32 3 offset=36 align=4
    drop
    local.get 0
    local.get 1
    i64.const -1
    memory.atomic.wait64 3 offset=40 align=8
  )

  (func $loads_and_stores (type $access) (param $address i32) (param $value i64)
    local.get 0
    i32.atomic.load offset=0 align=4
    drop
    local.get 0
    i64.atomic.load offset=8 align=8
    drop
    local.get 0
    i32.atomic.load8_u offset=16 align=1
    drop
    local.get 0
    i32.atomic.load16_u offset=18 align=2
    drop
    local.get 0
    i64.atomic.load8_u offset=20 align=1
    drop
    local.get 0
    i64.atomic.load16_u offset=22 align=2
    drop
    local.get 0
    i64.atomic.load32_u offset=4294967292 align=4
    drop
    local.get 0
    i32.const -1
    i32.atomic.store offset=24 align=4
    local.get 0
    local.get 1
    i64.atomic.store offset=32 align=8
    local.get 0
    i32.const 255
    i32.atomic.store8 offset=40 align=1
    local.get 0
    i32.const 65535
    i32.atomic.store16 offset=42 align=2
    local.get 0
    local.get 1
    i64.atomic.store8 offset=4294967295 align=1
    local.get 0
    local.get 1
    i64.atomic.store16 offset=46 align=2
    local.get 0
    local.get 1
    i64.atomic.store32 offset=48 align=4
  )

  (func $read_modify_write (type $access) (param $address i32) (param $value i64)
    local.get 0
    i32.const -20
    i32.atomic.rmw.add offset=0 align=4
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw.add offset=8 align=8
    drop
    local.get 0
    i32.const -14
    i32.atomic.rmw8.add_u offset=16 align=1
    drop
    local.get 0
    i32.const -11
    i32.atomic.rmw16.add_u offset=24 align=2
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw8.add_u offset=32 align=1
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw16.add_u offset=40 align=2
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw32.add_u offset=48 align=4
    drop
    local.get 0
    i32.const 1
    i32.atomic.rmw.sub offset=56 align=4
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw.sub offset=64 align=8
    drop
    local.get 0
    i32.const 7
    i32.atomic.rmw8.sub_u offset=72 align=1
    drop
    local.get 0
    i32.const 10
    i32.atomic.rmw16.sub_u offset=80 align=2
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw8.sub_u offset=88 align=1
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw16.sub_u offset=96 align=2
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw32.sub_u offset=104 align=4
    drop
    local.get 0
    i32.const 22
    i32.atomic.rmw.and offset=112 align=4
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw.and offset=120 align=8
    drop
    local.get 0
    i32.const 28
    i32.atomic.rmw8.and_u offset=128 align=1
    drop
    local.get 0
    i32.const 31
    i32.atomic.rmw16.and_u offset=136 align=2
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw8.and_u offset=144 align=1
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw16.and_u offset=152 align=2
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw32.and_u offset=160 align=4
    drop
    local.get 0
    i32.const 43
    i32.atomic.rmw.or offset=168 align=4
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw.or offset=176 align=8
    drop
    local.get 0
    i32.const 49
    i32.atomic.rmw8.or_u offset=184 align=1
    drop
    local.get 0
    i32.const 52
    i32.atomic.rmw16.or_u offset=192 align=2
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw8.or_u offset=200 align=1
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw16.or_u offset=208 align=2
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw32.or_u offset=216 align=4
    drop
    local.get 0
    i32.const 64
    i32.atomic.rmw.xor offset=224 align=4
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw.xor offset=232 align=8
    drop
    local.get 0
    i32.const 70
    i32.atomic.rmw8.xor_u offset=240 align=1
    drop
    local.get 0
    i32.const 73
    i32.atomic.rmw16.xor_u offset=248 align=2
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw8.xor_u offset=256 align=1
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw16.xor_u offset=264 align=2
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw32.xor_u offset=272 align=4
    drop
    local.get 0
    i32.const 85
    i32.atomic.rmw.xchg offset=280 align=4
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw.xchg offset=288 align=8
    drop
    local.get 0
    i32.const 91
    i32.atomic.rmw8.xchg_u offset=296 align=1
    drop
    local.get 0
    i32.const 94
    i32.atomic.rmw16.xchg_u offset=304 align=2
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw8.xchg_u offset=312 align=1
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw16.xchg_u offset=320 align=2
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw32.xchg_u offset=328 align=4
    drop
    local.get 0
    i32.const 106
    i32.const 107
    i32.atomic.rmw.cmpxchg offset=336 align=4
    drop
    local.get 0
    local.get 1
    i64.const -43001
    i64.atomic.rmw.cmpxchg offset=344 align=8
    drop
    local.get 0
    i32.const 112
    i32.const 113
    i32.atomic.rmw8.cmpxchg_u offset=352 align=1
    drop
    local.get 0
    i32.const 115
    i32.const 116
    i32.atomic.rmw16.cmpxchg_u offset=360 align=2
    drop
    local.get 0
    local.get 1
    i64.const -46001
    i64.atomic.rmw8.cmpxchg_u offset=368 align=1
    drop
    local.get 0
    local.get 1
    i64.const -47001
    i64.atomic.rmw16.cmpxchg_u offset=376 align=2
    drop
    local.get 0
    local.get 1
    i64.const -48001
    i64.atomic.rmw32.cmpxchg_u offset=384 align=4
    drop
  )

  (func $wide (type $wide_access) (param $address i64) (param $value i64) (result i64)
    local.get 0
    i32.atomic.load 1 offset=4294967296 align=4
    drop
    local.get 0
    i64.atomic.load 1 offset=4294967304 align=8
    drop
    local.get 0
    i64.atomic.load32_u 1 offset=18446744073709551612 align=4
    drop
    local.get 0
    local.get 1
    i64.atomic.store 1 offset=8589934592 align=8
    local.get 0
    i32.const 1
    i32.atomic.store16 1 offset=4294967298 align=2
    local.get 0
    i32.const 1
    i32.atomic.rmw.add 1 offset=4294967296 align=4
    drop
    local.get 0
    local.get 1
    i64.atomic.rmw8.xchg_u 1 offset=4294967297 align=1
    drop
    local.get 0
    local.get 1
    i64.const 0
    i64.atomic.rmw.cmpxchg 1 offset=1099511627776 align=8
  )

  (func $private (type $narrow_access) (param $address i32) (result i32)
    local.get 0
    i32.atomic.load 2 offset=0 align=4
    drop
    local.get 0
    i64.const 5
    i64.atomic.store32 2 offset=4 align=4
    local.get 0
    i32.const 1
    i32.atomic.rmw16.sub_u 2 offset=8 align=2
    drop
    local.get 0
    i64.const 0
    i64.const 1
    i64.atomic.rmw32.cmpxchg_u 2 offset=8 align=4
    drop
    local.get 0
    i32.const 1
    i32.atomic.rmw8.and_u 2 offset=12 align=1
  )

  (func $own (type $narrow_access) (param $address i32) (result i32)
    local.get 0
    i64.atomic.load16_u 3 offset=2 align=2
    drop
    local.get 0
    i32.const 7
    i32.atomic.store8 3 offset=1 align=1
    local.get 0
    i64.const 1
    i64.atomic.rmw.or 3 offset=8 align=8
    drop
    local.get 0
    i32.const 0
    i32.const 1
    i32.atomic.rmw.cmpxchg 3 offset=16 align=4
  )
)
