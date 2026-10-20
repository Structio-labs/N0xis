;; Copyright (c) 2026 Tymofii Kosovskyi
;; SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
;;
;; Exception handling with `exnref`, and no legacy instruction (V8 refuses a
;; module that mixes the two): five tags of four types, one of them imported
;; and one exported, `throw` of each, `throw_ref`, `try_table` with no clause,
;; with each of the four clause kinds on its own and with all four at once,
;; `try_table`s nested two deep, block types of all three kinds on
;; `try_table`, `exnref` locals and parameters, `ref.null exn`, and a name for
;; every tag. (`ref.null noexn` is in gc.wat: wabt does not read heap type
;; 0x74, and this module is one wabt reads.)
;;
;; Function bodies are written one canonical instruction per line (see
;; `src/instr.rs`); `tests/instructions.rs` reads them back from here.
(module $eh
  (type $nothing (func))
  (type $code (func (param i32)))
  (type $pair (func (param i32 i64)))
  (type $object (func (param externref)))
  (type $run (func (param i32) (result i32)))
  (type $caught (func (result i32 exnref)))
  (type $caught_pair (func (result i32 i64 exnref)))
  (type $rethrow (func (param exnref)))
  (import "env" "failure" (tag $failure (type $code)))
  (tag $empty (type $nothing))
  (tag $code (type $code))
  (tag $pair (type $pair))
  (tag $object (type $object))
  (export "code" (tag $code))
  (export "run" (func $several))

  (func $throws (type $run) (param $n i32) (result i32)
    local.get 0
    i32.eqz
    if
      throw 1
    end
    local.get 0
    i32.const 1
    i32.eq
    if
      local.get 0
      throw 0
    end
    local.get 0
    i32.const 2
    i32.eq
    if
      local.get 0
      throw 2
    end
    local.get 0
    i64.const 7
    throw 3
  )

  (func $catch_each (type $run) (param $n i32) (result i32) (local $exn exnref)
    try_table
      local.get 0
      call 0
      drop
    end
    block (result i32)
      try_table (result i32) (catch 2 0)
        local.get 0
        call 0
      end
    end
    drop
    block (type 5)
      try_table (catch_ref 2 0)
        local.get 0
        call 0
        drop
      end
      i32.const 0
      ref.null exn
    end
    local.set 1
    drop
    block
      try_table (catch_all 0)
        local.get 0
        call 0
        drop
      end
    end
    block (result exnref)
      try_table (catch_all_ref 0)
        local.get 0
        call 0
        drop
      end
      ref.null exn
    end
    local.set 1
    local.get 0
  )

  (func $several (type $run) (param $n i32) (result i32) (local $exn exnref)
    block (result exnref)
      block
        block (type 6)
          block (result i32)
            try_table (result i32) (catch 2 0) (catch_ref 3 1) (catch_all 2) (catch_all_ref 3)
              local.get 0
              call 0
            end
            return
          end
          return
        end
        local.set 1
        drop
        drop
        i32.const -1
        return
      end
      i32.const -2
      return
    end
    throw_ref
  )

  (func $nested (type $run) (param $n i32) (result i32)
    block (result i32)
      try_table (result i32) (catch 0 0)
        block (result exnref)
          try_table (result i32) (catch_all_ref 0)
            local.get 0
            call 0
          end
          return
        end
        throw_ref
      end
    end
    local.set 0
    block
      local.get 0
      try_table (type 4) (catch_all 0)
        call 0
      end
      return
    end
    i32.const 0
  )

  (func $object (type $object) (param $value externref)
    local.get 0
    throw 4
  )

  (func $rethrow (type $rethrow) (param $exn exnref)
    local.get 0
    throw_ref
  )
)
