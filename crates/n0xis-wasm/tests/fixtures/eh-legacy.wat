;; Copyright (c) 2026 Tymofii Kosovskyi
;; SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
;;
;; Legacy exception handling (`try`, `catch`, `catch_all`, `delegate`,
;; `rethrow`), what LLVM still emits by default for C++ exceptions, and no
;; `exnref` instruction (V8 refuses a module that mixes the two): `try` with one
;; `catch`, with several, with `catch_all` alone, with both, and with no handler
;; at all; `try ... delegate` to an enclosing `try`, to an enclosing `block`,
;; and to the function's own label (the depth is the number of enclosing
;; frames: 0 at the top level, 2 inside a `block` and a `try`); `rethrow` from a
;; handler at depth 0 and from blocks nested in one; `try`s nested three deep;
;; block types of all three kinds on `try`, and one with a parameter. A
;; `delegate` closes its `try`, so no `end` follows it.
;;
;; Function bodies are written one canonical instruction per line (see
;; `src/instr.rs`); `tests/instructions.rs` reads them back from here.
(module $eh_legacy
  (type $nothing (func))
  (type $code (func (param i32)))
  (type $pair (func (param i32 i64)))
  (type $run (func (param i32) (result i32)))
  (type $two (func (result i32 i64)))
  (tag $code (type $code))
  (tag $pair (type $pair))
  (tag $empty (type $nothing))
  (export "handlers" (func $handlers))

  (func $throws (type $run) (param $n i32) (result i32)
    local.get 0
    i32.eqz
    if
      throw 2
    end
    local.get 0
    i32.const 1
    i32.eq
    if
      local.get 0
      throw 0
    end
    local.get 0
    i64.const 7
    throw 1
  )

  (func $handlers (type $run) (param $n i32) (result i32)
    try (result i32)
      local.get 0
      call 0
    catch 0
    end
    drop
    try (result i32)
      local.get 0
      call 0
    catch 0
    catch 1
      drop
    catch 2
      i32.const 2
    end
    drop
    try
      local.get 0
      call 0
      drop
    catch_all
    end
    try (result i32)
      local.get 0
      call 0
    catch 1
      drop
    catch_all
      i32.const -1
    end
    drop
    try
      local.get 0
      call 0
      drop
    end
    try (type 4)
      local.get 0
      call 0
      i64.const 0
    catch 1
    end
    drop
    drop
    local.get 0
    try (type 3)
      call 0
    catch 0
      i32.const 1
      i32.add
    end
  )

  (func $delegates (type $run) (param $n i32) (result i32)
    try (result i32)
      try
        local.get 0
        call 0
        drop
      delegate 0
      local.get 0
    catch_all
      i32.const 0
    end
    drop
    block
      try
        local.get 0
        call 0
        drop
      delegate 0
    end
    block
      try
        try
          local.get 0
          call 0
          drop
        delegate 2
      catch_all
      end
    end
    try
      local.get 0
      call 0
      drop
    delegate 0
    local.get 0
  )

  (func $rethrows (type $run) (param $n i32) (result i32)
    try (result i32)
      local.get 0
      call 0
    catch 0
      drop
      rethrow 0
    end
    drop
    try
      local.get 0
      call 0
      drop
    catch_all
      block
        local.get 0
        if
          rethrow 2
        end
        rethrow 1
      end
    end
    try
      local.get 0
      call 0
      drop
    catch 0
      drop
      try
        local.get 0
        call 0
        drop
      catch_all
        rethrow 1
      end
    end
    local.get 0
  )

  (func $nested (type $run) (param $n i32) (result i32)
    try (result i32)
      try (result i32)
        try (result i32)
          local.get 0
          call 0
        catch 2
          i32.const 3
        end
      catch 0
      end
    catch_all
      i32.const -1
    end
  )
)
