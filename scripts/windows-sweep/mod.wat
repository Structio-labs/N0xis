(module
  (import "env" "log" (func $log (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "N0XIS_WASM_MARKER_94\00")
  (func $add (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add)
  (func $mix (export "mix") (param i32) (result i32)
    local.get 0 i32.const 0x5bd1e995 i32.mul local.tee 0 call $log local.get 0)
  (func $looped (export "looped") (param i32) (result i32) (local i32)
    (block (loop
      local.get 0 i32.eqz br_if 1
      local.get 1 local.get 0 i32.add local.set 1
      local.get 0 i32.const 1 i32.sub local.set 0
      br 0))
    local.get 1)
)
