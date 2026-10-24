;; Two kinds of contradiction `n0x contradictions` reports, planted once each.
;;   name   function 1 is `internal_name` in the name section and exported
;;          as `exported_name`; function 0 is `agreed` in both.
;;   image  data segment 0 is placed at 65530 and holds 10 bytes, in a memory
;;          of exactly one page (65536 bytes): instantiation traps on it.
(module
  (memory 1 1)
  (func $agreed (export "agreed") (result i32) i32.const 0)
  (func $internal_name (export "exported_name") (result i32) i32.const 1)
  (data (i32.const 65530) "0123456789"))
