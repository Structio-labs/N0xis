;; Copyright (c) 2026 Tymofii Kosovskyi
;; SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
;;
;; A data segment and an element segment placed by an imported global, which
;; the format allows and whose value is the host's at instantiation; one of
;; each placed by a constant beside them. Assembled by `build.sh`.
(module
  (import "env" "base" (global $base i32))
  (import "env" "slot" (global $slot i32))
  (memory 1)
  (table 4 funcref)
  (func $f)
  (data (global.get $base) "hosted")
  (data (i32.const 64) "fixed")
  (elem (global.get $slot) func $f)
  (elem (i32.const 2) func $f))
