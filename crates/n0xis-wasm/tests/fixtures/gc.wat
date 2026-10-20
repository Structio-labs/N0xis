;; Copyright (c) 2026 Tymofii Kosovskyi
;; SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
;;
;; Garbage-collected types and every opcode of the 0xFB space (all 31), plus
;; `ref.eq`. Types: an empty recursion group, an explicit group of three types
;; that refer to one another, an explicit group of one, and bare types;
;; non-final types with and without a supertype, final types with one, for
;; structures and functions; a structure with a field of every storage type
;; (i8, i16, i32, i64, f32, f64, v128 and references), each both immutable and
;; mutable, and an empty structure; arrays of packed, numeric, vector and
;; reference elements. Instructions: `array.copy` within one type and between
;; two (into the mutable array of `(ref null $node)` from the immutable one of
;; `(ref null $tree)`, a subtype's references), so that a reader exchanging
;; its destination and source is caught; `ref.test` and `ref.cast` in both
;; nullabilities with abstract and concrete targets in three hierarchies;
;; `br_on_cast` and `br_on_cast_fail` with the three nullability combinations
;; validation allows (a cast from a non-null type to a nullable one is invalid,
;; since the target must match the source); `ref.null` of every abstract heap
;; type and of concrete ones. Parameters and locals of every abstract reference
;; type, nullable (which `wasm-tools parse` writes as the one-byte
;; abbreviation) and non-null. Globals initialised with GC constant
;; instructions and with extended constant arithmetic, a passive data segment
;; read by `array.new_data` and `array.init_data` (so a data count section),
;; an element segment of a concrete GC reference type, and a name for every
;; type and every structure field. wabt reads none of this.
;;
;; Function bodies are written one canonical instruction per line (see
;; `src/instr.rs`); `tests/instructions.rs` reads them back from here.
(module $gc
  (rec)
  (rec
    (type $node (sub (struct (field $value i32) (field $next (mut (ref null $node))))))
    (type $tree (sub $node (struct (field $value i32) (field $next (mut (ref null $node))) (field $left (ref null $tree)) (field $right (ref null $tree)))))
    (type $leaf (sub final $tree (struct (field $value i32) (field $next (mut (ref null $node))) (field $left (ref null $tree)) (field $right (ref null $tree)) (field $weight (mut i64))))))
  (rec (type $empty (struct)))
  (type $fields (struct (field $i8 i8) (field $mut_i8 (mut i8)) (field $i16 i16) (field $mut_i16 (mut i16)) (field $i32 i32) (field $mut_i32 (mut i32)) (field $i64 i64) (field $mut_i64 (mut i64)) (field $f32 f32) (field $mut_f32 (mut f32)) (field $f64 f64) (field $mut_f64 (mut f64)) (field $v128 v128) (field $mut_v128 (mut v128)) (field $any anyref) (field $mut_node (mut (ref null $node))) (field $small (ref i31)) (field $mut_func (mut funcref))))
  (type $bytes (array (mut i8)))
  (type $shorts (array i16))
  (type $longs (array (mut i64)))
  (type $trees (array (ref null $tree)))
  (type $vectors (array (mut v128)))
  (type $nodes (array (mut (ref null $node))))
  (type $functions (array funcref))
  (type $callback (sub (func (param i32) (result i32))))
  (type $narrow (sub final $callback (func (param i32) (result i32))))
  (type $structs (func (param i32 i64 f32 f64 v128) (result i32)))
  (type $arrays (func (param i32 i64) (result i32)))
  (type $casts (func (param anyref (ref any) eqref funcref externref) (result i32)))
  (type $conversions (func (param externref anyref i32) (result i32)))
  (type $nothing (func))
  (type $nullable (func (param funcref nullfuncref externref nullexternref anyref eqref i31ref structref arrayref nullref exnref nullexnref) (result i32)))
  (type $non_null (func (param (ref func) (ref nofunc) (ref extern) (ref noextern) (ref any) (ref eq) (ref i31) (ref struct) (ref array) (ref none) (ref exn) (ref noexn))))
  (global $answer i32 (i32.add (i32.const 40) (i32.const 2)))
  (global $product i64 (i64.mul (i64.const 6) (i64.const 7)))
  (global $mixed i64 (i64.sub (i64.add (i64.const 1) (i64.const 2)) (i64.mul (i64.const 3) (i64.const 4))))
  (global $derived i32 (i32.mul (global.get 0) (i32.sub (i32.const 3) (i32.const 1))))
  (global $small i31ref (ref.i31 (i32.const 7)))
  (global $single (ref $node) (struct.new 0 (i32.const 1) (ref.null 0)))
  (global $nothing (ref $empty) (struct.new_default 3))
  (global $three (ref $bytes) (array.new_fixed 5 3 (i32.const 1) (i32.const 2) (i32.const 3)))
  (global $zeros (ref $longs) (array.new_default 7 (i32.const 4)))
  (global $sevens (ref $longs) (array.new 7 (i64.const 7) (i32.const 2)))
  (global $outside externref (extern.convert_any (global.get 4)))
  (global $inside anyref (any.convert_extern (global.get 10)))
  (global $latest (mut (ref null $node)) (ref.null 0))
  (global $handler (ref $narrow) (ref.func 7))
  (global $leaf (ref $leaf) (struct.new 2 (i32.const 5) (ref.null 0) (ref.null 1) (ref.null 1) (i64.const 9)))
  (export "structs" (func $structs))
  (elem $callbacks funcref (item ref.func 7) (item ref.null func))
  (elem $node_items (ref null $node) (item ref.null 0) (item struct.new_default 0))
  (data $bytes_data "\01\02\03\04\05\06\07\08")

  (func $structs (type $structs) (param $small i32) (param $big i64) (param $single f32) (param $double f64) (param $lanes v128) (result i32) (local $node (ref null $node)) (local $all (ref null $fields)) (local $leaf (ref null $leaf))
    i32.const 1
    ref.null 0
    struct.new 0
    local.set 5
    local.get 5
    local.get 5
    struct.set 0 1
    local.get 5
    struct.get 0 0
    drop
    local.get 5
    struct.get 0 1
    drop
    struct.new_default 3
    drop
    struct.new_default 0
    drop
    i32.const -1
    i32.const 255
    i32.const -32768
    i32.const 65535
    local.get 0
    local.get 0
    local.get 1
    local.get 1
    local.get 2
    local.get 2
    local.get 3
    local.get 3
    local.get 4
    local.get 4
    ref.null none
    local.get 5
    i32.const 7
    ref.i31
    ref.null func
    struct.new 4
    local.set 6
    local.get 6
    struct.get_s 4 0
    drop
    local.get 6
    struct.get_u 4 1
    drop
    local.get 6
    struct.get_s 4 2
    drop
    local.get 6
    struct.get_u 4 3
    drop
    local.get 6
    struct.get 4 4
    drop
    local.get 6
    struct.get 4 5
    drop
    local.get 6
    struct.get 4 6
    drop
    local.get 6
    struct.get 4 7
    drop
    local.get 6
    struct.get 4 8
    drop
    local.get 6
    struct.get 4 9
    drop
    local.get 6
    struct.get 4 10
    drop
    local.get 6
    struct.get 4 11
    drop
    local.get 6
    struct.get 4 12
    drop
    local.get 6
    struct.get 4 13
    drop
    local.get 6
    struct.get 4 14
    drop
    local.get 6
    struct.get 4 15
    drop
    local.get 6
    struct.get 4 16
    drop
    local.get 6
    struct.get 4 17
    drop
    local.get 6
    i32.const 5
    struct.set 4 1
    local.get 6
    i32.const 6
    struct.set 4 3
    local.get 6
    i32.const 7
    struct.set 4 5
    local.get 6
    local.get 1
    struct.set 4 7
    local.get 6
    local.get 2
    struct.set 4 9
    local.get 6
    local.get 3
    struct.set 4 11
    local.get 6
    local.get 4
    struct.set 4 13
    local.get 6
    ref.null 0
    struct.set 4 15
    local.get 6
    ref.null func
    struct.set 4 17
    i32.const 3
    ref.null 0
    ref.null 1
    ref.null 1
    local.get 1
    struct.new 2
    local.set 7
    local.get 7
    struct.get 2 4
    i64.const 1
    i64.add
    local.set 1
    local.get 7
    local.get 1
    struct.set 2 4
    i32.const 2
    local.get 5
    ref.null 1
    local.get 7
    struct.new 1
    struct.get 1 2
    drop
    local.get 7
    struct.get 2 0
  )

  (func $arrays (type $arrays) (param $n i32) (param $wide i64) (result i32) (local $bytes (ref null $bytes)) (local $longs (ref null $longs)) (local $nodes (ref null $nodes))
    i32.const 7
    local.get 0
    array.new 5
    local.set 2
    local.get 0
    array.new_default 7
    local.set 3
    i32.const 1
    i32.const 2
    i32.const 3
    array.new_fixed 6 3
    i32.const 1
    array.get_s 6
    drop
    i32.const 0
    i32.const 4
    array.new_data 5 0
    drop
    i32.const 0
    i32.const 1
    array.new_data 7 0
    drop
    i32.const 0
    i32.const 2
    array.new_elem 11 0
    drop
    i32.const 0
    i32.const 2
    array.new_elem 10 1
    local.set 4
    local.get 2
    i32.const 0
    array.get_s 5
    drop
    local.get 2
    i32.const 1
    array.get_u 5
    drop
    local.get 3
    i32.const 0
    array.get 7
    drop
    local.get 4
    i32.const 1
    array.get 10
    drop
    local.get 2
    i32.const 2
    i32.const 9
    array.set 5
    local.get 3
    i32.const 1
    local.get 1
    array.set 7
    local.get 4
    i32.const 0
    ref.null 0
    array.set 10
    local.get 2
    array.len
    drop
    local.get 2
    i32.const 0
    i32.const 255
    i32.const 2
    array.fill 5
    local.get 3
    i32.const 0
    local.get 1
    local.get 0
    array.fill 7
    local.get 2
    i32.const 4
    local.get 2
    i32.const 0
    i32.const 4
    array.copy 5 5
    local.get 4
    i32.const 1
    local.get 4
    i32.const 0
    i32.const 1
    array.copy 10 10
    i32.const 1
    array.new_default 10
    i32.const 0
    i32.const 1
    array.new_default 8
    i32.const 0
    i32.const 1
    array.copy 10 8
    local.get 2
    i32.const 0
    i32.const 1
    i32.const 2
    array.init_data 5 0
    local.get 3
    i32.const 0
    i32.const 0
    i32.const 1
    array.init_data 7 0
    local.get 4
    i32.const 0
    i32.const 0
    i32.const 2
    array.init_elem 10 1
    local.get 0
    array.new_default 8
    i32.const 0
    array.get 8
    drop
    local.get 0
    array.new_default 9
    i32.const 0
    array.get 9
    drop
    i32.const 1
    i32.const 2
    array.new_fixed 6 2
    i32.const 0
    array.get_u 6
    drop
    local.get 3
    array.len
  )

  (func $casts (type $casts) (param $any anyref) (param $some (ref any)) (param $eq eqref) (param $func funcref) (param $outside externref) (result i32)
    local.get 0
    ref.test (ref 0)
    drop
    local.get 0
    ref.test (ref null 1)
    drop
    local.get 0
    ref.test (ref eq)
    drop
    local.get 0
    ref.test i31ref
    drop
    local.get 1
    ref.test (ref none)
    drop
    local.get 0
    ref.test nullref
    drop
    local.get 3
    ref.test (ref 12)
    drop
    local.get 3
    ref.test nullfuncref
    drop
    local.get 4
    ref.test (ref noextern)
    drop
    local.get 0
    ref.cast (ref 2)
    drop
    local.get 0
    ref.cast (ref null 4)
    drop
    local.get 2
    ref.cast (ref struct)
    drop
    local.get 0
    ref.cast arrayref
    drop
    local.get 3
    ref.cast (ref 13)
    drop
    local.get 3
    ref.cast funcref
    drop
    local.get 4
    ref.cast externref
    drop
    block (result anyref)
      local.get 1
      br_on_cast 0 (ref any) (ref 0)
      br_on_cast 0 (ref any) (ref i31)
      drop
      local.get 0
      br_on_cast 0 anyref (ref 1)
      br_on_cast 0 anyref (ref null 2)
      br_on_cast 0 (ref any) (ref struct)
      drop
      local.get 2
      br_on_cast 0 eqref nullref
      drop
      ref.null none
    end
    drop
    block (result anyref)
      block (result (ref 0))
        local.get 0
        br_on_cast 1 anyref (ref null 0)
        br_on_cast 0 (ref any) (ref 0)
        drop
        unreachable
      end
    end
    drop
    block (result anyref)
      local.get 1
      br_on_cast_fail 0 (ref any) (ref 0)
      drop
      local.get 0
      br_on_cast_fail 0 anyref (ref 1)
      drop
      local.get 0
      br_on_cast_fail 0 anyref (ref null 2)
      drop
      local.get 2
      br_on_cast_fail 0 eqref arrayref
      drop
      local.get 1
      br_on_cast_fail 0 (ref any) (ref i31)
      drop
      ref.null none
    end
    drop
    block (result funcref)
      local.get 3
      br_on_cast 0 funcref (ref 13)
      br_on_cast_fail 0 funcref (ref null 12)
      drop
      ref.null nofunc
    end
    drop
    block (result externref)
      local.get 4
      br_on_cast 0 externref (ref noextern)
    end
    drop
    local.get 2
    local.get 2
    ref.eq
  )

  (func $conversions (type $conversions) (param $outside externref) (param $inside anyref) (param $n i32) (result i32)
    local.get 0
    any.convert_extern
    drop
    local.get 1
    extern.convert_any
    drop
    local.get 2
    ref.i31
    i31.get_s
    drop
    local.get 2
    ref.i31
    i31.get_u
    drop
    local.get 2
    ref.i31
    extern.convert_any
    any.convert_extern
    ref.cast i31ref
    i31.get_u
  )

  (func $nulls (type $nothing)
    ref.null func
    drop
    ref.null nofunc
    drop
    ref.null extern
    drop
    ref.null noextern
    drop
    ref.null any
    drop
    ref.null eq
    drop
    ref.null i31
    drop
    ref.null struct
    drop
    ref.null array
    drop
    ref.null none
    drop
    ref.null exn
    drop
    ref.null noexn
    drop
    ref.null 0
    drop
    ref.null 5
    drop
    ref.null 12
    drop
  )

  (func $nullable (type $nullable) (param $func funcref) (param $nofunc nullfuncref) (param $extern externref) (param $noextern nullexternref) (param $any anyref) (param $eq eqref) (param $i31 i31ref) (param $struct structref) (param $array arrayref) (param $none nullref) (param $exn exnref) (param $noexn nullexnref) (result i32) (local $sure_func (ref func)) (local $sure_nofunc (ref nofunc)) (local $sure_extern (ref extern)) (local $sure_noextern (ref noextern)) (local $sure_any (ref any)) (local $sure_eq (ref eq)) (local $sure_i31 (ref i31)) (local $sure_struct (ref struct)) (local $sure_array (ref array)) (local $sure_none (ref none)) (local $sure_exn (ref exn)) (local $sure_noexn (ref noexn))
    local.get 5
    local.get 9
    ref.eq
    drop
    local.get 6
    ref.is_null
    drop
    local.get 10
    ref.is_null
    drop
    local.get 11
    ref.is_null
  )

  (func $non_null (type $non_null) (param $func (ref func)) (param $nofunc (ref nofunc)) (param $extern (ref extern)) (param $noextern (ref noextern)) (param $any (ref any)) (param $eq (ref eq)) (param $i31 (ref i31)) (param $struct (ref struct)) (param $array (ref array)) (param $none (ref none)) (param $exn (ref exn)) (param $noexn (ref noexn)) (local $maybe_func funcref) (local $maybe_nofunc nullfuncref) (local $maybe_extern externref) (local $maybe_noextern nullexternref) (local $maybe_any anyref) (local $maybe_eq eqref) (local $maybe_i31 i31ref) (local $maybe_struct structref) (local $maybe_array arrayref) (local $maybe_none nullref) (local $maybe_exn exnref) (local $maybe_noexn nullexnref)
    local.get 0
    local.set 12
    local.get 1
    local.set 13
    local.get 2
    local.set 14
    local.get 3
    local.set 15
    local.get 4
    local.set 16
    local.get 5
    local.set 17
    local.get 6
    local.set 18
    local.get 7
    local.set 19
    local.get 8
    local.set 20
    local.get 9
    local.set 21
    local.get 10
    local.set 22
    local.get 11
    local.set 23
    local.get 6
    i31.get_s
    drop
  )

  (func $callee (type $narrow) (param $n i32) (result i32)
    local.get 0
    i32.const 1
    i32.add
  )

  (func $caller (type $callback) (param $n i32) (result i32)
    local.get 0
    ref.func 7
    call_ref 12
  )
)
