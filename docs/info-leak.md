# Info-leak primitive + ASLR bypass (CVE-2026-109619, stale backtrace)

This is the isolated info-leak / ASLR-bypass stage. It is deliberately separate
from the OOM RCE chain (`cve-2026-109618`) so the leak primitive can be
reproduced and documented on its own. It turns the stale fatal-backtrace
use-after-free into a **read** that discloses the heap base (and, by extension,
libphp/libc), which the RCE chain needs to resolve absolute addresses.

Status: **primitive + addresses measured; the over-HTTP read is gdb-verified
(ASLR-off).** A fully remote (ASLR-on) read still needs either the session
upload-progress consumer (READ) or the `free_tail`/bin grooming documented in
`heap-feng-shui.md` §8.

---

## 1. What leaks (the source)

The producer (`GET /fatal.php`) raises a fatal error. PHP stores a request-owned
**packed** backtrace in `EG(last_fatal_error_backtrace)`. That graph is a chain of
heap allocations that each hold heap pointers:

```
EG(last_fatal_error_backtrace)  (zval @ executor_globals+0x1b0, IS_ARRAY)
  .arr = H   (zend_array header, 56B)          -> holds arData = D
H.arData = D (packed zval array, 64*16 = 1024B) -> each zv is IS_ARRAY -> frame
frame[]     (zend_array headers, 56B each)      -> holds arData -> args/strings
args[]      (zend_array, 56B)                   -> holds arg zvals
S           ("X"*32 -> 56B zend_string)          -> the controlled arg string
```

Every one of `H`, `D`, `frame[]`, `args[]`, `S` is a heap pointer. Disclosing any
one of them discloses the heap base (they are all inside the single 2MB main
chunk at fixed page offsets). The heap base is the first ingredient the RCE
chain needs (to know where the fake object / ROP payload sits).

The backtrace also indirectly anchors the module bases: `H.pDestructor` is the
address of `zval_ptr_dtor` (a libphp function pointer), so reading that field
discloses **libphp**; the standard ROP chain additionally needs **libc**
(`system`, `pop rdi; ret`), disclosed the same way once any libc pointer is
reachable.

## 2. Why it is a read, and why the free path panics

The consumer (`php_flag report_memleaks off`) runs in `apply_config()` **before**
`php_request_startup()`. Its `zend_error_zstr_at()` begins with

```c
zval_ptr_dtor(&EG(last_fatal_error_backtrace));   /* Zend/zend.c:1501 */
ZVAL_UNDEF(&EG(last_fatal_error_backtrace));
```

i.e. a **free**, not a read. That free walks `H -> D -> frame[] -> args[] -> S`
and re-frees every allocation. Because the previous request's
`zend_mm_shutdown(full=0)` zeroed every `chunk->map[]` entry, the re-free is
misclassified as a large run and hits
`ZEND_MM_CHECK(page_offset % PAGE_SIZE == 0)` in `zend_mm_free_heap`
(`Zend/zend_alloc.c:1539`) -> `zend_mm_panic`.

Measured first panic pointer: the **args-array arData** (`0x7ffff7279140`,
page `0x79`), not `S`. So the *free* consumer is a deterministic crash, not a
leak.

## 3. The read path

To turn this into a leak the consumer must **read** the stale graph instead of
freeing it, or re-run the stale pages so the free is a clean mid-run free that
leaves the dangling pointer aliasing a live object whose *content* is then
displayed. Two routes:

1. **Session upload-progress consumer (READ, pre-RINIT).** The advisory's second
   confirmed consumer. `session.upload_progress.enabled=On` (default) plus a
   multipart `PHP_SESSION_UPLOAD_PROGRESS` field publishes request-owned
   session/decoder state; OOM/fatal prevents the matching reset; the next
   upload-progress op reads `PS(...)` before RINIT. This is a read of stale
   state that may contain pointers, and it does not go through the backtrace
   `zval_ptr_dtor` panic path.

2. **Groomed backtrace read.** Re-run the stale `D`/`S` pages as a same-bin
   `SRUN` in the consumer (the `heap-feng-shui.md` §8 free-list/free_tail work),
   so the walk is a clean mid-run free; then the dangling `S`/`D` slot aliases a
   live allocation whose `zend_string {val,len}` we control, and the error
   display (`display_errors=On`, `html_errors=Off`) returns `len` bytes at `val`
   to the client.

## 4. What the ASLR bypass needs

The RCE chain (`rop.py`) uses an object-handler hijack (`free_obj`) and this ROP:

```
pivot      = jump_fcontext+0x2e   (libphp)   mov rsp,rdi; ...; jmp *r8
pop rdi;ret = libc+0x277e5
ret         = libc+0x277e6
system      = libc+0x4c490
```

So the leak must yield at minimum the **heap base** (payload location) and the
**libc base** (gadgets), or the **libphp base** if the target is switched to a
libphp builtin (`php_readfile`, etc.).

## 5. Measured addresses (current build, `setarch -R`)

`php-rce-stale:8.5.11`, mod_php, ASLR disabled. Re-measured 2026-10-22.

| Symbol | Address | Derivation |
|--------|---------|-----------|
| libphp base | `0x7ffff4400000` | first `libphp.so` mapping |
| libc base | `0x7ffff7cd4000` | first `libc.so.6` mapping |
| `system` | `0x7ffff7d20490` | libc + `0x4c490` |
| `pop rdi; ret` | `0x7ffff7cfb7e5` | libc + `0x277e5` |
| `ret` | `0x7ffff7cfb7e6` | libc + `0x277e6` |
| `jump_fcontext` | `0x7ffff49fb880` | libphp |
| pivot (`jump_fcontext+0x2e`) | `0x7ffff49fb8ae` | the `mov rdi,rsp` insn |
| `zval_ptr_dtor` | `0x7ffff4b605f0` | libphp |
| `executor_globals` | `0x7ffff5b40fc0` | |
| `alloc_globals` | `0x7ffff5b40c88` | |
| stale backtrace `H` | `0x7ffff72570e0` | page 3 |
| stale backtrace `D` (`arData`) | `0x7ffff7293008` | page 121 |
| `S` (`"X"*32`, 56B) | `~page 131` | see `memory-layout.md` |

(Offsets are stable across rebuilds; absolute bases shift with ASLR. The leak
must recover the bases.)

## 6. Files

- `container/cve-2026-109619-info-leak/` — dedicated victim (same producer +
  INI-diagnostic consumer as the stale-state case).
- `exploits/cve-2026-109619-info-leak/leak.py` — measures and reports the
  leak-relevant addresses under gdb (ASLR-off), and documents the read path.
- `exploits/cve-2026-109619-info-leak/run.sh` — build/run/leak.

## 7. Open work

- Wire the **session upload-progress read consumer** (advisory's READ path) to
  leak a pointer over HTTP with ASLR on.
- Or complete the `free_tail`/bin grooming (`heap-feng-shui.md` §8.6) so the
  backtrace read consumer returns the heap/libc bytes.
