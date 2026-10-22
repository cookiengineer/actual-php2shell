# Heap Feng Shui — CVE-2026-109619 (stale fatal-backtrace UAF)

Progress log for the grooming stage that turns the confirmed use-after-free into
an arbitrary call (`system("cat /etc/passwd")`). All addresses are for the
`setarch -R` (ASLR-off) target; with ASLR on they are offsets from the
libphp/libc/heap bases.

## 1. The primitive (recap)

Producer `GET /producer.php` raises a fatal error; the backtrace (a **packed**
`zend_array`) is stored in `EG(last_fatal_error_backtrace)` and is never reset
(`fast_shutdown` always true). The consumer is the **next** diagnostic's
`zval_ptr_dtor(&EG(last_fatal_error_backtrace))` in `zend_error_zstr_at()`
(`Zend/zend.c:1501`).

Deterministic object graph (measured):

```
H  (backtrace header, 56B)     = 0x7ffff7203150  (packed, nNumUsed=2)
D  (packed zvals, arData)      = 0x7ffff72791e8
frame[0] (trigger_error frame) = 0x7ffff72031c0
  -> args array                = 0x7ffff72031f8
     -> string ("t", interned) + long
frame[1] (boom frame)          -> args = ["X"*32]  (S = 56B zend_string, controlled)
```

## 2. Why the naive double-free panics (measured)

`_efree` disassembly (`0x7ffff4a6ff80`):

```
+41  mov 0x250(%rsi,%rdx,4),%ecx   ; info = chunk->map[page_num]
+48  cmp (%rsi),%rax               ; chunk->heap == heap ?
+51  jne <_efree.cold>             ; panic ("zend_mm_heap corrupted")
+57  test %ecx,%ecx
+59  jns <large>                   ; info not SRUN -> large path
...
+174 test $0xfff,%edi              ; ptr page-aligned?
+180 jne <_efree.cold>             ; panic
```

The panic is the **page-info** check, not `chunk->heap`. Root cause: at every
request shutdown, `zend_mm_shutdown(full=false)` does

```
memset(p->free_map, 0, sizeof(p->free_map) + sizeof(p->map));
```

which zeroes every `chunk->map[]` entry. So when the consumer re-frees a string
whose page was already returned to the free pool, `info = map[page_num] == 0`,
the free is misclassified as a *large* run, and the `ptr & 0xfff` alignment check
fails -> panic.

Measured at the panic:

```
ptr=0x7ffff7279140  heap=0x7ffff7200040  chunk=0x7ffff7200000  chunk->heap=0x7ffff7200040
-> page_num = 0x79, map[0x79] = 0 (reset), so panic on alignment (0x9140 & 0xfff != 0)
```

## 3. What this means for exploitation

The INI-diagnostic consumer fires in `apply_config()` **before**
`php_request_startup()`, so the stale backtrace's pages are still `map=0` -> the
double-free is always a detected panic, no aliasing window.

The **second-fatal** consumer fires after `zend_activate()`/`sapi_activate()`
have reallocated those pages as fresh 56-byte runs (`symbol_table`, `$_GET`,
`$_POST`). Re-freeing the stale string then does `zend_mm_free_small` on a slot
in the **middle of a live run**, which is the exploitable condition: the slot is
returned to the 56-byte bin free list while its neighbors remain allocated, so a
later 56-byte allocation aliases a live object.

## 4. Planned exploitation (second-fatal consumer)

1. Producer: fatal error with a controlled `S` ("X"*32 -> 56B zend_string) in the
   backtrace args.
2. Consumer: `POST /producer.php` (or a fatal script) whose startup reallocates
   `S`'s page as a live 56-byte run, then the script fatals -> `zval_ptr_dtor(H)`
   frees `S`'s slot into the free list (mid-run).
3. A controlled 56-byte allocation in the request body then reuses that slot
   (aliasing a live autoglobal/symbol-table entry).
4. Place the `rop.py` payload (fake `zend_object` + handlers + ROP:
   `jump_fcontext+0x30` pivot -> `pop rdi; ret` -> `&cmd` -> `system`) so that the
   live entry's release performs `free_obj(object)` -> `system("cat /etc/passwd")`.

### 5.3 Reallocation is the blocker (corrected)

An earlier "body-size window" observation was an artifact of the worker
respawning between test requests; with a **fresh worker per attempt** the
consumer crashes for every body size (50 KB … 600 KB), for both the 2-frame and
40-frame producers.

Root cause: after `zend_mm_shutdown(full=false)` the small-bin free lists are
`memset` to 0 and `map[]` is zeroed, so the next request allocates *fresh* small
runs at `free_tail` (low pages). The stale backtrace's strings live at high pages
(`S` ~ page 131), which the consumer's startup/body never turns back into a
`map=SRUN` small run of the same bin. A body `erealloc`/`zend_string` that lands
on the page is a *large* run, so the stale small-string free is still
misclassified (alignment panic). And if the stale header `H` were on a low page,
it would be reallocated as `symbol_table` (harmless).

So the exploitable "free-mid-run" state requires **spraying the same bin across
the stale page** (thousands of 56-byte strings so the 56-byte small run reaches
page ~131) or forcing the producer's fatal during startup (the CVE-2026-109618
OOM path) so the backtrace lands in the low pages the consumer's startup reuses.

A direct spray is capped by the default `max_input_vars=1000` (~14 pages of
56-byte runs, nowhere near page 131); even with `max_input_vars` raised, the
consumer still crashed up to 11000 fields, confirming the stale strings sit
beyond what a body can practically re-run into a `SRUN` of the same bin before
the fatal fires.

## 5. Status / next steps

- [x] Object graph and all addresses measured.
- [x] ROP chain + fake object/handlers layout written (`rop.py`).
- [x] Panic mechanism fully characterized (page-info reset).
- [x] Second-fatal consumer characterized (see §5.1).
- [ ] Determine the exact slot offset of `S` within the reallocated 56-byte run
      in the second-fatal consumer (gdb), so the body can target the aliased slot.
- [ ] Trigger `system("cat /etc/passwd")` end-to-end.

### 5.1 Second-fatal consumer — why it also panics

POST second-fatal panic backtrace (measured):

```
#7 zend_array_destroy (ht=0x7ffff7203150)   # H
#8 zend_error_zstr_at (orig_type=8192)       # E_DEPRECATED
#9 zend_error_zstr (type=8192)
```

Two compounding facts:

1. `trigger_error("t", E_USER_ERROR)` first emits a **deprecation** (8192,
   "Passing E_USER_ERROR to trigger_error() is deprecated"), so the "second
   fatal" is actually *deprecation + fatal*; the deprecation's
   `zend_error_zstr_at` is the consumer that frees the stale backtrace.
2. The stale backtrace is allocated at the **end** of the producer request, so
   `S` lands in a high page (e.g. page `0x83`, ~536 KB into the 2 MB main chunk).
   The consumer's startup (`symbol_table`, `$_GET`, `$_POST`) only reallocates
   the low pages, so `S`'s page stays `map=0` -> the double-free still hits the
   page-info panic.

So the INI-diagnostic consumer and the second-fatal consumer converge on the
same wall: the page-info reset (`memset(map,0)`) plus the high-page placement of
the stale string make the cross-request double-free a *detected* panic rather
than a usable mid-run free.

### 5.2 Remaining work (precise)

To get a non-panicking double-free, one of:

- make the producer allocate the backtrace in a **low** page (minimal
  pre-fatal footprint) so the consumer's startup reuses `S`'s page, OR
- make the consumer's startup allocate ~500 KB+ so it reaches `S`'s page, OR
- use a producer whose fatal carries a *page-aligned* controlled allocation so
  the double-free takes the `zend_mm_free_large` path (which does not run the
  small-bin `map=0` misclassification).

Then the freed `S` slot (mid-run) is reused by a controlled body allocation, and
the `rop.py` fake object triggers `system("cat /etc/passwd")`.

## 6. Constants (ASLR-off)

```
libphp base      0x7ffff4400000
libc  base       0x7ffff7cd5000
system           0x7ffff7d21490
zval_ptr_dtor    0x7ffff4b605f0
pivot (jump_fcontext+0x30) 0x7ffff49fb8ae
pop rdi; ret     0x7ffff7cfc7e5
ret              0x7ffff7cfc7e6
_efree           0x7ffff4a6ff80
executor_globals 0x7ffff5b40fc0  (last_fatal_error_backtrace @ +0x1b0)
```
