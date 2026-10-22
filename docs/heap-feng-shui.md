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

## 7. H4 corrected model (gdb-measured, supersedes §5.3 / handover §6)

Measured with `exploits/cve-2026-109619-stale-state/trace.py` + `trace.sh`
(committed), attaching gdb to the prefork worker and tracing
`php_request_startup/shutdown`, `zend_error_zstr_at`, `zend_mm_shutdown`,
`zend_mm_alloc_small_slow`, `zend_fetch_debug_backtrace`, `_efree`, and a
hardware watchpoint on the backtrace zval's type byte.

### 7.1 The second-fatal consumer DOES NOT EXIST

`zend_activate()` calls `init_executor()` on every request
(`Zend/zend.c:1324`), and `init_executor()` does
`ZVAL_UNDEF(&EG(last_fatal_error_backtrace))` (`Zend/zend_execute_API.c:139`).

Watchpoint proof (consumer request):

```
REQUEST_STARTUP backtrace_type=7      # stale backtrace still present
WATCH_BT_WRITE type_now=0 func=init_executor   # cleared here
ERROR_ZSTR_AT type=8192 ... type=UNDEF         # trigger_error deprecation sees UNDEF
```

So by the time the script runs (the "second-fatal" consumer), the backtrace is
already UNDEF; its `zval_ptr_dtor` is a no-op. The handover §6 / §5.3
"second-fatal consumer" was a **misidentified consumer** — the panic it
attributed to the second-fatal path was actually the INI diagnostic (the
`php_flag report_memleaks off` deprecation), which fires in `apply_config()`
*before* `php_request_startup()`.

This is exactly what the advisory states: the stale value is consumed "before
normal request initialization resets it".

### 7.2 The only consumer is pre-startup and always panics

The sole consumer that runs before `init_executor()` is the INI diagnostic
(`php_flag report_memleaks off`, in `apply_config()`). At that point
`zend_mm_shutdown(full=0)` from the previous request has already zeroed every
`chunk->map[]` entry, so the re-free is misclassified as a large run and hits
`ZEND_MM_CHECK(page_offset % PAGE_SIZE == 0)` in `zend_mm_free_heap`
(`Zend/zend_alloc.c:1539`) → `zend_mm_panic`.

Measured panic pointer (2-frame `producer.php`): `EFREE_MAP0 ptr=0x...79140
page=121 slot=5` — the **args array arData** (128B, bin 11), *not* `S` (the
`"X"*32` arg string at page ~131) as the handover assumed.

### 7.3 Measured backtrace layout (2-frame producer.php, stable across rebuilds in page terms)

```
H        (56B, bin 6)   page 3    0x...3150
frame[0] (56B, bin 6)   page 3    0x...31c0   arData (128B, bin 11) page 4
args[0]  (56B, bin 6)   page 3    0x...31f8   arData (128B, bin 11) page 121
D        (128B, bin 11) page 121  0x...791e8   (nSize=8, not 64*16)
S        (56B, bin 6)   page ~131  ("X"*32)
```

(For the 40-frame `fatal.php` producer, `D` is 64*16=1024B → bin 23.)

### 7.4 Heap protection is ON

`ZEND_MM_HEAP_PROTECTION` defaults to 1 (`Zend/zend_alloc.c:149`, no configure
switch). Free slots carry an XOR-shadowed `next` pointer keyed by the per-worker
random `heap->shadow_key` (re-randomized in the child via
`zend_mm_refresh_key_child`), verified on every allocation. This kills the
"free-list cycle" double-free idea (`memory-layout.md` §5.1/§5.2); a *single*
free + *single* realloc of the same slot remains shadow-safe.

### 7.5 Consumer startup re-runs page 3 as bin 16, not bin 6

The handover assumed `H`'s low page would be "reallocated as symbol_table
(56B)". Measured: the consumer's startup allocates bin 3→page1, bin 6→page2,
bin 16 (320B, 5 pages)→pages 3-7, ... So page 3 (where `H` lives) becomes a
bin-16 run, not bin 6. (Irrelevant now — the pre-startup consumer never
re-runs any page.)

### 7.6 Consequence for the plan

The second-fatal path (H1/H2) is closed. Re-plan around a pre-startup consumer
and/or the CVE-2026-109618 OOM `pDestructor` primitive (the original
`exploit-plan.md` "Primitive A = primary, Primitive B = leak" split).

## 8. Pivot to OOM pDestructor (CVE-2026-109618) — confirmed reachable

Given the second-fatal consumer is impossible (§7), the exploit pivots to the
OOM `pDestructor` primitive (original `exploit-plan.md` "Primitive A"). Gdb
verification of the corrupting allocation is now done.

### 8.1 The fix (diff 8.5.11 -> 8.5.12)

Every hash-table allocation in `Zend/zend_hash.c` is converted from
`emalloc`/`pemalloc`/`perealloc2` (which `zend_bailout()` on OOM) to
`femalloc`/`fpemalloc`/`fperealloc2` (fallible, return NULL + `HASH_FALLIBLE`
flag). The vulnerable pattern is the bailout that unwinds with the table
half-initialised.

### 8.2 The corrupting allocation (8.5.11)

`_zend_hash_str_add_or_update_i()` `add_to_hash` (Zend/zend_hash.c:960):

```c
idx = ht->nNumUsed++;                                    // (1) bumped
ht->nNumOfElements++;                                    // (2) bumped
p = ht->arData + idx;
p->key = key = zend_string_init(str, len, ...);          // (3) OOM -> bailout
```

The key copy at (3) is the first large allocation on the nested-name path, so
the OOM lands exactly here, leaving `ht->arData[idx]` (key/h/val) unwritten.

### 8.3 Confirmed trigger (gdb-verified)

`strat_bracket_key(nvars, keylen)`: urlencoded `a[<large-key>][c]=v`.

`php_register_variable_ex()` adds the LARGE *intermediate* key to `$_POST["a"]`
via `zend_symtable_str_update_ind()` -> `_zend_hash_str_add_or_update_i()`
(str variant -> key copy, **no interning**). The leaf `[c]` goes through
`php_register_variable_quick()` (which interns), so only the intermediate level
reaches the raw str variant. OOM backtrace:

```
zend_mm_safe_error <- ... <- zend_string_alloc <- zend_string_init
  <- _zend_hash_str_add_or_update_i <- zend_hash_str_update_ind
  <- zend_symtable_str_update_ind <- php_register_variable_ex
```

### 8.4 The corrupted table and walk

Corrupted table is `$_POST["a"]` (nUsed = fields-until-OOM). Shutdown's
`zend_array_destroy()` does **not** call `zend_hash_destroy()` for the common
case (`pDestructor == ZVAL_PTR_DTOR`); it inlines:

```c
do { i_zval_ptr_dtor(&p->val); if (p->key) zend_string_release_ex(p->key); } while (++p != end);
```

The unwritten bucket's `val` is currently garbage (`IS_ARRAY` pointing at a
live array, i.e. a stale `array_init` result) — non-UNDEF, so it IS walked.

### 8.5 Grooming target (remaining)

Make the unwritten bucket's `val` (16 bytes at `arData + (nUsed-1)*32`) an
`IS_OBJECT` zval pointing at the fake object/handlers/ROP from `rop.py`, so
`i_zval_ptr_dtor` -> `zend_objects_store_del` -> `free_obj` -> `system`.
The bucket sits in the new (garbage) portion of the arData realloc, so the
groom must control the freed memory the realloc reuses.

### 8.6 Grooming status (gdb-measured)

The `$_POST["a"]` arData grows 8->16->32->64 buckets via
`zend_hash_do_resize`, which for the final 32->64 step does
`perealloc2` -> `zend_mm_realloc_heap`: `zend_mm_alloc_small(bin 28)` +
`memcpy(old)` + `zend_mm_free_small(old, bin 24)`.

Measured facts:
- 64-bucket arData = `HT_SIZE_EX(64)` = 64*32 + 128*4 = **2560 bytes = bin 28**
  (`HT_SIZE_TO_MASK(n)=-(2n)`, so the hash array is `2n*4`).
- The bin-28 free list is **empty** at the resize, so it allocates a fresh
  5-page run from `chunk->free_tail` (not from a freed bin slot). The unwritten
  bucket (index 45) lands in the stale content of those free_tail pages.
- That stale content is a **deterministic previous arData bucket** (measured
  `val=IS_ARRAY @ 0x...f540, h=0xf7302a9e38b2b70e` every run) — i.e. a pointer
  to a live `tmp` array. So `i_zval_ptr_dtor` already double-frees a live array,
  but it does not crash (shadow-key check only fires on the next alloc).
- A pad value (small bin-28 or large page-aligned) does **not** land in the
  arData tail: `add_post_var` does `estrndup(value)` -> `ZVAL_STRINGL_FAST`
  (copy) -> `efree(estrndup)`, so the freed `A` block sits *before* the live
  copy `B` and its pages go to `free_map`, never the contiguous `free_tail`.

Remaining grooming problem: place attacker-controlled bytes on the
`free_tail` pages the bin-28 resize consumes (page-level grooming of
`free_map`/`free_tail`), not bin free-list grooming.

### 8.7 Stale-alias primitive (corrected) — the actual double-free target

Re-examined with per-address `zend_array_destroy` logging. The unwritten bucket's
`val` is a **stale pointer that aliases the field-46 `tmp` array** (which was
leaked by the OOM'd insert, since the insert aborted before `ZVAL_COPY_VALUE`).
At shutdown the walk does `i_zval_ptr_dtor(stale IS_ARRAY)` ->
`zend_array_destroy(tmp)`, freeing the *leaked* tmp once. There is no
second free of a live array in the default layout (the stale pointer's value
`0x…284540` lands exactly on the leaked tmp, verified: that address appears
exactly once in the destroy trace).

So the primitive is a **stale-pointer free**, not a literal double-free. Its
value: the unwritten bucket's `val` is *attacker-influenced via the arData
tail*, and when it points at a **fake `zend_array`** (controlled `pDestructor`),
`zend_array_destroy` takes the `pDestructor != ZVAL_PTR_DTOR` branch and does
`ht->pDestructor(&p->val)` — the arbitrary indirect call. That is the same
object-hijack target as `rop.py`, reached through the OOM bucket instead of the
backtrace. The "double-free" framing is therefore the *wrong* lens: the real
task is exactly the bin-28 slot placement of §8.6.

### 8.8 The two-insert structure (gdb: `zend_hash_str_update_ind` trace)

Each `a[<large>][c]=v` field registers the `<large>` key into **two** arrays via
`zend_symtable_str_update_ind` (the "symtable" indirect-value path):

```
ADD ht=0x..b150 nNumUsed=43   (insert #1 -> $_POST["a"])
ADD ht=0x..b0e0 nNumUsed=44   (insert #2 -> a second array)
ADD ht=0x..b150 nNumUsed=44
ADD ht=0x..b0e0 nNumUsed=45
ADD ht=0x..b150 nNumUsed=45
ADD ht=0x..b0e0 nNumUsed=46   <- OOM here (2nd insert's key-copy)
```

- `ht=0x..b150` = **`$_POST["a"]`** (verified: it is the array destroyed second in
  `php_request_shutdown`, right after `$_POST`, `nUsed=46`).
- `ht=0x..b0e0` = a **second array** (a symtable/indirect copy, `nUsed=47`).

The OOM always lands on the **second** insert (`b0e0`, index 46) because the
first insert's 80 KB key-copy succeeds and the second exhausts the limit. The
unwritten bucket is therefore in `b0e0`.

### 8.9 The walk only reaches `$_POST["a"]` (b150), not b0e0

`zend_array_destroy` / `zend_hash_destroy` trace at shutdown shows only `b150`
is walked; `b0e0` is **not** destroyed (it is the symbol-table-style copy that
fast-shutdown discards). So the naive "unwritten bucket is walked" model
(attack-surface §4) is wrong for this trigger: the corrupted bucket is in a
table that is never walked.

### 8.10 The pad reaches b0e0's arData, not b150's

The `zend_hash_do_resize` sweep (bin-28 head) shows `b0e0` resizes first and
reuses the pad's freed `'P'` block; `b150` resizes second and reuses a zeroed
slot. Combined with 8.9 this is the exact mismatch:

| table | arData (pad?) | walked? | has OOM bucket? |
|-------|---------------|---------|-----------------|
| b0e0  | `'P'` (pad)   | **no**  | yes (idx 46)    |
| b150  | zeros         | **yes** | no              |

### 8.11 Path forward

Make the OOM land on the **first** insert (`b150`) by spending ~80 KB more
memory before the OOM field (pad or extra field), so the first key-copy fails
and `b150` (walked) holds the unwritten bucket; and place **two** pads (or a
pad sized/positioned for both resizes) so `b150`'s arData also gets the
controlled bytes. Then `i_zval_ptr_dtor` on `b150`'s controlled bucket reaches
the fake `pDestructor`/`free_obj`.

### 8.12 Confirmed: pad size selects the OOM table

`zend_hash_str_update_ind` trace with a leading memory-shift pad
(`pad=<Q*N>` before the bracket-key fields):

| pad length | last ADD before OOM (the OOM bucket) |
|-----------|--------------------------------------|
| 0          | `b0e0` idx 46 (non-walked)          |
| 40000      | `b150` idx 45 (**walked**)          |
| 80000      | `b0e0` idx 45 (non-walked)          |
| 120000     | `b150` idx 44 (**walked**)          |

So a ~40 KB pad shifts the OOM from the second insert (`b0e0`, discarded) onto
the **first** insert (`b150` = `$_POST["a"]`, walked at shutdown). This makes
the unwritten bucket reachable by `zend_array_destroy`. Remaining: (a) also
make `b150`'s 32->64 resize reuse the controlled bin-28 block (it currently
reuses a zeroed slot, while `b0e0`'s earlier resize takes the pad — so use two
pads, or a pad positioned between the two resizes), and (b) place the fake
`pDestructor`/`free_obj` bytes at the unwritten bucket's offset.

### 8.13 The pad slot-reuse blocker (b150's resize)

Two pads placed before the resizes do not help: `add_post_var`'s
`estrndup(A)` -> `ZVAL_STRINGL_FAST(B, copy)` -> `efree(A)` order means the
*next* field's `A` reuses the just-freed slot. Measured bin-28 free/alloc:

```
EMALLOC 2537 (pad1 A -> slot1)  EFREE slot1
EMALLOC 2537 (pad2 A -> slot1 REUSE)  EFREE slot1
RESIZE64 b0e0 -> pops slot1 (pad2 'Q')
RESIZE64 b150 -> pops slot4 (zeros)     # B blocks (slot2,slot3) are live
```

So there is always exactly **one** freed bin-28 block (the pads' `A` share a
slot), consumed by `b0e0`'s (first) resize; `b150`'s (second) resize always
gets a zeroed slot. Getting a controlled block into `b150` needs a *second
distinct* freed bin-28 block between the two resizes — e.g. a field whose value
is rejected by `sapi_module.input_filter` (so `A` is freed with no `B` copy), or
the multipart path, or making the two resizes land on different fields so a pad
fits between them.

### 8.14 The resizes are at consecutive inserts (INS#65/#66)

Field-marker trace shows `b0e0` resizes at insert #65 and `b150` at insert #66
(back-to-back: `b0e0` is 1 key ahead of `b150`, so they cross the 32-key
boundary on adjacent fields). A pad's `estrndup(A)` is freed at a field
boundary that is either before both resizes (padpos 30-32 -> `b0e0` takes it) or
after both (padpos 33 -> neither takes it). There is no field boundary *between*
the two resizes, so a single pad cannot be placed to reach `b150`. Combined with
the `A`-reuses-slot behavior (§8.13), `b150`'s resize consistently gets a zeroed
slot. Also: the pad's `B` copy is not bin-28 (no `_emalloc(2560)` seen), so the
duplicate-key "dtor the old value" trick cannot free a bin-28 block either.

Open paths (unchanged): (a) a field whose value `sapi_module.input_filter`
rejects (frees `A` with no `B`), (b) the multipart value path, (c) making the
two resizes land >1 field apart so a pad fits between them.
