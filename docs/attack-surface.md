# PHP 2026 RCE — Attack Surface Analysis

Status: analysis of what is affected, derived from the vendored advisories
(`references/`) and the `php-src` fix commit
`31c0ea7d7ff1d1fccb6492e52dab544011628065` ("Avoid state corruption via
bailout").

## 1. Scope of the vulnerability class

Two advisories were published 2026-10-21 by `php-src`, fixed by a single commit
across all maintained branches:

| Advisory | CVE | Title |
|----------|-----|-------|
| GHSA-w8hw-w9fx-j79w | CVE-2026-109618 | RCE via OOM corruption |
| GHSA-6wmf-4rv5-p3rp | CVE-2026-109619 | RCE via stale global state |

- Affected: `< 8.2.35`, `< 8.3.36`, `< 8.4.27`, `< 8.5.12`.
- Patched: `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`.
- CVSS 4.0: `AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (9.2).

Both are a re-emergence of the class first discovered by Stefan Esser in 2004
(`CAN-2004-0594`, see `references/112004.html` / `108981780109154.html`):
a *memory-limit / OOM interruption that abandons an operation before it resets
request-owned state*, leaving the worker's persistent globals pointing at freed
request memory.

## 2. The two primitives

### 2.1 CVE-2026-109618 — OOM `longjmp` leaves invalid request memory

PHP uses `longjmp()` (`zend_bailout()`) to abort on out-of-memory. When the
allocation that fails happens while a request-owned structure is only
*half-initialized*, the bailout unwinds past the code that would have finished
initializing it. The structure is then in an invalid state, and
`php_request_shutdown()` later reads or branches on it.

Vulnerable path in 8.5.11:

```
Zend/zend_alloc.c:395   zend_mm_safe_error()          -> zend_error_noreturn(E_ERROR, "Allowed memory size ...")
Zend/zend_alloc.c:418       zend_bailout();            -> longjmp out of the allocator
Zend/zend_alloc.c:1043/1045/1059/1061/1063/1643/1645/1940  call sites
```

The fix replaces the bailout with a *delayed soft OOM* (`EG(delayed_oom)`,
handled at the next VM safe point via `zend_handle_delayed_oom()`) plus a hard
OOM that calls `_exit(137)`. The shutdown procedure therefore never sees the
invalid intermediate state again.

### 2.2 CVE-2026-109619 — stale worker globals (use-after-free)

Worker globals that live for the whole process but point into request-owned
memory must be reset before the request heap is freed. A fatal error (including
OOM) abandons an operation before its matching reset, or a late diagnostic
repopulates state after it was cleared. The request heap is then freed while the
worker global still points into it. A later operation that runs *before* normal
request initialization (RINIT) consumes the stale value.

Confirmed producers / consumers:

| Producer | Consumer | SAPI |
|----------|----------|------|
| `fatal_error_backtraces=On` fatal error stores `EG(last_fatal_error_backtrace)` | the next request's diagnostic runs `zval_ptr_dtor(&EG(last_fatal_error_backtrace))` on the stale zval | mod_php |
| session upload progress publishes `PS(...)` session/decoder state; OOM/fatal prevents reset | next upload-progress op (`php_session_rfc1867_update()`) before RINIT | mod_php and FPM |

**Why the backtrace reset is always missed (confirmed in source):**

`zend_deactivate()` computes
`fast_shutdown = is_zend_mm() && !EG(full_tables_cleanup)`
(`Zend/zend_execute_API.c:446`). `EG(full_tables_cleanup)` is initialised to
`0` and only set to `1` by `dl()` (`ext/standard/dl.c:71`), so on the default
Zend-MM build `fast_shutdown` is always `true`. The reset
`zval_ptr_dtor(&EG(last_fatal_error_backtrace))` inside
`zend_shutdown_executor_values()` (`Zend/zend_execute_API.c:309`) is guarded by
`if (!fast_shutdown)` and is therefore never executed.

**The consuming primitive is a free, not a read:** the next request's first
diagnostic reaches `zend_error_zstr_at()` (`Zend/zend.c:1499`), whose very first
statement is `zval_ptr_dtor(&EG(last_fatal_error_backtrace))`
(`Zend/zend.c:1501`). That dtor walks the *already-freed* `zend_array` and
re-frees its buckets/strings, corrupting the Zend MM heap. (The `php_error_cb`
read at `main/main.c:1389` runs *after* this dtor and therefore sees `UNDEF`.)

### 2.3 Confirmed reproduction (end-to-end)

`exploits/cve-2026-109619-stale-state/exploit.py` reproduces the UAF deterministically on the victim
container:

1. `GET /fatal.php` — fatal error stores a 40-frame backtrace; unclean shutdown
   leaves it stale (200 OK).
2. `GET /index.php` — the mod_php per-directory diagnostic
   (`php_flag report_memleaks off`, applied in `apply_config()` before
   `php_request_startup()`) triggers `zend_error_zstr_at` →
   `zval_ptr_dtor(stale backtrace)` → `zend_mm_heap corrupted` → SIGABRT
   (connection dies, no HTTP response).

## 3. OOM reachability ("strategies")

An attacker must reach OOM *inside the configured limits*. The multipart parser
(`main/rfc1867.c`) provides several amplifier bugs (fixed in the same commit):

1. **Missing/undecodable `Content-Length`** — passes the initial `post_max_size`
   check, then keeps feeding decoded body (`fill_buffer()`).
2. **Unbounded part headers** — internal representation costs far more than the
   wire bytes (`multipart_buffer_headers()` previously `estrdup()`ed every
   header line).
3. **Empty file controls** — not counted toward `max_file_uploads` but still
   build the full file-metadata arrays.
4. **Nested field names** (`a[b][c]...`) — `php_register_variable_ex()` used
   `array_init()` per nesting level, multiplying allocation work (fixed to
   `array_init_singleton()` + `ZEND_HAS_OOM()` checks).

## 4. Modern analog of the 2004 destructor-pointer primitive

The 2004 advisory described controlling a HashTable `pDestructor` by triggering
the memory-limit abort inside `zend_hash_init()`. The same structure persists in
PHP 8:

```
Zend/zend_hash.c:261  _zend_hash_init_int()   header written (pDestructor at :272)
Zend/zend_hash.c:1730 zend_hash_destroy()      iterates ht->arData for ht->nNumUsed buckets
Zend/zend_hash.c:1740/1788  ht->pDestructor(&p->val);   <= indirect call, arg is zval*
```

If an OOM bailout interrupts bucket insertion (after `nNumUsed`/`nNumOfElements`
are bumped but before `arData` is coherent, or after the header is written but
before the bucket space is fully populated), the shutdown destruction path
(`zend_call_destructors()` → `zend_array_destroy()` → `zend_hash_destroy()`)
will iterate attacker-controlled `arData` and call an attacker-influenced
`pDestructor` — an arbitrary indirect call with an attacker-controlled argument.

The precise corruption point is the key-string allocation in
`_zend_hash_str_add_or_update_i()` (`Zend/zend_hash.c:960`):

```
add_to_hash:
    idx = ht->nNumUsed++;                       // (1) bumped FIRST
    ht->nNumOfElements++;                       // (2) bumped
    p = ht->arData + idx;
    p->key = key = zend_string_init(str, len, ...);   // (3) OOM -> zend_bailout
```

An OOM at (3) longjmps out after (1)/(2), leaving the last bucket's `key`/`val`
unwritten. Shutdown then walks that bucket; a zeroed bucket is skipped
(`IS_UNDEF`), but a bucket reused from attacker-controlled memory yields a
garbage `pDestructor`/`key` → arbitrary call. Verified by
`exploits/cve-2026-109618-oom/`: the OOM lands on this exact allocation (see
the fatal's "tried to allocate <key size>" bytes). Making the garbage non-zero
is the same heap-grooming technique as the stale-state case (T-08).

This is the code-execution primitive we target for file read.

## 5. Key source references (PHP 8.5.11)

| Location | Function / struct | Role |
|----------|-------------------|------|
| `Zend/zend_alloc.c:395` | `zend_mm_safe_error()` | OOM handler that `longjmp`s |
| `Zend/zend_alloc.c:418` | `zend_bailout()` | the unsafe early exit |
| `Zend/zend_hash.c:261` | `_zend_hash_init_int()` | header init incl. `pDestructor` |
| `Zend/zend_hash.c:1730` | `zend_hash_destroy()` | indirect call `ht->pDestructor()` |
| `Zend/zend.c:263` | `fatal_error_backtraces` INI (default `1`) | enables backtrace producer |
| `Zend/zend.c:1499` | `zend_error_zstr_at()` | producer: `zend_fetch_debug_backtrace(&EG(last_fatal_error_backtrace))` |
| `Zend/zend.c:1501` | `zval_ptr_dtor(&EG(last_fatal_error_backtrace))` | **consumer**: frees the stale backtrace -> UAF |
| `Zend/zend_execute_API.c:309` | backtrace reset in `zend_shutdown_executor_values()` | skipped (`fast_shutdown` always true) |
| `Zend/zend_execute_API.c:446` | `fast_shutdown = is_zend_mm() && !full_tables_cleanup` | always true on default build |
| `ext/standard/dl.c:71` | `EG(full_tables_cleanup) = 1` | only place it is set -> always 0 by default |
| `main/main.c:1389` | `php_error_cb()` | reads backtrace for display (after dtor already freed it) |
| `main/main.c:1307` | `clear_last_error()` | frees `PG(last_error_message/file)` (stale if skipped) |
| `main/main.c:1960` | `php_request_shutdown()` | step 8 destroys `PG(http_globals)`, step 15 frees heap |
| `main/rfc1867.c` | `multipart_buffer_headers/read_body`, `rfc1867_post_handler` | OOM amplifiers |
| `main/php_variables.c:219` | `php_register_variable_ex()` | nested-name array allocation |
| `ext/session/session.c:3180` | `php_session_rfc1867_update()` | pre-RINIT consumer (session) |

## 6. What is *not* in scope (per requirements)

Reachability by misconfiguration is explicitly excluded: a PHP variable that can
read `/etc/passwd` through an ordinary filesystem/IO call is **not** an exploit.
The PoC must obtain file read through the memory-corruption primitive above
(UAF → info-leak → indirect call → file read), not through a permissive PHP
script.
