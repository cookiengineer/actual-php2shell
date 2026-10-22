# Task Tracking

Each task maps to a standalone demo case: its own container image
(`container/<case>/`) and exploit scripts (`exploits/<case>/`). See
`exploits/README.md`.

Columns:

- **Case** = demo folder (`exploits/<case>/`)
- **Impl** = implementation state (code/build exists)
- **Exploit** = exploit state (primitive actually behaves as intended)
- **E2E** = verified end-to-end remotely against the victim container

Legend:

| Code | Meaning |
|------|---------|
| `-` | not started |
| `wip` | in progress |
| `done` | complete |
| `crash` | reaches a crash/UAF but not controlled |
| `prim` | primitive confirmed (controlled behavior) |
| `work` | working end-to-end |
| `n/a` | not applicable to this task |
| `block` | blocked (see notes) |

## Tasks

| ID | Case | Task | Impl | Exploit | E2E | Notes / blocker |
|----|------|------|------|---------|-----|-----------------|
| T-01 | — | Vendor affected versions into `affected-versions/` (+ patched into `patched-versions/`) | done | n/a | n/a | 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11 / 8.5.12 |
| T-02 | — | Write docs (attack-surface, impl, exploit, tasks) | done | n/a | n/a | |
| T-03 | — | Shared base `container/base/Containerfile` | done | n/a | n/a | parameterized (vuln 8.5.11 / patched 8.5.12) |
| T-04 | — | Build base images; verify PHP + mod_php | done | n/a | n/a | `php -v`=8.5.11/8.5.12 |
| T-05 | — | Restructure into per-case containers + exploits | done | n/a | n/a | 3 standalone cases |
| T-06 | `cve-2026-109618-oom` | OOM corruption trigger | done | prim | - | CONFIRMED via `a[<large>][c]=v` (bracket-key): OOM lands on the key-copy `zend_string_init` in `_zend_hash_str_add_or_update_i` after `nNumUsed++`, leaving `$_POST["a"]`'s last bucket unwritten; walked by `zend_array_destroy`→`i_zval_ptr_dtor`. Next: groom the unwritten bucket's `val` to IS_OBJECT |
| T-07 | `cve-2026-109619-stale-state` | Confirm stale-backtrace UAF crash | done | work | work | `run.sh uaf` -> `zend_mm_heap corrupted` -> SIGABRT |
| T-08 | `cve-2026-109619-stale-state` | Heap groom: control freed `zend_array` | - | - | - | shared technique for both CVEs; needs allocator layout under gdb |
| T-09 | `cve-2026-109619-stale-state` | Info-leak: fake `zend_string` read | - | - | - | scaffold in `leak.py` |
| T-10 | `cve-2026-109619-stale-state` | ASLR bypass: leak heap+libc+PIE | - | - | - | depends on T-09 |
| T-11 | `cve-2026-109618-oom` | Arbitrary call -> file read | done | work | work | RCE achieved: OOM unwritten bucket -> `free_obj` hijack -> `system("cat /etc/passwd")` (ASLR-off; `rce.py`) |
| T-12 | `cve-2026-109619-stale-state` | `exploit.py read <file>` end-to-end | partial | - | - | `uaf` wired; `read` not yet |
| T-13 | `negative-control` | Patched rebuild not exploitable | done | work | work | `CONTROL PASSED` (5/5 requests survived) |
| T-14 | `cve-2026-109619-info-leak` | Info-leak + ASLR bypass (addresses) | done | prim | - | gdb/`setarch -R` measured heap/libphp/libc + backtrace H/D addresses; over-HTTP read needs session consumer or grooming (`docs/info-leak.md`) |

## Current status

- **E2E=work (verified):**
  - `cve-2026-109619-stale-state`: stale fatal-backtrace use-after-free ->
    deterministic worker crash (`zend_mm_heap corrupted` -> SIGABRT).
  - `negative-control`: identical sequence against patched 8.5.12 survives,
    proving the PoC exploits the vulnerability, not a misconfiguration.
  - `cve-2026-109618-oom`: **RCE achieved (ASLR-off)** — OOM leaves an unwritten
    bucket in `$_POST["a"]`; `free_obj` object-handler hijack -> ROP ->
    `system("cat /etc/passwd > /var/www/html/leak.txt")` -> `GET /leak.txt`
    returns the file (`rce.py`, see `docs/heap-feng-shui.md` §8.16).
- **Primitive confirmed (verified):**
  - `cve-2026-109618-oom`: OOM lands on the corrupting allocation — the hash
    key `zend_string_init()` inside `_zend_hash_str_add_or_update_i()` after
    `nNumUsed++` — leaving the last bucket unwritten.
- **Deep analysis complete (see `docs/memory-layout.md`):**
  - Exact backtrace object layout (packed array: H=56B header, D=1024B packed
    zvals), the `zend_objects_store_del` indirect call site (rdi=object,
    rdx=handlers), an NX-safe stack pivot (`jump_fcontext+0x30`), and a
    complete ROP chain (`pop rdi; ret` + `system`) with measured addresses.
  - `exploits/cve-2026-109619-stale-state/rop.py` implements the payload
    generator.
- **Remaining (not yet verified):** the heap-feng-shui grooming that places the
  ROP payload into the dangling target. The two analyzed consumers either
  double-free the intact header (INI diagnostic -> crash, no control) or
  reallocate H as the autoglobal array (second fatal -> harmless). The intended
  path is the double-free of a backtrace *argument string* (controlled by the
  producer's fatal-error args) to place a controlled chunk on the Zend MM free
  list twice. Tracked as T-08..T-11.

## End-to-end proof

The PoC is considered done when **T-12** reports `E2E = work`:

```
$ ./exploits/cve-2026-109619-stale-state/run.sh read /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
```
