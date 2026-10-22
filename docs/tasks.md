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
| T-06 | `cve-2026-109618-oom` | OOM corruption trigger | done | wip | - | OOM reaches limit cleanly; corruption (global-write) trigger not yet pinned |
| T-07 | `cve-2026-109619-stale-state` | Confirm stale-backtrace UAF crash | done | work | work | `run.sh uaf` -> `zend_mm_heap corrupted` -> SIGABRT |
| T-08 | `cve-2026-109619-stale-state` | Heap groom: control freed `zend_array` | - | - | - | needs allocator layout under gdb |
| T-09 | `cve-2026-109619-stale-state` | Info-leak: fake `zend_string` read | - | - | - | scaffold in `leak.py` |
| T-10 | `cve-2026-109619-stale-state` | ASLR bypass: leak heap+libc+PIE | - | - | - | depends on T-09 |
| T-11 | `cve-2026-109619-stale-state` | Arbitrary call -> file read | - | - | - | RCE-first; depends on T-10 |
| T-12 | `cve-2026-109619-stale-state` | `exploit.py read <file>` end-to-end | partial | - | - | `uaf` wired; `read` not yet |
| T-13 | `negative-control` | Patched rebuild not exploitable | done | work | work | `CONTROL PASSED` (5/5 requests survived) |

## Current status

- **E2E=work (confirmed):**
  - `cve-2026-109619-stale-state`: stale fatal-backtrace use-after-free ->
    deterministic worker crash (`zend_mm_heap corrupted` -> SIGABRT).
  - `negative-control`: identical sequence against patched 8.5.12 survives,
    proving the PoC exploits the vulnerability, not a misconfiguration.
- **In progress:** `cve-2026-109618-oom` corruption trigger (T-06), and the
  stale-state grooming/leak/RCE stages (T-08..T-11).

## End-to-end proof

The PoC is considered done when **T-12** reports `E2E = work`:

```
$ ./exploits/cve-2026-109619-stale-state/run.sh read /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
```
