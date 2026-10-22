# Implementation Plan

How the reproducibly-exploitable target and the exploit tooling are built.

## 1. Directory layout

```
actual-php2shell/
├── affected-versions/        # vendored VULNERABLE PHP tarballs + SHA256SUMS
├── patched-versions/         # vendored PATCHED PHP tarball (negative control)
├── references/               # advisories (input)
├── docs/                     # this plan, exploit plan, attack surface, task tracking
├── container/
│   ├── base/                 # shared Apache+PHP build (ARG PHP_VERSION / PHP_TARBALL)
│   │   ├── Containerfile
│   │   ├── php.ini / php.conf / mpm.conf
│   │   └── app/ (index.php, fatal.php)
│   ├── cve-2026-109618-oom/          # T-06 target (vulnerable, plain vhost)
│   ├── cve-2026-109619-stale-state/  # T-08..T-11 target (vulnerable + diagnostic consumer)
│   └── negative-control/             # T-13 target (patched 8.5.12, same config)
└── exploits/
    ├── lib/                  # shared raw-socket HTTP client
    ├── cve-2026-109618-oom/          # OOM strategies PoC
    ├── cve-2026-109619-stale-state/  # UAF -> leak -> RCE PoC
    └── negative-control/             # same exploit vs patched build
```

Each case is a standalone PoC with its own container image and exploit scripts
(see `exploits/README.md`).

## 2. Victim container

### 2.1 Image

- Base: `debian:bookworm-slim` (stable glibc, reproducible).
- Apache 2.4 from Debian (`apache2`), built PHP **8.5.11** from the vendored
  `affected-versions/php-8.5.11.tar.xz` (copied into the image at build time, so
  the build is hermetic and does not re-fetch from the network).
- Configure flags (mod_php):
  ```
  --with-apxs2=/usr/bin/apxs2 --enable-debug --disable-cgi --disable-phpdbg
  --with-config-file-path=/etc/php8 --with-config-file-scan-dir=/etc/php8/conf.d
  --enable-mbstring --enable-session  (session is built-in)
  ```
  `--enable-debug` keeps symbols and disables the Zend MM `USE_ZEND_ALLOC=0`
  confusion; we keep the *default* Zend allocator so the target is realistic.
- Keep default limits (`memory_limit=128M`, `post_max_size=8M`,
  `session.upload_progress.enabled=On`, `fatal_error_backtraces=On`), matching
  the advisory's "default configuration" claim.

### 2.2 Worker model

`StartServers 1 / MaxSpareServers 1 / MaxRequestWorkers 1` (single prefork
worker) so the producer and consumer requests deterministically land on the
same worker. This is a reproducibility aid, not a mitigation bypass; the
advisory explicitly states multiple workers only reduce per-request success.

### 2.3 App

A single `index.php` that echoes a fixed string and never opens files. It exists
only to prove the exploit is application-independent. A `/etc/passwd` and a
`/secret.txt` marker exist in the image.

### 2.4 Mitigations

Full defaults: ASLR + PIE + NX + full RELRO. The exploit must contain its own
info-leak stage; the container does not disable any mitigation.

### 2.5 Build / run

```
podman build -f container/Containerfile -t php-rce-target .
podman run --rm -p 127.0.0.1:8080:80 php-rce-target
```

## 3. Attacker tooling

Pure Python 3 standard library (`http.client` / raw sockets). Raw sockets are
required because the OOM producers need precise control over `Content-Length`
and chunked/multipart framing (no client auto-normalization).

## 4. Verification gates

1. `php -v` in container reports `8.5.11` (pre-patch).
2. A known-affected `.phpt`-style check: sending the OOM multipart producer
   followed by the consumer yields a controlled crash / ASAN UAF report under
   `gdb`.
3. `exploit.py --read /secret.txt` returns the file contents over HTTP.
4. The same binary target, when the patch commit is applied and rebuilt, is
   **not** exploitable (negative control).
