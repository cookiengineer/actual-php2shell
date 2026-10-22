# Affected PHP versions

Pinned, vendored copies of the PHP releases that are affected by the 2026 PHP
RCE class, taken from the official `php.net` distribution mirror **before** they
are potentially unpublished or superseded.

These are the **most recent affected release per supported branch** as of the
advisories. The patched releases are one version higher on each branch.

| Branch | Affected (vendored) | Patched | CVE-2026-109618 (OOM) | CVE-2026-109619 (stale state) |
|--------|---------------------|---------|------------------------|-------------------------------|
| 8.2    | 8.2.34              | 8.2.35  | yes                    | yes                           |
| 8.3    | 8.3.35              | 8.3.36  | yes                    | yes                           |
| 8.4    | 8.4.26              | 8.4.27  | yes                    | yes                           |
| 8.5    | 8.5.11              | 8.5.12  | yes                    | yes (`fatal_error_backtraces`) |

## Files

- `php-8.2.34.tar.xz`
- `php-8.3.35.tar.xz`
- `php-8.4.26.tar.xz`
- `php-8.5.11.tar.xz`
- `SHA256SUMS` — integrity manifest

## Provenance

Downloaded from `https://www.php.net/distributions/php-<version>.tar.xz`.

```
$ sha256sum -c SHA256SUMS
```

## Primary target

The end-to-end PoC targets **PHP 8.5.11** (most recent affected release) because:

1. It is the newest affected branch and the one the advisories describe the
   strongest *confirmed* case for (`fatal_error_backtraces` producer for
   CVE-2026-109619).
2. It contains the `fatal_error_backtraces` INI knob (default `On`) used by the
   stale-global-state primitive.

The other three tarballs are retained so the container can be rebuilt against
any branch to test version portability.
