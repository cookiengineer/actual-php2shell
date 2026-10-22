<?php
// Minimal 2-frame fatal producer for CVE-2026-109619 heap-feng-shui work.
// Keeps the backtrace small so its allocations land at predictable, low-ish
// pages (H ~ page 3, packed-zval array D ~ page 121, arg string ~ page 131).
function boom($arg) { trigger_error("t", E_USER_ERROR); }
boom(str_repeat("X", 32));
