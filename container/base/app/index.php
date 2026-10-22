<?php
// Application-independent target: the exploit must not rely on any PHP code
// here. This page does no filesystem IO and returns a fixed string.
header('Content-Type: text/plain');
echo "ok\n";
