<?php

// Cross-function taint in one file (--taint-intrafile): the request value is
// handed to a helper that holds the sink, or a helper returns it.
function use_value($value)
{
    // ruleid: php.shell-interpolation
    exec('convert ' . $value . ' out.png');
}

function wanted()
{
    return $_GET['file'];
}

// The sanitizer sits in the helper.
function cleaned($value)
{
    return escapeshellarg($value);
}

function handler()
{
    use_value($_GET['file']);
    // ruleid: php.shell-interpolation
    exec('convert ' . wanted() . ' out.png');
    // ok: php.shell-interpolation
    exec('convert ' . cleaned($_GET['file']) . ' out.png');
}
