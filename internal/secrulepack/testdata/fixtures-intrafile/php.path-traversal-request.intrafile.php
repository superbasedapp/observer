<?php

// Cross-function taint in one file (--taint-intrafile): the request value is
// handed to a helper that holds the sink, or a helper returns it.
function use_value($value)
{
    // ruleid: php.path-traversal-request
    readfile('/srv/files/' . $value);
}

function wanted()
{
    return $_GET['name'];
}

// The sanitizer sits in the helper.
function cleaned($value)
{
    return basename($value);
}

function handler()
{
    use_value($_GET['name']);
    // ruleid: php.path-traversal-request
    readfile('/srv/files/' . wanted());
    // ok: php.path-traversal-request
    readfile('/srv/files/' . cleaned($_GET['name']));
}
