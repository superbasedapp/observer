<?php

// Cross-function taint in one file (--taint-intrafile): the request value is
// handed to a helper that holds the sink, or a helper returns it.
function use_value($value)
{
    // ruleid: php.unsafe-deserialization
    $state = unserialize($value);
}

function wanted()
{
    return $_COOKIE['state'];
}

// No sanitizer exists for this sink: the helper ignores its input and
// returns the program's own value.
function cleaned($value)
{
    return DEFAULT_STATE;
}

function handler()
{
    use_value($_COOKIE['state']);
    // ruleid: php.unsafe-deserialization
    $state = unserialize(wanted());
    // ok: php.unsafe-deserialization
    $state = unserialize(cleaned($_COOKIE['state']));
}
