<?php

// Cross-function taint in one file (--taint-intrafile): the request value is
// handed to a helper that holds the sink, or a helper returns it.
function use_value($value)
{
    // ruleid: php.ssrf-request-url
    $ch = curl_init($value);
}

function wanted()
{
    return $_GET['url'];
}

// The sanitizer sits in the helper.
function cleaned($value)
{
    return urlencode($value);
}

function handler()
{
    use_value($_GET['url']);
    // ruleid: php.ssrf-request-url
    $ch = curl_init(wanted());
    // ok: php.ssrf-request-url
    $ch = curl_init(cleaned($_GET['url']));
}
