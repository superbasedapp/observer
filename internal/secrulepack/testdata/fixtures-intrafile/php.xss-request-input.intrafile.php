<?php

// Cross-function taint in one file (--taint-intrafile): the request value is
// handed to a helper that holds the sink, or a helper returns it.
function use_value($value)
{
    // ruleid: php.xss-request-input
    echo '<p>' . $value . '</p>';
}

function wanted()
{
    return $_GET['title'];
}

// The sanitizer sits in the helper.
function cleaned($value)
{
    return htmlspecialchars($value);
}

function handler()
{
    use_value($_GET['title']);
    // ruleid: php.xss-request-input
    echo '<p>' . wanted() . '</p>';
    // ok: php.xss-request-input
    echo '<p>' . cleaned($_GET['title']) . '</p>';
}
