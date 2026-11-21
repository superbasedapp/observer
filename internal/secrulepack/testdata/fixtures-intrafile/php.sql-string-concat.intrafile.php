<?php

// Cross-function taint in one file (--taint-intrafile): the request value is
// handed to a helper that holds the sink, or a helper returns it.
function use_value($value)
{
    // ruleid: php.sql-string-concat
    $rows = mysqli_query($GLOBALS['db'], "SELECT * FROM users WHERE name = '" . $value . "'");
}

function wanted()
{
    return $_GET['name'];
}

// The sanitizer sits in the helper.
function cleaned($value)
{
    return (int) $value;
}

function handler()
{
    use_value($_GET['name']);
    // ruleid: php.sql-string-concat
    $rows = mysqli_query($GLOBALS['db'], "SELECT * FROM users WHERE name = '" . wanted() . "'");
    // ok: php.sql-string-concat
    $rows = mysqli_query($GLOBALS['db'], "SELECT * FROM users WHERE name = '" . cleaned($_GET['name']) . "'");
}
