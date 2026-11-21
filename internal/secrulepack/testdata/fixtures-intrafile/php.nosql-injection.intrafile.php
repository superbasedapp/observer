<?php

// Cross-function taint in one file (--taint-intrafile): the request value is
// handed to a helper that holds the sink, or a helper returns it.
function use_value($value)
{
    // ruleid: php.nosql-injection
    $usersCollection = users_collection(); $user = $usersCollection->findOne(['name' => $value]);
}

function wanted()
{
    return $_POST['name'];
}

// The sanitizer sits in the helper.
function cleaned($value)
{
    return (string) $value;
}

function handler()
{
    use_value($_POST['name']);
    // ruleid: php.nosql-injection
    $usersCollection = users_collection(); $user = $usersCollection->findOne(['name' => wanted()]);
    // ok: php.nosql-injection
    $usersCollection = users_collection(); $user = $usersCollection->findOne(['name' => cleaned($_POST['name'])]);
}
