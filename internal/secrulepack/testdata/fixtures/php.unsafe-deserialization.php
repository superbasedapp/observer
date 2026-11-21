<?php

function restore($request)
{
    $blob = base64_decode($_COOKIE['state']);
    // ruleid: php.unsafe-deserialization
    $state = unserialize($blob);
    // ruleid: php.unsafe-deserialization
    $cart = unserialize($request->input('cart'));
    // ruleid: php.unsafe-deserialization
    $prefs = unserialize(file_get_contents('php://input'));
    return [$state, $cart, $prefs];
}

function safe($request)
{
    // ok: php.unsafe-deserialization
    $state = unserialize(base64_decode($_COOKIE['state']), ['allowed_classes' => false]);
    // ok: php.unsafe-deserialization
    $cart = json_decode($request->input('cart'), true);
    return [$state, $cart];
}

// The program's own values, not request input.
function cached(string $path)
{
    // ok: php.unsafe-deserialization
    return unserialize(file_get_contents($path));
}
