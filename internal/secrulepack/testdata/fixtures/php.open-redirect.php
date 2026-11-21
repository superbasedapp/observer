<?php

function login_done($request)
{
    $target = $_GET['next'];
    // ruleid: php.open-redirect
    header('Location: ' . $target);
    // ruleid: php.open-redirect
    header("Location: {$_POST['return_to']}");
    // ruleid: php.open-redirect
    header('Location: //' . $_GET['host'] . '/welcome');
    // ruleid: php.open-redirect
    return redirect($request->input('return_to'));
}

function back($request)
{
    // ruleid: php.open-redirect
    return redirect()->away($request->query('url'));
}

function wp($request)
{
    // ruleid: php.open-redirect
    wp_redirect($_REQUEST['redirect_to']);
    exit;
}

function safe($request)
{
    // ok: php.open-redirect
    header('Location: /items/' . $_GET['id']);
    // ok: php.open-redirect
    header('Location: https://shop.example.com/cart?item=' . $_GET['item']);
    // ok: php.open-redirect
    header('X-Request-Id: ' . $_GET['rid']);
    $page = Page::findOrFail($request->input('id'));
    // ok: php.open-redirect
    redirect($page->getUrl());
    // ok: php.open-redirect
    redirect(route('pages.show', ['id' => $request->input('id')]));
    // ok: php.open-redirect
    return redirect('/dashboard?tab=' . $request->query('tab'));
}

// The program's own values, not request input.
function home(string $path)
{
    // ok: php.open-redirect
    header('Location: ' . $path);
}
