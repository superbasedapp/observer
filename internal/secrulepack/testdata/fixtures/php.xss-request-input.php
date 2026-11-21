<?php

function results($request)
{
    $q = $_GET['q'];
    // ruleid: php.xss-request-input
    echo "<p>Results for $q</p>";
    // ruleid: php.xss-request-input
    print '<h1>' . $_POST['title'] . '</h1>';
    // ruleid: php.xss-request-input
    printf('<a href="%s">back</a>', $_SERVER['HTTP_REFERER']);
    // ruleid: php.xss-request-input
    echo $_SERVER['PHP_SELF'];
    // ruleid: php.xss-request-input
    return response('<div>' . $request->input('note') . '</div>');
}

function fail()
{
    // ruleid: php.xss-request-input
    die('Unknown item: ' . $_GET['item']);
}

function safe($request)
{
    // ok: php.xss-request-input
    echo '<p>Results for ' . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') . '</p>';
    // ok: php.xss-request-input
    echo 'Page ' . (int) $_GET['page'];
    // ok: php.xss-request-input
    echo e($request->input('name'));
    // ok: php.xss-request-input
    echo esc_html($_POST['comment']);
    // ok: php.xss-request-input
    echo $_SERVER['SERVER_NAME'];
}

// The program's own values, not request input.
function badge(string $label)
{
    // ok: php.xss-request-input
    echo "<span class=\"badge\">$label</span>";
}
// A short echo tag in a template.
// ruleid: php.xss-request-input
?><p><?= $_GET['message'] ?></p>
<?php
// ok: php.xss-request-input
?><p><?= htmlspecialchars($_GET['message']) ?></p>
