<?php

function search(mysqli $db, PDO $pdo, $request)
{
    $name = $_GET['name'];
    // ruleid: php.sql-string-concat
    $rows = mysqli_query($db, "SELECT * FROM users WHERE name = '$name'");
    // ruleid: php.sql-string-concat
    $stmt = $pdo->query("SELECT * FROM users WHERE id = " . $_POST['id']);
    // ruleid: php.sql-string-concat
    $users = DB::select("SELECT * FROM users WHERE email = '{$request->input('email')}'");
    // ruleid: php.sql-string-concat
    $sorted = User::query()->orderByRaw($request->query('sort') . ' DESC')->get();
    // ruleid: php.sql-string-concat
    $pdo->exec('DELETE FROM sessions WHERE token = "' . $_COOKIE['token'] . '"');
    return [$rows, $stmt, $users, $sorted];
}

function wordpress($wpdb)
{
    // ruleid: php.sql-string-concat
    $wpdb->get_results("SELECT * FROM {$wpdb->posts} WHERE post_title = '" . $_REQUEST['title'] . "'");
    // ok: php.sql-string-concat
    $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE post_title = %s", $_REQUEST['title']));
}

function safe(mysqli $db, PDO $pdo, $request)
{
    // ok: php.sql-string-concat
    $stmt = $pdo->prepare('SELECT * FROM users WHERE name = ?');
    $stmt->execute([$_GET['name']]);
    // ok: php.sql-string-concat
    $rows = mysqli_query($db, 'SELECT * FROM users WHERE id = ' . (int) $_GET['id']);
    // ok: php.sql-string-concat
    $users = DB::select('SELECT * FROM users WHERE email = ?', [$request->input('email')]);
    // ok: php.sql-string-concat
    $more = $pdo->query('SELECT * FROM users WHERE name = ' . $pdo->quote($_GET['name']));
    // ok: php.sql-string-concat
    $dbi->query('SELECT * FROM t WHERE c = ' . $dbi->quoteString($_POST['c']));
    // ok: php.sql-string-concat
    $esc = mysqli_query($db, "SELECT * FROM t WHERE c = '" . mysqli_real_escape_string($db, $_GET['c']) . "'");
    return [$rows, $users, $more, $esc];
}

// The program's own values, not request input.
function report(PDO $pdo, string $column)
{
    // ok: php.sql-string-concat
    return $pdo->query("SELECT $column FROM stats");
}
