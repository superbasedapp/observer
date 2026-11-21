<?php

const BASE = '/srv/uploads/';

function download($request)
{
    $name = $_GET['name'];
    // ruleid: php.path-traversal-request
    readfile(BASE . $name);
    // ruleid: php.path-traversal-request
    $data = file_get_contents("/srv/reports/{$_POST['report']}.csv");
    // ruleid: php.path-traversal-request
    include $_GET['page'] . '.php';
    // ruleid: php.path-traversal-request
    unlink(BASE . $request->input('file'));
    // ruleid: php.path-traversal-request
    return response()->download(storage_path('exports/' . $request->query('export')));
}

function upload()
{
    // ruleid: php.path-traversal-request
    move_uploaded_file($_FILES['doc']['tmp_name'], BASE . $_FILES['doc']['name']);
}

function safe($request)
{
    // ok: php.path-traversal-request
    readfile(BASE . basename($_GET['name']));
    // ok: php.path-traversal-request
    $data = file_get_contents('/srv/reports/report-' . (int) $_GET['id'] . '.csv');
    // ok: php.path-traversal-request
    file_put_contents(BASE . 'upload.bin', $_POST['body']);
    // ok: php.path-traversal-request
    include __DIR__ . '/views/header.php';
    // ok: php.path-traversal-request
    $cached = file_get_contents('/srv/cache/' . sha1($_GET['url']) . '.json');
    // ok: php.path-traversal-request
    require_once $_SERVER['DOCUMENT_ROOT'] . '/config.php';
    return $data;
}

// The program's own values, not request input.
function cleanup(string $dir)
{
    // ok: php.path-traversal-request
    rmdir(BASE . $dir);
}
