<?php

function convert($request)
{
    $file = $_GET['file'];
    // ruleid: php.shell-interpolation
    exec("convert $file out.png", $out);
    // ruleid: php.shell-interpolation
    $listing = shell_exec('ls -la ' . $_POST['dir']);
    // ruleid: php.shell-interpolation
    system("ping -c 1 " . $request->input('host'));
    // ruleid: php.shell-interpolation
    $size = `du -sh {$_GET['path']}`;
    // ruleid: php.shell-interpolation
    passthru('tar czf - ' . $_COOKIE['folder']);
    // ruleid: php.shell-interpolation
    $p = Process::fromShellCommandline('git log ' . $request->query('ref'));
    return [$out, $listing, $size, $p];
}

function safe($request)
{
    // ok: php.shell-interpolation
    exec('convert ' . escapeshellarg($_GET['file']) . ' out.png');
    // ok: php.shell-interpolation
    system('kill -HUP ' . (int) $_GET['pid']);
    // ok: php.shell-interpolation
    $proc = proc_open(['convert', $_GET['file'], 'out.png'], [], $pipes);
    // ok: php.shell-interpolation
    $p = new Process(['git', 'log', $request->query('ref')]);
    return [$proc, $p];
}

// The program's own values, not request input.
function rotate(string $path)
{
    // ok: php.shell-interpolation
    exec("logrotate $path");
}
