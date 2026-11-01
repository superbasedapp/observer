<#
.SYNOPSIS
  One light, read-only live check of the Windows sandbox driver (MXC
  ProcessContainer, lane SBX-P6, sandbox plan v2 section 13.10 register
  WIN-1 to WIN-4), ending with a receipt block to paste back.

.DESCRIPTION
  Runs exactly ONE named check per invocation, each under a time limit.
  It installs nothing, changes no setting, starts no service, never
  restarts or reboots anything, and writes only to a temporary directory it
  removes before it exits. Run it from a normal (not elevated) PowerShell,
  one check at a time, never during a render. The operator ruling P-047
  ("Yes, light checks only") governs: building and tests happen elsewhere.

  Checks:
    build-info     Windows build, UBR, edition and version; `wsl --version`;
                   `observer --version`. Nothing MXC is touched.
    files          The bundled MXC files beside observer.exe: present, their
                   sha256 against the pins, their Authenticode status and
                   signer. Nothing is loaded or run.
    mxc-version    Loads the verified mxc_ffi.dll in a short-lived helper
                   (`observer sandbox-mxc-probe --stage version`) and reads
                   mxc_version(). Nothing else is called.
    psec-probe     MXC's own request probe of a ProcessContainer policy
                   (`--stage request`): the tier MXC would choose, nothing
                   created (register WIN-4 on a Home build).
    create-close   MXC's create-and-close check (`--stage create`): one
                   ProcessContainer is created for `cmd /c exit 0` and
                   closed by MXC itself (destroyOnExit).
    launch-echo    The same plus one ProcessContainer run of
                   `cmd /c echo observer-mxc-echo-ok` (`--stage echo`).
    sandbox-status `observer sandbox status`: how the daemon's selection
                   table lists the mxc-process row on this machine.

.PARAMETER Check
  The one check to run.

.PARAMETER Observer
  The observer.exe to use (default: the one on PATH).

.PARAMETER TimeoutSeconds
  The check's time limit (default 60; the first run of a freshly updated
  binary can take seconds while Defender scans it).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\sandbox\p6-live-check.ps1 -Check build-info
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('build-info', 'files', 'mxc-version', 'psec-probe', 'create-close', 'launch-echo', 'sandbox-status')]
    [string]$Check,
    [string]$Observer = '',
    [ValidateRange(5, 600)]
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

# The pins of the bundled files (internal/sandboxmxc.ManifestX64,
# scripts/mxc-files.sh): MXC 1.0.1 from @microsoft/mxc-sdk.
$Pins = [ordered]@{
    'mxc_ffi.dll'  = 'bd45522f06dc9cc8001dcd5d7320bc2bf303fb08a39bf10f3404bd9a8001812c'
    'wxc-exec.exe' = '090f5d1f7bb93104ab08dcd4e8034ef954aeefcdaf6658dde5f7dff4cfc12f3a'
}

$started = Get-Date
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('observer-p6-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$lines = New-Object System.Collections.Generic.List[string]
$verdict = 'done'

function Add-Line([string]$s) { $script:lines.Add($s) | Out-Null }

function Find-Observer {
    if ($Observer -ne '') {
        if (-not (Test-Path -LiteralPath $Observer -PathType Leaf)) { throw "no observer.exe at $Observer" }
        return (Resolve-Path -LiteralPath $Observer).Path
    }
    $c = Get-Command observer.exe -ErrorAction SilentlyContinue
    if ($null -eq $c) { $c = Get-Command observer -ErrorAction SilentlyContinue }
    if ($null -eq $c) { throw 'observer.exe is not on PATH; pass -Observer <path>' }
    $p = $c.Source
    # An npm or pip shim points at the real binary; prefer a sibling .exe.
    if ($p -notlike '*.exe') {
        throw "observer on PATH is a shim ($p); pass -Observer <path to observer.exe>"
    }
    return $p
}

# Invoke-Bounded runs a program with a time limit, its output captured to
# files in the temp directory, and returns the exit code and the output.
function Invoke-Bounded([string]$file, [string[]]$argv) {
    $out = Join-Path $tmp 'out.txt'
    $err = Join-Path $tmp 'err.txt'
    $p = Start-Process -FilePath $file -ArgumentList $argv -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    # Touch the handle so ExitCode is kept after the process ends.
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
        try { $p.Kill() } catch { }
        $script:verdict = 'timed_out'
        return @{ Code = -1; Out = "timed out after $TimeoutSeconds s"; Err = '' }
    }
    $o = if (Test-Path $out) { Get-Content -Raw -LiteralPath $out } else { '' }
    $e = if (Test-Path $err) { Get-Content -Raw -LiteralPath $err } else { '' }
    # Get-Content -Raw returns $null for an empty file (finding L4).
    if ($null -eq $o) { $o = '' }
    if ($null -eq $e) { $e = '' }
    return @{ Code = $p.ExitCode; Out = $o; Err = $e }
}

function Get-ProductName($cv) {
    # The registry ProductName still says "Windows 10" on Windows 11 (live
    # run 2026-10-22); the OS caption does not. Without the caption, build
    # 22000 and up is Windows 11.
    try {
        $cap = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption
        if ($cap) { return ($cap -replace '^Microsoft\s+', '').Trim() }
    } catch { }
    $name = "$($cv.ProductName)"
    $build = 0
    if ([int]::TryParse("$($cv.CurrentBuildNumber)", [ref]$build) -and $build -ge 22000) {
        $name = $name -replace 'Windows 10', 'Windows 11'
    }
    return $name
}

function Get-BuildFacts {
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $ubr = if ($cv.PSObject.Properties['UBR']) { $cv.UBR } else { '?' }
    $disp = if ($cv.PSObject.Properties['DisplayVersion']) { $cv.DisplayVersion } else { '?' }
    return "$(Get-ProductName $cv) $disp, build $($cv.CurrentBuildNumber).$ubr, edition $($cv.EditionID)"
}

try {
    Add-Line ("host: " + (Get-BuildFacts))
    switch ($Check) {
        'build-info' {
            try {
                $r = Invoke-Bounded 'wsl.exe' @('--version')
                Add-Line ('wsl --version (exit ' + $r.Code + '):')
                Add-Line (($r.Out -replace "`0", '').Trim())
            } catch { Add-Line ('wsl --version: ' + $_.Exception.Message) }
            try {
                $obs = Find-Observer
                $r = Invoke-Bounded $obs @('--version')
                Add-Line ("observer: $obs")
                Add-Line ('observer --version: ' + $r.Out.Trim())
            } catch { Add-Line ("observer: " + $_.Exception.Message) }
        }
        'files' {
            $obs = Find-Observer
            $dir = Join-Path (Split-Path -Parent $obs) 'mxc'
            Add-Line ("bundle dir: $dir")
            foreach ($name in $Pins.Keys) {
                $p = Join-Path $dir $name
                if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { Add-Line ("$name : MISSING"); $verdict = 'artifact_missing'; continue }
                $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLowerInvariant()
                $match = if ($h -eq $Pins[$name]) { 'matches the pin' } else { $verdict = 'artifact_unverified'; 'DOES NOT match the pin' }
                $sig = Get-AuthenticodeSignature -LiteralPath $p
                $subject = if ($null -ne $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '(none)' }
                Add-Line ("$name : $((Get-Item -LiteralPath $p).Length) bytes, sha256 $h ($match), signature $($sig.Status), signer $subject")
            }
            $m = Join-Path $dir 'mxc-manifest.json'
            if (Test-Path -LiteralPath $m) { Add-Line ('manifest: ' + ((Get-Content -Raw -LiteralPath $m) -replace '\s+', ' ')) }
        }
        { $_ -in 'mxc-version', 'psec-probe', 'create-close', 'launch-echo' } {
            $stage = @{ 'mxc-version' = 'version'; 'psec-probe' = 'request'; 'create-close' = 'create'; 'launch-echo' = 'echo' }[$Check]
            $obs = Find-Observer
            $r = Invoke-Bounded $obs @('sandbox-mxc-probe', '--active', '--stage', $stage)
            Add-Line ("observer sandbox-mxc-probe --active --stage $stage (exit $($r.Code)):")
            Add-Line ($r.Out.Trim())
            if ($r.Err.Trim() -ne '') { Add-Line ('stderr: ' + $r.Err.Trim()) }
            if ($r.Code -ne 0 -and $verdict -eq 'done') { $verdict = 'helper_failed' }
        }
        'sandbox-status' {
            $obs = Find-Observer
            $r = Invoke-Bounded $obs @('sandbox', 'status')
            Add-Line ("observer sandbox status (exit $($r.Code)):")
            Add-Line ($r.Out.Trim())
        }
    }
} catch {
    $verdict = 'error'
    Add-Line ('error: ' + $_.Exception.Message)
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$elapsed = [int]((Get-Date) - $started).TotalMilliseconds
$body = ($lines -join "`n")
if ($body.Length -gt 6000) { $body = $body.Substring(0, 6000) + "`n(truncated)" }
Write-Output ''
Write-Output '===== P6 LIVE CHECK RECEIPT (paste everything up to END) ====='
Write-Output ("check:    $Check")
Write-Output ("when:     " + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
Write-Output ("verdict:  $verdict")
Write-Output ("elapsed:  $elapsed ms (limit $TimeoutSeconds s)")
Write-Output ("temp dir: removed")
Write-Output $body
Write-Output '===== END P6 LIVE CHECK RECEIPT ====='
