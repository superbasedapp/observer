<#
.SYNOPSIS
  Install a SuperBased Observer edition on Windows.

.DESCRIPTION
  install.ps1 [-Edition minimal|developer|managed|full] [-Version vX.Y.Z]
              [-Prefix DIR] [-FromDir DIR] [-BaseUrl URL]
              [-RequireSignature] [-AddToPath] [-Uninstall [-Purge] [-Force]]
              [-DryRun] [-Yes]

  -Edition          minimal | developer | managed | full (default: a menu on
                    an interactive console, otherwise developer)
  -Version          release to install, e.g. v1.36.0 or 1.36.0 (default:
                    latest, the newest FINAL release; a pre-release such as
                    v1.36.0-rc.1 is installed only when named)
  -Prefix           install directory (default:
                    %LOCALAPPDATA%\SuperBased\Observer\bin)
  -FromDir          install from a local directory holding the release
                    assets (the .zip, SHA256SUMS and <zip>.sig): air-gapped
                    installs and tests, no network at all
  -BaseUrl          an https mirror laid out like GitHub releases
                    (<url>/download/<tag>/<asset>); needs -Version
  -RequireSignature refuse unless the vendor signature is present and
                    verified
  -AddToPath        add the install directory to the USER Path without
                    asking (otherwise asked on an interactive console, and
                    only printed with -Yes)
  -Uninstall        run `observer uninstall --all` (hook, MCP and
                    proxy-route entries), then delete the binaries and the
                    user Path entry this installer added; %USERPROFILE%\.observer
                    is kept
  -Purge            with -Uninstall: also delete %USERPROFILE%\.observer
  -Force            install a second copy even though another observer
                    (npm, pip, another copy) is on Path or a daemon from
                    another install is running (the default: explain,
                    offer the package manager's upgrade command and
                    install nothing); with -Uninstall: delete the binaries
                    even when `observer uninstall --all` reports a problem
  -DryRun           say what would happen, change nothing
  -Yes              ask nothing, take the defaults

  Verification, before anything is written outside a temporary directory:
  the zip's SHA-256 must equal its line in the release's SHA256SUMS (a
  missing line or a mismatch is refused), and when the release publishes
  <zip>.sig (the raw 64-byte Ed25519 vendor signature over the archive
  bytes, the file the enterprise update system verifies against
  internal/update/vendorkey.go) it must verify against a vendor key
  compiled into this script. The verifier is built in (pure PowerShell
  over System.Numerics.BigInteger, RFC 8032) and checks the RFC 8032 test
  vector before it is trusted. A bad signature is always refused; an absent
  one is a warning unless -RequireSignature.

  Upgrading in place (an observer.exe already in the install directory): the
  installer says "Upgraded X -> Y". A running observer.exe cannot be
  overwritten, so it is renamed aside (<name>.exe.old-<time>, removed by the
  next install or uninstall) and keeps running the previous binary: the
  installer names its pid and the safe restart order and never stops it,
  because the daemon IS the proxy (docs/daemon-restart-runbook.md).

  The Windows sandbox files (lane SBX-P3B): an archive whose edition compiles
  the Windows sandbox driver carries mxc\ (mxc_ffi.dll, wxc-exec.exe and
  mxc-manifest.json). They are copied into mxc\ beside observer.exe only when
  the archive carries them, each file checked first against the archive's
  own mxc-manifest.json (its name, size and sha256; the archive itself was
  checked above), and a failure part way puts the previous set back whole.

  No telemetry. The only hosts contacted are api.github.com (to resolve
  "latest") and github.com (the release assets), or your -BaseUrl. It takes
  no token or credential.

  Run it with: powershell -ExecutionPolicy Bypass -File install.ps1 -Edition developer
  (the flag applies to that one process only; no system setting changes).
#>
[CmdletBinding()]
param(
  [string]$Edition = "",
  [string]$Version = "latest",
  [string]$Prefix = "",
  [string]$FromDir = "",
  [string]$BaseUrl = "",
  [switch]$RequireSignature,
  [switch]$AddToPath,
  [switch]$Uninstall,
  [switch]$Purge,
  [switch]$Force,
  [switch]$DryRun,
  [switch]$Yes
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

# The accepted vendor verification keys, newest first: the same values as
# internal/update/vendorkey.go (VendorPublicKeyV1, then the rotation slot
# VendorPublicKeyV0Previous while it is set). tests/invariant pins the two.
$VendorKeys = @("npbhJUUL/Zy088BDnuqYRDqjjQtlyF9/eVcWFOCzj2g=")

$DefaultBaseUrl = "https://github.com/superbasedapp/observer/releases"
$LatestApiUrl = "https://api.github.com/repos/superbasedapp/observer/releases/latest"
$DefaultEdition = "developer"
$Editions = [ordered]@{
  minimal   = "capture only: hooks, transcript watcher and the local dashboard; no proxy, terminals or self-update"
  developer = "a developer's own machine: proxy, dashboard, terminals, guard and every adapter (recommended)"
  managed   = "a machine enrolled in an organization: org client and self-update on, local extras off"
  full      = "everything compiled in: the build npm, PyPI and the VS Code extension ship"
}

function Say([string]$m) { Write-Host $m }
function Warn([string]$m) { Write-Warning "install.ps1: $m" }
function Fail([string]$m) { throw "install.ps1: $m" }

function Test-Interactive {
  if ($Yes -or $DryRun) { return $false }
  try {
    return [Environment]::UserInteractive -and -not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected
  } catch { return $false }
}

function Ask([string]$prompt, [string]$default) {
  $r = Read-Host -Prompt $prompt
  if ([string]::IsNullOrWhiteSpace($r)) { return $default }
  return $r.Trim()
}

# ------------------------------------------------------------ Ed25519 (RFC 8032)
#
# Verification only, cofactorless, the check Go's crypto/ed25519 makes:
# [S]B == R + [k]A with k = SHA-512(R || A || M) mod L and S < L.

Add-Type -AssemblyName System.Numerics
$BI = [System.Numerics.BigInteger]
$EdP = [System.Numerics.BigInteger]::Subtract([System.Numerics.BigInteger]::Pow(2, 255), 19)
$EdL = [System.Numerics.BigInteger]::Add([System.Numerics.BigInteger]::Pow(2, 252), [System.Numerics.BigInteger]::Parse("27742317777372353535851937790883648493"))

function EdMod($v) {
  $r = [System.Numerics.BigInteger]::Remainder($v, $EdP)
  if ($r.Sign -lt 0) { $r = [System.Numerics.BigInteger]::Add($r, $EdP) }
  return $r
}
function EdMul($u, $v) { return EdMod ([System.Numerics.BigInteger]::Multiply($u, $v)) }
function EdSub($u, $v) { return EdMod ([System.Numerics.BigInteger]::Subtract($u, $v)) }
function EdAddN($u, $v) { return EdMod ([System.Numerics.BigInteger]::Add($u, $v)) }
function EdInv($u) { return [System.Numerics.BigInteger]::ModPow($u, [System.Numerics.BigInteger]::Subtract($EdP, 2), $EdP) }

$EdD = EdMul ([System.Numerics.BigInteger]::Parse("-121665")) (EdInv ([System.Numerics.BigInteger]::Parse("121666")))
$EdSqrtM1 = [System.Numerics.BigInteger]::ModPow(2, [System.Numerics.BigInteger]::Divide([System.Numerics.BigInteger]::Subtract($EdP, 1), 4), $EdP)
$EdBx = [System.Numerics.BigInteger]::Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202")
$EdBy = [System.Numerics.BigInteger]::Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960")

function EdPointAdd($pa, $pb) {
  $va = EdMul (EdSub $pa[1] $pa[0]) (EdSub $pb[1] $pb[0])
  $vb = EdMul (EdAddN $pa[1] $pa[0]) (EdAddN $pb[1] $pb[0])
  $vc = EdMul (EdMul (EdMul 2 $pa[3]) $pb[3]) $EdD
  $vk = EdMul (EdMul 2 $pa[2]) $pb[2]
  $ve = EdSub $vb $va
  $vf = EdSub $vk $vc
  $vg = EdAddN $vk $vc
  $vh = EdAddN $vb $va
  return , @((EdMul $ve $vf), (EdMul $vg $vh), (EdMul $vf $vg), (EdMul $ve $vh))
}

function EdScalarMul($s, $pt) {
  $q = @([System.Numerics.BigInteger]::Zero, [System.Numerics.BigInteger]::One, [System.Numerics.BigInteger]::One, [System.Numerics.BigInteger]::Zero)
  $n = $s
  while ($n.Sign -gt 0) {
    if (-not $n.IsEven) { $q = EdPointAdd $q $pt }
    $pt = EdPointAdd $pt $pt
    $n = [System.Numerics.BigInteger]::Divide($n, 2)
  }
  return , $q
}

function EdFromLE([byte[]]$b) {
  $u = New-Object byte[] ($b.Length + 1)
  [Array]::Copy($b, $u, $b.Length)
  return New-Object System.Numerics.BigInteger (, $u)
}

# EdDecompress: a 32-byte encoding to an extended point, or $null.
function EdDecompress([byte[]]$enc) {
  if ($enc.Length -ne 32) { return $null }
  $sign = ($enc[31] -shr 7) -band 1
  $c = [byte[]]$enc.Clone()
  $c[31] = $c[31] -band 0x7f
  $y = EdFromLE $c
  if ($y.CompareTo($EdP) -ge 0) { return $null }
  $yy = EdMul $y $y
  $x2 = EdMul (EdSub $yy 1) (EdInv (EdAddN (EdMul $EdD $yy) 1))
  if ($x2.IsZero) {
    if ($sign -eq 1) { return $null }
    return , @([System.Numerics.BigInteger]::Zero, $y, [System.Numerics.BigInteger]::One, [System.Numerics.BigInteger]::Zero)
  }
  $x = [System.Numerics.BigInteger]::ModPow($x2, [System.Numerics.BigInteger]::Divide([System.Numerics.BigInteger]::Add($EdP, 3), 8), $EdP)
  if (-not (EdSub (EdMul $x $x) $x2).IsZero) { $x = EdMul $x $EdSqrtM1 }
  if (-not (EdSub (EdMul $x $x) $x2).IsZero) { return $null }
  $parity = if ($x.IsEven) { 0 } else { 1 }
  if ($parity -ne $sign) { $x = [System.Numerics.BigInteger]::Subtract($EdP, $x) }
  return , @($x, $y, [System.Numerics.BigInteger]::One, (EdMul $x $y))
}

# Test-Ed25519 <public key bytes> <signature bytes> <message file path or $null for empty>
function Test-Ed25519([byte[]]$pub, [byte[]]$sig, [string]$msgPath) {
  if ($pub.Length -ne 32 -or $sig.Length -ne 64) { return $false }
  $pa = EdDecompress $pub
  if ($null -eq $pa) { return $false }
  $rEnc = [byte[]]$sig[0..31]
  $sEnc = [byte[]]$sig[32..63]
  $pr = EdDecompress $rEnc
  if ($null -eq $pr) { return $false }
  $s = EdFromLE $sEnc
  if ($s.CompareTo($EdL) -ge 0) { return $false }
  $sha = [System.Security.Cryptography.SHA512]::Create()
  try {
    [void]$sha.TransformBlock($rEnc, 0, 32, $null, 0)
    [void]$sha.TransformBlock($pub, 0, 32, $null, 0)
    if ($msgPath) {
      $fs = [System.IO.File]::OpenRead($msgPath)
      try {
        $buf = New-Object byte[] 1048576
        while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) { [void]$sha.TransformBlock($buf, 0, $n, $null, 0) }
      } finally { $fs.Dispose() }
    }
    [void]$sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
    $k = [System.Numerics.BigInteger]::Remainder((EdFromLE $sha.Hash), $EdL)
  } finally { $sha.Dispose() }
  $basePt = @($EdBx, $EdBy, [System.Numerics.BigInteger]::One, (EdMul $EdBx $EdBy))
  $sB = EdScalarMul $s $basePt
  $kA = EdScalarMul $k $pa
  $rhs = EdPointAdd $pr $kA
  if (-not (EdSub (EdMul $sB[0] $rhs[2]) (EdMul $rhs[0] $sB[2])).IsZero) { return $false }
  if (-not (EdSub (EdMul $sB[1] $rhs[2]) (EdMul $rhs[1] $sB[2])).IsZero) { return $false }
  return $true
}

# The RFC 8032 section 7.1 TEST 1 vector (empty message); the verifier is
# trusted only after it accepts this and rejects a one-bit change.
function Test-VerifierSelfCheck {
  $pub = [Convert]::FromBase64String("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
  $sig = [Convert]::FromBase64String("5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc+bRr0lv18FlbviRlUUFDjnoQCw==")
  if (-not (Test-Ed25519 $pub $sig $null)) { return $false }
  $bad = [byte[]]$sig.Clone()
  $bad[0] = $bad[0] -bxor 1
  return -not (Test-Ed25519 $pub $bad $null)
}

# ---------------------------------------------------------------- transport

function Use-Tls12 {
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  } catch { }
}

function Get-Url([string]$url, [string]$out) {
  if (-not $url.StartsWith("https://")) { Fail "refusing a non-https URL: $url" }
  Use-Tls12
  $prev = $ProgressPreference
  $ProgressPreference = "SilentlyContinue"
  try { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out } finally { $ProgressPreference = $prev }
}

# Get-Asset <name> <out> [optional]: $true present, $false absent (404 or
# no such file); any other failure throws.
function Get-Asset([string]$name, [string]$out, [bool]$optional = $false) {
  if ($FromDir) {
    $src = Join-Path $FromDir $name
    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) {
      if ($optional) { return $false }
      Fail "$name is not in $FromDir"
    }
    Copy-Item -LiteralPath $src -Destination $out
    return $true
  }
  try {
    Get-Url "$script:AssetBase/$name" $out
    return $true
  } catch {
    $resp = $null
    if ($_.Exception.PSObject.Properties["Response"]) { $resp = $_.Exception.Response }
    if ($optional -and $resp -and [int]$resp.StatusCode -eq 404) { return $false }
    if ($optional) { Fail "could not fetch $name (network error): $($_.Exception.Message). Re-run, or use -FromDir." }
    Fail "could not get ${name}: $($_.Exception.Message)"
  }
}

# ------------------------------------------------------------------- helpers

function Get-DefaultPrefix { return (Join-Path $env:LOCALAPPDATA "SuperBased\Observer\bin") }

function Get-UserPath { $p = [Environment]::GetEnvironmentVariable("Path", "User"); if ($null -eq $p) { return "" } return $p }

function Test-OnUserPath([string]$dir) {
  foreach ($e in (Get-UserPath).Split(";")) { if ($e.TrimEnd("\") -ieq $dir.TrimEnd("\")) { return $true } }
  return $false
}

# Get-InstalledVersion <exe>: the first line of `<exe> --version`, or
# "observer version unknown" when it does not answer.
function Get-InstalledVersion([string]$path) {
  try {
    $o = @(& $path --version)
    if ($LASTEXITCODE -eq 0 -and $o.Count -gt 0 -and [string]$o[0]) { return [string]$o[0] }
  } catch { }
  return "observer version unknown"
}

# Get-RunningFrom <paths>: the processes whose image is one of paths.
function Get-RunningFrom([string[]]$paths) {
  $out = @()
  foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
    $img = $null
    try { $img = $p.Path } catch { }
    if (-not $img) { continue }
    foreach ($want in $paths) { if ($img -ieq $want) { $out += $p; break } }
  }
  return $out
}

# Install-Over <new> <target>: copy new onto target. A running .exe cannot be
# overwritten but can be renamed, so a locked target is moved aside to
# <target>.old-<timestamp> first (removed by the next install or uninstall).
function Install-Over([string]$src, [string]$target) {
  try {
    Copy-Item -LiteralPath $src -Destination $target -Force
    return
  } catch {
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw }
  }
  $aside = "$target.old-" + (Get-Date -Format "yyyyMMddHHmmssfff")
  Move-Item -LiteralPath $target -Destination $aside
  Copy-Item -LiteralPath $src -Destination $target -Force
}

# Remove-StaleAside <dir>: delete binaries an earlier upgrade moved aside,
# skipping any a process still runs (the sandbox files in mxc\ too).
function Remove-StaleAside([string]$dir) {
  $stale = @(Get-ChildItem -LiteralPath $dir -Filter "*.exe.old-*" -File -ErrorAction SilentlyContinue)
  $mxcPath = Join-Path $dir $MxcDir
  if (Test-Path -LiteralPath $mxcPath -PathType Container) {
    $stale += @(Get-ChildItem -LiteralPath $mxcPath -Filter "*.old-*" -File -ErrorAction SilentlyContinue)
  }
  foreach ($f in $stale) {
    try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop } catch { }
  }
}

# The Windows sandbox driver's bundled files (terminals.sandbox.mxc; sandbox
# plan v2 sections 11.3 and 12.3, ledger SBX-SUP-1). The names equal
# internal/sandboxmxc's FileFFI, FileExec and BundleDir and the manifest that
# scripts/mxc-files.sh writes (TestInstallScriptsKnowTheMXCFiles).
$MxcDir = "mxc"
$MxcFiles = @("mxc_ffi.dll", "wxc-exec.exe")
$MxcManifest = "mxc-manifest.json"
$MxcManifestKind = "observer.mxc-files.v1"

# Test-MxcSet <dir>: check an extracted mxc\ against its own manifest before
# anything is copied: exactly the known files (no other file, no directory, no
# link), each one's size and sha256 equal to the manifest's. The manifest
# rides inside the archive whose sha256 and vendor signature were checked, so
# it is as trusted as observer.exe. Returns the manifest.
function Test-MxcSet([string]$src) {
  $mpath = Join-Path $src $MxcManifest
  if (-not (Test-Path -LiteralPath $mpath -PathType Leaf)) { Fail "the archive's $MxcDir\ has no $MxcManifest, so its sandbox files cannot be checked. Refusing to install." }
  try { $m = Get-Content -Raw -LiteralPath $mpath | ConvertFrom-Json } catch { Fail "the archive's $MxcDir\$MxcManifest is not valid JSON. Refusing to install." }
  if ([string]$m.kind -ne $MxcManifestKind) { Fail "the archive's $MxcDir\$MxcManifest is not a $MxcManifestKind manifest. Refusing to install." }
  $listed = @($m.files | ForEach-Object { [string]$_.name })
  if ($listed.Count -ne $MxcFiles.Count) { Fail "the archive's $MxcDir\$MxcManifest lists $($listed.Count) files, not the $($MxcFiles.Count) known sandbox files. Refusing to install." }
  foreach ($n in $MxcFiles) {
    if ($listed -notcontains $n) { Fail "the archive's $MxcDir\$MxcManifest does not list $n. Refusing to install." }
  }
  foreach ($item in @(Get-ChildItem -LiteralPath $src -Force)) {
    if ($item.Name -ne $MxcManifest -and $MxcFiles -notcontains $item.Name) { Fail "the archive's $MxcDir\ carries an unexpected entry $($item.Name). Refusing to install." }
  }
  foreach ($f in $m.files) {
    $p = Join-Path $src ([string]$f.name)
    $item = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Fail "the archive's $MxcDir\$($f.name) is missing or not a regular file. Refusing to install." }
    if ($item.Length -ne [int64]$f.size) { Fail "$MxcDir\$($f.name): size $($item.Length) does not match its manifest ($($f.size)). Refusing to install." }
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLowerInvariant()
    if ($h -ne ([string]$f.sha256).ToLowerInvariant()) { Fail "$MxcDir\$($f.name): sha256 $h does not match its manifest. Refusing to install." }
  }
  return $m
}

# Install-MxcSet <src> <dest>: replace the sandbox files in <dest> with the
# checked set in <src>, one file at a time: the old file is renamed aside
# (a running wxc-exec.exe can be renamed, never overwritten), the new one is
# copied in and its sha256 read back. Any failure removes what was copied and
# renames every old file back, so the previous set stays whole. It returns the
# steps it took and keeps the asides: Complete-MxcSet removes them once the
# binary swap succeeded (one still in use is removed by the next install), and
# Undo-MxcSet puts them back if the binary swap failed, so a new set is never
# left beside the old binary (audit SBX-P3B F6).
function Install-MxcSet([string]$src, [string]$dest, $manifest) {
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  $stamp = Get-Date -Format "yyyyMMddHHmmssfff"
  $want = @{}
  foreach ($f in $manifest.files) { $want[[string]$f.name] = ([string]$f.sha256).ToLowerInvariant() }
  $done = @()
  try {
    foreach ($n in @($MxcFiles + $MxcManifest)) {
      $target = Join-Path $dest $n
      $aside = $null
      if (Test-Path -LiteralPath $target) {
        $aside = "$target.old-$stamp"
        Move-Item -LiteralPath $target -Destination $aside
      }
      $done += ,@{ target = $target; aside = $aside }
      Copy-Item -LiteralPath (Join-Path $src $n) -Destination $target
      if ($want.ContainsKey($n) -and (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash.ToLowerInvariant() -ne $want[$n]) {
        throw "$n did not read back with its manifest's sha256"
      }
    }
  } catch {
    $why = $_.Exception.Message
    Undo-MxcSet $done
    throw "replacing the sandbox files in $dest failed ($why); the previous files were put back"
  }
  return ,$done
}

# Undo-MxcSet <steps>: remove what Install-MxcSet copied and rename every old
# file back, last step first.
function Undo-MxcSet($steps) {
  for ($i = $steps.Count - 1; $i -ge 0; $i--) {
    $d = $steps[$i]
    Remove-Item -LiteralPath $d.target -Force -ErrorAction SilentlyContinue
    if ($d.aside) { Move-Item -LiteralPath $d.aside -Destination $d.target -Force -ErrorAction SilentlyContinue }
  }
}

# Complete-MxcSet <steps>: remove the old files Install-MxcSet set aside.
function Complete-MxcSet($steps) {
  foreach ($d in $steps) {
    if ($d.aside) { try { Remove-Item -LiteralPath $d.aside -Force -ErrorAction Stop } catch { } }
  }
}

function Get-SumsVersions([string]$sumsPath) {
  $found = @{}
  foreach ($line in (Get-Content -LiteralPath $sumsPath)) {
    $parts = $line.Trim() -split "\s+", 2
    if ($parts.Count -lt 2) { continue }
    $f = $parts[1].TrimStart("*")
    if ($f -notmatch '^observer-v[0-9]+\.[0-9]+\.[0-9]+.*\.(tar\.gz|zip)$') { continue }
    $f = $f -replace '\.(tar\.gz|zip)$', ''
    $t = $f.Split("-")
    $m = $t.Count - 3
    if ($t[$m] -match '^(minimal|developer|managed|full)$') { $m-- }
    elseif ($m -ge 3 -and $t[$m - 1] -eq "custom" -and $t[$m].Length -eq 64) { $m -= 2 }
    $found[($t[1..$m] -join "-")] = $true
  }
  return @($found.Keys)
}

# ----------------------------------------------------------------- uninstall

function Invoke-Uninstall {
  $dir = if ($Prefix) { $Prefix } else { Get-DefaultPrefix }
  $exe = Join-Path $dir "observer.exe"
  if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { Fail "no observer.exe in $dir (pass -Prefix <dir>)" }
  $args2 = @("uninstall", "--all")
  if ($Purge) { $args2 += "--purge" }
  Say "Uninstall plan:"
  Say "  - remove hook, MCP and proxy-route entries ($exe $($args2 -join ' '))"
  if (-not $Purge) { Say "    ($env:USERPROFILE\.observer is kept)" }
  Say "  - delete $exe and $(Join-Path $dir 'superbased.exe')"
  if (Test-OnUserPath $dir) { Say "  - remove $dir from the user Path" }
  Say "If this machine is enrolled in an organization, leave it first: observer unenroll"
  Say "Stop a running ``observer start`` first (the binary cannot be deleted while it runs)."
  if ($DryRun) { Say "(dry run: nothing changed)"; return }
  if (Test-Interactive) {
    $a = Ask "Proceed? [y/N]" "n"
    if ($a -notmatch '^(y|yes)$') { Say "Nothing changed."; return }
  }
  & $exe @args2
  if ($LASTEXITCODE -ne 0) {
    if ($Force) { Warn "observer $($args2 -join ' ') failed; deleting the binaries anyway (-Force). Hook entries left behind fail until removed." }
    else { Fail "observer $($args2 -join ' ') failed, so the binaries were kept (deleting them would leave hook entries that point at a missing program). Fix the reported problem, or re-run with -Force." }
  }
  Remove-Item -LiteralPath $exe -Force
  $alias = Join-Path $dir "superbased.exe"
  if (Test-Path -LiteralPath $alias) { Remove-Item -LiteralPath $alias -Force }
  Remove-StaleAside $dir
  # The sandbox files this installer copied (only the known names; the
  # directory goes only when nothing else is left in it).
  $mxcPath = Join-Path $dir $MxcDir
  if (Test-Path -LiteralPath $mxcPath -PathType Container) {
    foreach ($n in @($MxcFiles + $MxcManifest)) {
      $p = Join-Path $mxcPath $n
      if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }
    if (@(Get-ChildItem -LiteralPath $mxcPath -Force).Count -eq 0) { Remove-Item -LiteralPath $mxcPath -Force }
  }
  if (Test-OnUserPath $dir) {
    $kept = @((Get-UserPath).Split(";") | Where-Object { $_ -and ($_.TrimEnd("\") -ine $dir.TrimEnd("\")) })
    [Environment]::SetEnvironmentVariable("Path", ($kept -join ";"), "User")
    Say "Removed $dir from the user Path."
  }
  Say "Removed $exe."
}

# ------------------------------------------------ another install (U4)
#
# Lane FIX-UPGRADE U4 (D-590): installing over an npm or pip install used to
# put a second copy on the machine with one Path warning, while the running
# daemon and the registered hooks kept the package-manager copy. Now the
# installer looks first, explains which copy wins, offers the package
# manager's own upgrade command, and installs a second copy only on an
# explicit menu answer or -Force. OBSERVER_INSTALL_TEST_PATH and
# OBSERVER_INSTALL_TEST_DAEMONS ("pid=path;pid=path", or empty for none)
# stand in for the Path and the process table, honoured only with -FromDir.

function Get-PathObservers {
  $dirs = $env:Path
  if ($FromDir -and (Test-Path Env:OBSERVER_INSTALL_TEST_PATH)) { $dirs = $env:OBSERVER_INSTALL_TEST_PATH }
  $out = @()
  foreach ($d in ($dirs -split ";")) {
    if (-not $d) { continue }
    foreach ($n in @("observer.exe", "observer.cmd")) {
      $p = Join-Path $d $n
      if (Test-Path -LiteralPath $p -PathType Leaf) { $out += $p; break }
    }
  }
  return $out
}

function Get-InstallKind([string]$path) {
  $d = Split-Path -Parent $path
  if ($path -match '\\node_modules\\@superbased\\' -or (Test-Path -LiteralPath (Join-Path $d "node_modules\@superbased\observer"))) { return "npm" }
  if ($path -match '\\pipx\\') { return "pip" }
  if ((Split-Path -Leaf $d) -ieq "Scripts" -and (Test-Path -LiteralPath (Join-Path $d "..\Lib\site-packages\observer"))) { return "pip" }
  return "archive"
}

function Get-UpgradeCommand([string]$kind, [string]$path) {
  switch ($kind) {
    "npm" { return "npm.cmd install -g @superbased/observer@latest" }
    "pip" {
      if ($path -match '\\pipx\\') { return "pipx upgrade superbased-observer" }
      $py = Join-Path (Split-Path -Parent $path) "python.exe"
      if (Test-Path -LiteralPath $py) { return "& '$py' -m pip install --upgrade superbased-observer" }
      return "py -m pip install --upgrade superbased-observer"
    }
  }
  return ""
}

function Get-EditionOf([string]$path, [string]$kind) {
  if ($kind -eq "npm" -or $kind -eq "pip") { return "full" }
  try {
    $j = (& $path components list --json 2>$null | Out-String | ConvertFrom-Json)
    if ($j -and ($j.PSObject.Properties.Name -contains "distro") -and $Editions.Contains([string]$j.distro)) { return [string]$j.distro }
  } catch { }
  return ""
}

# Get-OtherDaemons <exe> <alias>: `observer start` processes running a binary
# other than this install's own (an upgrade of that one is handled later).
function Get-OtherDaemons([string]$exe, [string]$alias) {
  $out = @()
  if ($FromDir -and (Test-Path Env:OBSERVER_INSTALL_TEST_DAEMONS)) {
    foreach ($e in ($env:OBSERVER_INSTALL_TEST_DAEMONS -split ";")) {
      if ($e -match '^([0-9]+)=(.+)$') { $out += [pscustomobject]@{ Id = [int]$Matches[1]; Path = $Matches[2] } }
    }
    return $out
  }
  try {
    foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name LIKE 'observer%'" -ErrorAction Stop)) {
      if (-not $p.ExecutablePath -or -not $p.CommandLine) { continue }
      if ($p.CommandLine -notmatch '\sstart(\s|$)') { continue }
      if ($p.ExecutablePath -ieq $exe -or $p.ExecutablePath -ieq $alias) { continue }
      $out += [pscustomobject]@{ Id = [int]$p.ProcessId; Path = [string]$p.ExecutablePath }
    }
  } catch { }
  return $out
}

# Test-OtherInstalls <exe> <alias>: explains and decides (first match wins):
# nothing found -> install; -Force -> warn and install a second copy; an
# interactive console -> ask (default: keep the existing install, install
# nothing); -DryRun -> report and stop; otherwise refuse and name -Force.
# Returns @{ Go = bool; Edition = existing edition or ""; Daemons = @() }.
function Test-OtherInstalls([string]$exe, [string]$alias) {
  $res = @{ Go = $true; Edition = ""; Daemons = @() }
  $lines = @()
  foreach ($p in @(Get-PathObservers)) {
    if ($p -ieq $exe -or $p -ieq $alias) { continue }
    $k = Get-InstallKind $p
    $v = Get-InstalledVersion $p
    $lines += "  $k install: $p ($v)"
    $u = Get-UpgradeCommand $k $p
    if ($u) { $lines += "      upgrade it in place with: $u" }
    if (-not $res.Edition) { $res.Edition = Get-EditionOf $p $k }
  }
  $res.Daemons = @(Get-OtherDaemons $exe $alias)
  foreach ($d in $res.Daemons) { $lines += "  running daemon: pid $($d.Id) ($($d.Path))" }
  if (-not $Edition -and -not $res.Edition -and (Test-Path -LiteralPath $exe -PathType Leaf)) { $res.Edition = Get-EditionOf $exe "archive" }
  if ($lines.Count -eq 0) { return $res }
  Say "Observer is already installed on this machine:"
  foreach ($l in $lines) { Say $l }
  $now = Get-Command observer -ErrorAction SilentlyContinue | Select-Object -First 1
  $nowSrc = if ($now) { $now.Source } else { "none" }
  Say "  A new terminal runs the first ``observer`` on Path: now $nowSrc. This installer adds its directory to the END"
  Say "  of the user Path, so the existing copy keeps winning, and the running daemon and your hooks keep using it."
  if ($Force) { Warn "installing a second copy at $exe anyway (-Force)"; return $res }
  if (Test-Interactive) {
    Say ""
    Say "  1) keep the existing install and upgrade it with its own command (shown above)"
    Say "  2) install a second copy at $exe anyway"
    Say "  3) cancel"
    $pick = Ask "Choice [1]" "1"
    switch -regex ($pick) {
      '^2$' { return $res }
      '^(1|3)$' { Say "Nothing was installed."; $res.Go = $false; return $res }
      default { Fail "unknown choice '$pick'" }
    }
  }
  if ($DryRun) { Say "(dry run: a real run would stop here; pass -Force to install a second copy anyway)"; $res.Go = $false; return $res }
  Fail "not installing a second copy: upgrade the existing install with its own command above, or pass -Force to install a second copy at $exe anyway"
}

# ------------------------------------------------------------------- install

function Invoke-Install {
  $arch = $env:PROCESSOR_ARCHITECTURE
  if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
  switch ($arch) {
    "AMD64" { }
    "ARM64" { Warn "Windows on ARM: installing the x64 build, which runs under emulation" }
    default { Fail "unsupported CPU ${arch}: Observer ships x64 for Windows" }
  }

  # U4: another observer on Path (npm, pip, another copy) or a daemon from
  # another binary is found and explained before anything is chosen.
  $dir = if ($Prefix) { $Prefix } else { Get-DefaultPrefix }
  $other = Test-OtherInstalls (Join-Path $dir "observer.exe") (Join-Path $dir "superbased.exe")
  if (-not $other.Go) { return }
  $otherDaemons = @($other.Daemons)
  # An existing install's edition is the default (npm and pip ship full).
  $defEd = if ($other.Edition) { $other.Edition } else { $DefaultEdition }
  $defN = [array]::IndexOf(@($Editions.Keys), $defEd) + 1

  $ed = $Edition
  if ($ed) {
    if (-not $Editions.Contains($ed)) { Fail "unknown edition '$ed' (minimal, developer, managed or full)" }
  } elseif (Test-Interactive) {
    Say "Choose an edition:"
    $i = 1
    foreach ($k in $Editions.Keys) { Say ("  {0}) {1,-10} {2}" -f $i, $k, $Editions[$k]); $i++ }
    $pick = Ask "Edition [$defN, $defEd]" "$defN"
    switch -regex ($pick) {
      '^(1|minimal)$' { $ed = "minimal" }
      '^(2|developer)$' { $ed = "developer" }
      '^(3|managed)$' { $ed = "managed" }
      '^(4|full)$' { $ed = "full" }
      default { Fail "unknown choice '$pick'" }
    }
  } else { $ed = $defEd }

  if ($env:OBSERVER_INSTALL_TEST_VENDOR_KEY -and -not $FromDir) { Fail "OBSERVER_INSTALL_TEST_VENDOR_KEY is honoured only with -FromDir" }
  if ($BaseUrl -and -not $BaseUrl.StartsWith("https://")) { Fail "-BaseUrl must be https" }
  if ($FromDir) {
    if (-not (Test-Path -LiteralPath $FromDir -PathType Container)) { Fail "-FromDir: not a directory: $FromDir" }
    if (-not (Test-Path -LiteralPath (Join-Path $FromDir "SHA256SUMS") -PathType Leaf)) { Fail "-FromDir: $FromDir has no SHA256SUMS" }
  }

  $work = Join-Path ([IO.Path]::GetTempPath()) ("observer-install-" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path $work | Out-Null
  try {
    $ver = $Version
    if ($ver -eq "" -or $ver -eq "latest") {
      if ($FromDir) {
        $vs = @(Get-SumsVersions (Join-Path $FromDir "SHA256SUMS"))
        if ($vs.Count -ne 1) { Fail "cannot tell which release $FromDir holds (found: $($vs -join ' ')); pass -Version" }
        $ver = $vs[0]
      } else {
        if ($BaseUrl) { Fail "-BaseUrl needs an explicit -Version" }
        Use-Tls12
        try { $ver = [string](Invoke-RestMethod -UseBasicParsing -Uri $LatestApiUrl).tag_name }
        catch { Fail "could not resolve the latest release from $LatestApiUrl (pass -Version): $($_.Exception.Message)" }
      }
    } elseif ($ver -match '^[0-9]') { $ver = "v$ver" }
    if ($ver -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$') { Fail "not a release version: $ver (want vX.Y.Z or vX.Y.Z-pre)" }

    $base = if ($BaseUrl) { $BaseUrl } else { $DefaultBaseUrl }
    $script:AssetBase = "$base/download/$ver"
    $asset = if ($ed -eq "full") { "observer-$ver-win32-x64.zip" } else { "observer-$ver-$ed-win32-x64.zip" }

    Say "SuperBased Observer $ver, $ed edition"
    Say "  edition   $($Editions[$ed])"
    Say "  platform  win32-x64"
    Say "  archive   $asset"
    if ($FromDir) { Say "  source    $FromDir" } else { Say "  source    $script:AssetBase" }
    Say "  install   $(Join-Path $dir 'observer.exe')"

    $sums = Join-Path $work "SHA256SUMS"
    [void](Get-Asset "SHA256SUMS" $sums)
    $want = $null
    foreach ($line in (Get-Content -LiteralPath $sums)) {
      $parts = $line.Trim() -split "\s+", 2
      if ($parts.Count -eq 2 -and $parts[1].TrimStart("*") -eq $asset) { $want = $parts[0].ToLowerInvariant(); break }
    }
    if (-not $want) {
      if ($ed -ne "full") { Fail "release $ver publishes no $ed edition for win32-x64 ($asset is not in its SHA256SUMS). Editions are published from v1.36.0; use -Edition full for an older release." }
      Fail "release $ver has no $asset in its SHA256SUMS"
    }
    if ($DryRun -and -not $FromDir) { Say "(dry run: $asset is listed; it was not downloaded and nothing changed)"; return }

    $zip = Join-Path $work $asset
    [void](Get-Asset $asset $zip)
    $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
    if ($got -ne $want) { Fail "checksum MISMATCH for ${asset}: SHA256SUMS says $want, the file is $got. Refusing to install." }
    Say "  sha256    ok"

    $keys = $VendorKeys
    if ($env:OBSERVER_INSTALL_TEST_VENDOR_KEY) {
      Warn "verifying with the TEST key in OBSERVER_INSTALL_TEST_VENDOR_KEY, not the release keys"
      $keys = @($env:OBSERVER_INSTALL_TEST_VENDOR_KEY)
    }
    $sigPath = Join-Path $work "$asset.sig"
    if (Get-Asset "$asset.sig" $sigPath $true) {
      $sig = [IO.File]::ReadAllBytes($sigPath)
      if ($sig.Length -ne 64) { Fail "$asset.sig is not a 64-byte Ed25519 signature. Refusing to install." }
      if (-not (Test-VerifierSelfCheck)) {
        if ($RequireSignature) { Fail "the built-in Ed25519 verifier failed its self-check and -RequireSignature was given" }
        Warn "the built-in Ed25519 verifier failed its self-check, so the vendor signature was not checked. The sha256 matched."
      } else {
        $okSig = $false
        foreach ($k in $keys) {
          if (Test-Ed25519 ([Convert]::FromBase64String($k)) $sig $zip) { $okSig = $true; break }
        }
        if (-not $okSig) { Fail "vendor signature FAILED for ${asset}: it does not verify against any accepted vendor key. Refusing to install." }
        Say "  signature ok (vendor Ed25519)"
      }
    } else {
      if ($RequireSignature) { Fail "$ver publishes no vendor signature for $asset and -RequireSignature was given" }
      Warn "$ver publishes no vendor signature for $asset; only the sha256 was checked"
    }

    $x = Join-Path $work "x"
    Expand-Archive -LiteralPath $zip -DestinationPath $x
    $newExe = Join-Path $x "observer.exe"
    if (-not (Test-Path -LiteralPath $newExe -PathType Leaf)) { Fail "$asset has no observer.exe" }
    # The sandbox files ride only in the archives whose edition compiles the
    # Windows sandbox driver; checked before anything is written.
    $newMxc = Join-Path $x $MxcDir
    $mxcSet = $null
    if (Test-Path -LiteralPath $newMxc -PathType Container) {
      $mxcSet = Test-MxcSet $newMxc
      Say "  sandbox   $MxcDir\ ok (MXC $($mxcSet.version), every file matches its manifest)"
    }
    # No 2>&1 here: Windows PowerShell 5.1 turns a native program's stderr
    # into terminating errors under ErrorActionPreference Stop.
    $verOut = @(& $newExe --version)
    if ($LASTEXITCODE -ne 0) { Fail "the extracted binary does not run on this machine (exit $LASTEXITCODE)" }
    $reported = if ($verOut.Count -gt 0) { [string]$verOut[0] } else { "" }
    Say "  binary    $reported"
    if ($DryRun) { Say "(dry run: verified, nothing installed)"; return }

    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $exe = Join-Path $dir "observer.exe"
    $alias = Join-Path $dir "superbased.exe"
    Remove-StaleAside $dir

    # An existing install this run replaces (an upgrade, T-753), and any
    # daemon still running it. Windows cannot overwrite a running .exe but can
    # rename it, so a running daemon keeps its (renamed) binary and the new
    # one takes the name; the daemon is never stopped here (it IS the proxy).
    $previous = $null
    if (Test-Path -LiteralPath $exe -PathType Leaf) { $previous = Get-InstalledVersion $exe }
    $running = @(Get-RunningFrom @($exe, $alias))
    $mxcSteps = $null
    if ($mxcSet) {
      try {
        $mxcSteps = Install-MxcSet $newMxc (Join-Path $dir $MxcDir) $mxcSet
      } catch {
        Fail "$($_.Exception.Message). Nothing was installed; stop any sandboxed terminal that uses it and run the installer again."
      }
    }
    $exeSwapped = $false
    foreach ($target in @($exe, $alias)) {
      try {
        Install-Over $newExe $target
        if ($target -eq $exe) { $exeSwapped = $true }
      } catch {
        # observer.exe is still the old binary: put the old sandbox files
        # back beside it.
        if ($mxcSteps -and -not $exeSwapped) { Undo-MxcSet $mxcSteps; $mxcSteps = $null }
        Fail "could not write $target ($($_.Exception.Message)). If observer is running, stop it first (turn the proxy route off before stopping the daemon)."
      }
    }
    if ($mxcSteps) { Complete-MxcSet $mxcSteps }
    Say ""
    if ($previous) {
      Say "Upgraded ${exe}: $($previous -replace '^observer version ', '') -> $($reported -replace '^observer version ', '')."
    } else {
      Say "Installed $exe ($reported)."
    }

    if (-not (Test-OnUserPath $dir)) {
      $add = [bool]$AddToPath
      if (-not $add -and (Test-Interactive)) {
        $a = Ask "Add $dir to your user Path? [Y/n]" "y"
        $add = $a -match '^(y|yes)$'
      }
      if ($add) {
        $cur = Get-UserPath
        $new = if ($cur) { "$cur;$dir" } else { $dir }
        [Environment]::SetEnvironmentVariable("Path", $new, "User")
        Say "Added $dir to the user Path (new terminals pick it up)."
      } else {
        Warn "$dir is not on your user Path; add it, or re-run with -AddToPath"
      }
    }
    $resolved = Get-Command observer -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($resolved -and ($resolved.Source -ine $exe)) {
      Warn "``observer`` in this session resolves to $($resolved.Source), not $exe (an npm or pip install?); remove one so the shell runs the one you expect"
    }

    if ($previous) {
      foreach ($p in $running) {
        Say ""
        Say "observer (pid $($p.Id)) still runs the previous binary. The daemon is the proxy: restart it when no AI"
        Say "session uses the proxy, with the proxy route off first (docs/daemon-restart-runbook.md): stop it"
        Say "(Ctrl+C in its window, or Stop-Process -Id $($p.Id)), then run ``observer start`` again. Nothing was stopped."
      }
      Say ""
      Say "Your configuration and data in $env:USERPROFILE\.observer are unchanged."
      Say "Next steps:"
      Say "  observer components status             # what this edition runs"
      return
    }
    # U4: a daemon from another install runs (only with -Force or menu
    # choice 2): never start a second one in Next steps.
    if ($otherDaemons.Count -gt 0) {
      Say ""
      Say "A daemon from another install is running (pid $(($otherDaemons | ForEach-Object { $_.Id }) -join ', ')), so nothing was started."
      Say "To move to this copy: when no AI session uses the proxy, turn the proxy route off, stop that daemon, then start"
      Say "this one (docs/daemon-restart-runbook.md)."
      Say ""
      Say "Next steps:"
      Say "  & '$exe' components status   # what this edition runs"
      return
    }
    Say ""
    Say "Next steps:"
    if ($ed -eq "managed") { Say "  observer enroll --link <enrolment link>  # join your organization" }
    # The minimal edition compiles the proxy out (T-744): never claim one there.
    if ($ed -eq "minimal") {
      Say "  observer init                          # hooks for your AI tools"
      Say "  observer start                         # watcher + dashboard, no proxy in this edition (http://localhost:8081)"
    } else {
      Say "  observer init                          # hooks, MCP and the proxy route for your AI tools"
      Say "  observer start                         # proxy + watcher + dashboard (http://localhost:8081)"
    }
    Say "  observer components status             # what this edition runs"
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
}

if ($Purge -and -not $Uninstall) { Fail "-Purge applies only to -Uninstall" }
if ($Uninstall) { Invoke-Uninstall } else { Invoke-Install }
