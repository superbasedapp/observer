<#
.SYNOPSIS
  Hermetic test for scripts/install.ps1 (T-729), the Windows twin of
  scripts/test-install.sh.

.DESCRIPTION
  Builds a fixture release directory under a temp dir: a stub observer.exe
  per edition (compiled with Add-Type; it prints a version naming its
  edition and logs its arguments), one zip per edition, SHA256SUMS, and
  <zip>.sig signed by scripts/vendorsign with a throwaway key. Then runs
  install.ps1 -FromDir in a child Windows PowerShell with -Prefix inside the
  temp dir and -Yes. Nothing outside the temp dir is written: no -AddToPath,
  so the user Path is never touched.

  powershell -ExecutionPolicy Bypass -File scripts\test-install.ps1 [-VendorSign <vendorsign.exe>]

  Without -VendorSign it uses `go run ./scripts/vendorsign` (needs Go).
  Exit 0 = all cases pass.
#>
param([string]$VendorSign = "")

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$script = Join-Path $PSScriptRoot "install.ps1"
$ver = "v9.9.9-test.1"
$T = Join-Path ([IO.Path]::GetTempPath()) ("install-ps-test-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $T | Out-Null
$pass = 0; $fail = 0

function Ok([string]$m) { $script:pass++; Write-Host "ok   $m" }
function Bad([string]$m, [string]$out) { $script:fail++; Write-Host "FAIL $m"; if ($out) { Write-Host $out } }

function VS([string[]]$a) {
  $ErrorActionPreference = "Continue"
  if ($VendorSign) { $o = & $VendorSign @a 2>&1 } else { Push-Location $repo; try { $o = & go run ./scripts/vendorsign @a 2>&1 } finally { Pop-Location } }
  if ($LASTEXITCODE -ne 0) { throw "vendorsign $($a -join ' ') failed: $o" }
  return ($o | Out-String)
}

try {
  # ------------------------------------------------------------ fixture
  $keyDir = Join-Path $T "key"; $rel = Join-Path $T "rel"; $stage = Join-Path $T "stage"
  New-Item -ItemType Directory -Path $rel, $stage | Out-Null
  $kout = VS @("keygen", "-out", $keyDir)
  $pub = ([regex]::Match($kout, "public key : (\S+)")).Groups[1].Value
  if (-not $pub) { throw "no test key: $kout" }
  $key = Join-Path $keyDir "vendor-signing-key.key"
  $log = Join-Path $T "calls.log"

  foreach ($ed in @("minimal", "developer", "managed", "full")) {
    $d = Join-Path $stage $ed
    New-Item -ItemType Directory -Path $d | Out-Null
    $src = @"
using System;
using System.IO;
public static class P {
  public static int Main(string[] a) {
    File.AppendAllText(@"$log", string.Join(" ", a) + Environment.NewLine);
    if (a.Length > 0 && a[0] == "--version") Console.WriteLine("observer version $($ver.Substring(1)) ($ed stub)");
    if (a.Length > 0 && a[0] == "uninstall" && Environment.GetEnvironmentVariable("FAKE_UNINSTALL_FAIL") == "1") return 1;
    return 0;
  }
}
"@
    Add-Type -TypeDefinition $src -OutputAssembly (Join-Path $d "observer.exe") -OutputType ConsoleApplication
    Copy-Item (Join-Path $d "observer.exe") (Join-Path $d "superbased.exe")
    $name = if ($ed -eq "full") { "observer-$ver-win32-x64.zip" } else { "observer-$ver-$ed-win32-x64.zip" }
    Compress-Archive -Path (Join-Path $d "observer.exe"), (Join-Path $d "superbased.exe") -DestinationPath (Join-Path $rel $name)
  }
  $lines = foreach ($f in Get-ChildItem -LiteralPath $rel -Filter "observer-*.zip") { "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName).Hash.ToLowerInvariant(), $f.Name }
  [IO.File]::WriteAllText((Join-Path $rel "SHA256SUMS"), (($lines -join "`n") + "`n"))
  $zips = @(Get-ChildItem -LiteralPath $rel -Filter "observer-*.zip" | ForEach-Object { $_.FullName })
  [void](VS (@("sign", "-key", $key, "-allow-unpinned-key") + $zips))

  function Run([string[]]$a, [hashtable]$envs = @{}) {
    # U4: no real Path entry or process is ever read by a case (a fixture
    # Path directory and an empty daemon table stand in; a case overrides).
    $pre = "`$env:OBSERVER_INSTALL_TEST_VENDOR_KEY='$pub'; `$env:OBSERVER_INSTALL_TEST_PATH='$T\nopath'; `$env:OBSERVER_INSTALL_TEST_DAEMONS='none'; "
    foreach ($k in $envs.Keys) { $pre += "`$env:$k='$($envs[$k])'; " }
    $cmd = $pre + "& '$script' " + (($a | ForEach-Object { if ($_.StartsWith("-")) { $_ } else { "'$_'" } }) -join " ")
    # Continue, not Stop: the child's warnings arrive on stderr, which
    # Windows PowerShell 5.1 would otherwise turn into a terminating error.
    $ErrorActionPreference = "Continue"
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $cmd 2>&1 | Out-String
    return @{ rc = $LASTEXITCODE; out = $out }
  }
  function Variant { $v = Join-Path $T "v"; if (Test-Path $v) { Remove-Item -Recurse -Force $v }; Copy-Item -Recurse $rel $v; return $v }

  # -------------------------------------------------------------- cases
  $r = Run @("-FromDir", $rel, "-Prefix", "$T\p1", "-DryRun")
  if ($r.rc -eq 0 -and $r.out -match "dry run" -and -not (Test-Path "$T\p1")) { Ok "dry run verifies and writes nothing" } else { Bad "dry run" $r.out }

  $r = Run @("-FromDir", $rel, "-Prefix", "$T\p2", "-Yes")
  if ($r.rc -eq 0 -and $r.out -match "developer edition" -and $r.out -match "signature ok" -and (& "$T\p2\observer.exe" --version) -match "developer stub" -and (Test-Path "$T\p2\superbased.exe")) {
    Ok "default edition is developer, checksum + signature verified (built-in Ed25519)"
  } else { Bad "default install" $r.out }

  foreach ($ed in @("minimal", "managed", "full")) {
    $r = Run @("-FromDir", $rel, "-Prefix", "$T\p3$ed", "-Edition", $ed, "-Yes")
    if ($r.rc -eq 0 -and (& "$T\p3$ed\observer.exe" --version) -match "$ed stub") { Ok "edition $ed installs its archive" } else { Bad "edition $ed" $r.out }
    # T-744: the minimal edition's next steps never claim a proxy.
    $claimsProxy = $r.out -match "proxy \+ watcher"
    if (($ed -eq "minimal") -eq $claimsProxy) { Bad "edition $ed next steps (proxy claim = $claimsProxy)" $r.out } else { Ok "edition $ed next steps match its proxy" }
    # T-746: the managed next step is the real enrol command.
    if ($ed -eq "managed") {
      if ($r.out -match "observer enroll --link" -and $r.out -notmatch "observer org enroll") { Ok "managed next step names observer enroll --link" } else { Bad "managed enrol next step" $r.out }
    }
  }

  $v = Variant
  $z = Join-Path $v "observer-$ver-developer-win32-x64.zip"
  [IO.File]::AppendAllText($z, "x")
  $r = Run @("-FromDir", $v, "-Prefix", "$T\p4", "-Edition", "developer", "-Yes")
  if ($r.rc -ne 0 -and $r.out -match "checksum MISMATCH" -and -not (Test-Path "$T\p4\observer.exe")) { Ok "checksum mismatch refused" } else { Bad "checksum mismatch" $r.out }

  $v = Variant
  Copy-Item -Force (Join-Path $rel "observer-$ver-minimal-win32-x64.zip.sig") (Join-Path $v "observer-$ver-developer-win32-x64.zip.sig")
  $r = Run @("-FromDir", $v, "-Prefix", "$T\p5", "-Edition", "developer", "-Yes")
  if ($r.rc -ne 0 -and $r.out -match "signature FAILED" -and -not (Test-Path "$T\p5\observer.exe")) { Ok "wrong signature refused" } else { Bad "wrong signature" $r.out }

  $v = Variant
  Remove-Item (Join-Path $v "*.sig")
  $r = Run @("-FromDir", $v, "-Prefix", "$T\p6", "-Edition", "developer", "-Yes")
  if ($r.rc -eq 0 -and $r.out -match "publishes no vendor signature") { Ok "unsigned archive warns and installs" } else { Bad "unsigned" $r.out }
  $r = Run @("-FromDir", $v, "-Prefix", "$T\p6r", "-Edition", "developer", "-Yes", "-RequireSignature")
  if ($r.rc -ne 0 -and -not (Test-Path "$T\p6r\observer.exe")) { Ok "unsigned archive refused with -RequireSignature" } else { Bad "require signature" $r.out }

  $v = Variant
  $sums = Get-Content (Join-Path $v "SHA256SUMS") | Where-Object { $_ -notmatch "-managed-" }
  [IO.File]::WriteAllText((Join-Path $v "SHA256SUMS"), (($sums -join "`n") + "`n"))
  $r = Run @("-FromDir", $v, "-Prefix", "$T\p7", "-Edition", "managed", "-Yes")
  if ($r.rc -ne 0 -and $r.out -match "publishes no managed edition") { Ok "edition missing from the release refused" } else { Bad "missing edition" $r.out }

  # T-753: an in-place upgrade over a RUNNING daemon. The previous binary
  # keeps running (renamed aside, never stopped: the daemon is the proxy),
  # the new one takes the name, and the installer says "Upgraded X -> Y" with
  # the running pid and the safe order.
  $oldDir = Join-Path $T "old"
  New-Item -ItemType Directory -Path $oldDir | Out-Null
  $oldSrc = @"
using System;
using System.IO;
using System.Threading;
public static class P {
  public static int Main(string[] a) {
    File.AppendAllText(@"$log", string.Join(" ", a) + Environment.NewLine);
    if (a.Length > 0 && a[0] == "--version") Console.WriteLine("observer version 9.9.8-old (developer stub)");
    if (a.Length > 0 && a[0] == "start") Thread.Sleep(120000);
    return 0;
  }
}
"@
  Add-Type -TypeDefinition $oldSrc -OutputAssembly (Join-Path $oldDir "observer.exe") -OutputType ConsoleApplication
  $p8 = Join-Path $T "p8"
  New-Item -ItemType Directory -Path $p8 | Out-Null
  Copy-Item (Join-Path $oldDir "observer.exe") (Join-Path $p8 "observer.exe")
  Copy-Item (Join-Path $oldDir "observer.exe") (Join-Path $p8 "superbased.exe")
  $daemon = Start-Process -FilePath (Join-Path $p8 "observer.exe") -ArgumentList "start" -WindowStyle Hidden -PassThru
  try {
    Start-Sleep -Milliseconds 500
    $r = Run @("-FromDir", $rel, "-Prefix", $p8, "-Edition", "developer", "-Yes")
    $aside = @(Get-ChildItem -LiteralPath $p8 -Filter "observer.exe.old-*")
    $newVer = & (Join-Path $p8 "observer.exe") --version
    $alive = -not $daemon.HasExited
    if ($r.rc -eq 0 -and $r.out -match "Upgraded .*9\.9\.8-old \(developer stub\) -> 9\.9\.9-test\.1 \(developer stub\)" -and $r.out -match "pid $($daemon.Id)\) still runs the previous binary" -and $r.out -match "route off first" -and $newVer -match "9\.9\.9-test\.1 \(developer stub\)" -and $aside.Count -eq 1 -and $alive -and $r.out -notmatch "observer init") {
      Ok "upgrade over a running daemon: renamed aside, new binary in place, daemon left running, Upgraded X -> Y and the safe order"
    } else { Bad "upgrade over a running daemon (rc=$($r.rc), aside=$($aside.Count), alive=$alive, new=$newVer)" $r.out }
  } finally {
    if (-not $daemon.HasExited) { Stop-Process -Id $daemon.Id -Force -ErrorAction SilentlyContinue }
    $daemon.WaitForExit(5000) | Out-Null
  }
  $r = Run @("-FromDir", $rel, "-Prefix", $p8, "-Edition", "developer", "-Yes")
  if ($r.rc -eq 0 -and @(Get-ChildItem -LiteralPath $p8 -Filter "*.old-*").Count -eq 0 -and $r.out -match "Upgraded" -and $r.out -notmatch "still runs") { Ok "the next install removes the moved-aside binary once nothing runs it" } else { Bad "aside cleanup" $r.out }

  # U4: another install on Path (an npm global prefix: observer.cmd beside
  # node_modules\@superbased\observer) and a daemon from another binary.
  $npmDir = Join-Path $T "npm"
  New-Item -ItemType Directory -Force -Path (Join-Path $npmDir "node_modules\@superbased\observer") | Out-Null
  [IO.File]::WriteAllText((Join-Path $npmDir "observer.cmd"), "@echo observer version 1.34.0`r`n")
  $r = Run @("-FromDir", $rel, "-Prefix", "$T\p9", "-Yes") @{ OBSERVER_INSTALL_TEST_PATH = $npmDir }
  if ($r.rc -ne 0 -and $r.out -match "npm install:" -and $r.out -match "npm\.cmd install -g @superbased/observer@latest" -and $r.out -match "-Force" -and -not (Test-Path "$T\p9\observer.exe")) {
    Ok "an npm install on Path: explained, its upgrade command offered, nothing installed without -Force"
  } else { Bad "npm install on Path" $r.out }
  $r = Run @("-FromDir", $rel, "-Prefix", "$T\p9f", "-Yes", "-Force") @{ OBSERVER_INSTALL_TEST_PATH = $npmDir }
  if ($r.rc -eq 0 -and (& "$T\p9f\observer.exe" --version) -match "full stub") { Ok "-Force installs a second copy with the existing install's edition (full)" } else { Bad "-Force over npm" $r.out }
  $r = Run @("-FromDir", $rel, "-Prefix", "$T\p9d", "-DryRun") @{ OBSERVER_INSTALL_TEST_PATH = $npmDir }
  if ($r.rc -eq 0 -and $r.out -match "a real run would stop here" -and -not (Test-Path "$T\p9d")) { Ok "dry run with an npm install reports and changes nothing" } else { Bad "dry run over npm" $r.out }
  $r = Run @("-FromDir", $rel, "-Prefix", "$T\p10", "-Edition", "developer", "-Yes") @{ OBSERVER_INSTALL_TEST_DAEMONS = "4242=C:\elsewhere\observer.exe" }
  if ($r.rc -ne 0 -and $r.out -match "running daemon: pid 4242" -and -not (Test-Path "$T\p10\observer.exe")) { Ok "a running daemon from another install blocks a second install without -Force" } else { Bad "running daemon guard" $r.out }
  $r = Run @("-FromDir", $rel, "-Prefix", "$T\p10f", "-Edition", "developer", "-Yes", "-Force") @{ OBSERVER_INSTALL_TEST_DAEMONS = "4242=C:\elsewhere\observer.exe" }
  if ($r.rc -eq 0 -and (Test-Path "$T\p10f\observer.exe") -and $r.out -match "A daemon from another install is running \(pid 4242\)" -and $r.out -notmatch "  observer start ") {
    Ok "with -Force beside a running daemon: no observer start step"
  } else { Bad "next steps beside a running daemon" $r.out }

  # Lane SBX-P3B: an archive whose edition carries the Windows sandbox files
  # (mxc\ with its manifest) installs them beside observer.exe; a file that
  # does not match its manifest is refused before anything is written, and
  # an existing set is replaced whole (the upgrade keeps no stale file).
  $relM = Join-Path $T "relmxc"; $stM = Join-Path $T "stagemxc"
  New-Item -ItemType Directory -Path $relM, (Join-Path $stM "mxc") | Out-Null
  Copy-Item (Join-Path $stage "developer\observer.exe"), (Join-Path $stage "developer\superbased.exe") $stM
  [IO.File]::WriteAllText((Join-Path $stM "mxc\mxc_ffi.dll"), "fake dll")
  [IO.File]::WriteAllText((Join-Path $stM "mxc\wxc-exec.exe"), "fake exe!")
  function MxcManifestFor([string]$d) {
    $files = foreach ($n in @("mxc_ffi.dll", "wxc-exec.exe")) {
      $p = Join-Path $d $n
      @{ name = $n; package_path = "package/bin/x64/$n"; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLowerInvariant(); size = (Get-Item -LiteralPath $p).Length }
    }
    return (@{ kind = "observer.mxc-files.v1"; upstream = "npm:@microsoft/mxc-sdk"; version = "1.0.1"; files = @($files) } | ConvertTo-Json -Depth 4)
  }
  [IO.File]::WriteAllText((Join-Path $stM "mxc\mxc-manifest.json"), (MxcManifestFor (Join-Path $stM "mxc")))
  $zM = Join-Path $relM "observer-$ver-developer-win32-x64.zip"
  Compress-Archive -Path (Join-Path $stM "observer.exe"), (Join-Path $stM "superbased.exe"), (Join-Path $stM "mxc") -DestinationPath $zM
  [IO.File]::WriteAllText((Join-Path $relM "SHA256SUMS"), ("{0}  {1}`n" -f (Get-FileHash -Algorithm SHA256 -LiteralPath $zM).Hash.ToLowerInvariant(), (Split-Path -Leaf $zM)))
  [void](VS @("sign", "-key", $key, "-allow-unpinned-key", $zM))
  $pM = Join-Path $T "pmxc"
  New-Item -ItemType Directory -Path (Join-Path $pM "mxc") | Out-Null
  [IO.File]::WriteAllText((Join-Path $pM "mxc\wxc-exec.exe"), "old exe")
  $r = Run @("-FromDir", $relM, "-Prefix", $pM, "-Edition", "developer", "-Yes")
  $gotExe = if (Test-Path "$pM\mxc\wxc-exec.exe") { [IO.File]::ReadAllText("$pM\mxc\wxc-exec.exe") } else { "" }
  if ($r.rc -eq 0 -and $r.out -match "sandbox   mxc" -and $gotExe -eq "fake exe!" -and (Test-Path "$pM\mxc\mxc_ffi.dll") -and (Test-Path "$pM\mxc\mxc-manifest.json") -and @(Get-ChildItem -LiteralPath "$pM\mxc" -Filter "*.old-*").Count -eq 0) {
    Ok "the sandbox files are checked against their manifest and replace the old set beside observer.exe"
  } else { Bad "mxc install (exe=$gotExe)" $r.out }
  # A tampered sandbox file in a correctly signed archive: refused, and the
  # installed set and binary are untouched.
  $stT = Join-Path $T "stagemxc-t"
  Copy-Item -Recurse $stM $stT
  [IO.File]::WriteAllText((Join-Path $stT "mxc\mxc_ffi.dll"), "fake dlX")
  $relT = Join-Path $T "relmxc-t"
  New-Item -ItemType Directory -Path $relT | Out-Null
  $zT = Join-Path $relT "observer-$ver-developer-win32-x64.zip"
  Compress-Archive -Path (Join-Path $stT "observer.exe"), (Join-Path $stT "superbased.exe"), (Join-Path $stT "mxc") -DestinationPath $zT
  [IO.File]::WriteAllText((Join-Path $relT "SHA256SUMS"), ("{0}  {1}`n" -f (Get-FileHash -Algorithm SHA256 -LiteralPath $zT).Hash.ToLowerInvariant(), (Split-Path -Leaf $zT)))
  [void](VS @("sign", "-key", $key, "-allow-unpinned-key", $zT))
  $pT = Join-Path $T "pmxc-t"
  New-Item -ItemType Directory -Path (Join-Path $pT "mxc") | Out-Null
  [IO.File]::WriteAllText((Join-Path $pT "mxc\mxc_ffi.dll"), "old dll")
  $r = Run @("-FromDir", $relT, "-Prefix", $pT, "-Edition", "developer", "-Yes")
  if ($r.rc -ne 0 -and $r.out -match "does not match its manifest" -and [IO.File]::ReadAllText("$pT\mxc\mxc_ffi.dll") -eq "old dll" -and -not (Test-Path "$pT\observer.exe")) {
    Ok "a sandbox file that does not match its manifest is refused before anything is written"
  } else { Bad "tampered mxc file" $r.out }
  # An archive with no mxc\ leaves an installed set alone.
  $r = Run @("-FromDir", $rel, "-Prefix", $pM, "-Edition", "developer", "-Yes")
  if ($r.rc -eq 0 -and [IO.File]::ReadAllText("$pM\mxc\wxc-exec.exe") -eq "fake exe!") { Ok "an archive without mxc\ leaves the installed sandbox files alone" } else { Bad "no mxc in the archive" $r.out }

  $r = Run @("-Uninstall", "-Prefix", "$T\p2", "-Yes")
  if ($r.rc -eq 0 -and -not (Test-Path "$T\p2\observer.exe") -and (Get-Content $log) -contains "uninstall --all") { Ok "uninstall runs observer uninstall --all and removes the binaries" } else { Bad "uninstall" $r.out }

  $r = Run @("-Uninstall", "-Prefix", "$T\p3minimal", "-Yes") @{ FAKE_UNINSTALL_FAIL = "1" }
  if ($r.rc -ne 0 -and (Test-Path "$T\p3minimal\observer.exe")) { Ok "failed observer uninstall keeps the binary" } else { Bad "uninstall failure" $r.out }
  $r = Run @("-Uninstall", "-Prefix", "$T\p3minimal", "-Yes", "-Force") @{ FAKE_UNINSTALL_FAIL = "1" }
  if ($r.rc -eq 0 -and -not (Test-Path "$T\p3minimal\observer.exe")) { Ok "-Force removes the binary anyway" } else { Bad "uninstall -Force" $r.out }
} finally {
  Remove-Item -LiteralPath $T -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "install.ps1: $pass passed, $fail failed"
if ($fail -ne 0) { exit 1 }
