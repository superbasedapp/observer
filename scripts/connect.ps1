<#
.SYNOPSIS
  Install SuperBased Observer and connect this machine, in one step, on Windows.

.DESCRIPTION
  irm https://superbased.app/connect.ps1 | iex                          # personal dashboard
  $env:SBO_CONNECT_TEAM='<team>'; irm https://superbased.app/connect.ps1 | iex   # a team

  It downloads the newest release's install.ps1, checks it against the
  release's SHA256SUMS, checks SHA256SUMS against the vendor key below (the
  same key install.ps1 and internal/update/vendorkey.go carry; tests/invariant
  pins them) with the same built-in Ed25519 verifier install.ps1 uses (pure
  PowerShell, RFC 8032, checked against the RFC test vector first), then runs
  `install.ps1 -Connect [team]`. install.ps1 verifies the Observer archive the
  same way before installing it, sets Observer to start when you sign in to
  Windows (no administrator rights, no Windows service) and runs `observer
  connect`: you approve this machine in your browser (or enter a short code
  on any device), and nothing is sent before you do.

  It takes no token or credential. A release with no
  SHA256SUMS.sig is a warning, unless SBO_REQUIRE_SIGNATURE=1, which refuses.
#>
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

# The accepted vendor verification keys, newest first: the same values as
# internal/update/vendorkey.go. tests/invariant pins them.
$VendorKeys = @("npbhJUUL/Zy088BDnuqYRDqjjQtlyF9/eVcWFOCzj2g=")

$ReleaseUrl = "https://github.com/superbasedapp/observer/releases/latest/download"

function Say([string]$m) { Write-Host $m }
function Warn([string]$m) { Write-Warning "connect.ps1: $m" }
function Fail([string]$m) { throw "connect.ps1: $m" }

# The Ed25519 block below is a verbatim copy of install.ps1's; a test in
# tests/invariant keeps the two identical.
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

# ------------------------------------------------------------------ connect

function Invoke-Connect {
  $team = [string]$env:SBO_CONNECT_TEAM
  if ($team -and $team -notmatch '^[a-z0-9][a-z0-9-]{0,62}$') { Fail "SBO_CONNECT_TEAM='$team' is not a team name (lowercase letters, digits and hyphens)" }
  # Tests: SBO_CONNECT_FROM_DIR reads the release files from a directory
  # (and passes -FromDir to install.ps1); only then is a test key honoured.
  $fromDir = [string]$env:SBO_CONNECT_FROM_DIR
  $keys = $VendorKeys
  if ($env:OBSERVER_INSTALL_TEST_VENDOR_KEY) {
    if (-not $fromDir) { Fail "OBSERVER_INSTALL_TEST_VENDOR_KEY is honoured only with SBO_CONNECT_FROM_DIR" }
    $keys = @([string]$env:OBSERVER_INSTALL_TEST_VENDOR_KEY)
  }
  $requireSig = ($env:SBO_REQUIRE_SIGNATURE -eq "1")

  $work = Join-Path ([IO.Path]::GetTempPath()) ("observer-connect-" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path $work | Out-Null
  try {
    $get = {
      param([string]$name, [bool]$optional)
      $out = Join-Path $work $name
      if ($fromDir) {
        $src = Join-Path $fromDir $name
        if (Test-Path -LiteralPath $src -PathType Leaf) { Copy-Item -LiteralPath $src -Destination $out; return $true }
        if ($optional) { return $false }
        Fail "$name is not in $fromDir"
      }
      try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
      } catch { }
      $prev = $ProgressPreference
      $ProgressPreference = "SilentlyContinue"
      try {
        Invoke-WebRequest -UseBasicParsing -Uri "$ReleaseUrl/$name" -OutFile $out
        return $true
      } catch {
        if ($optional) { return $false }
        Fail "could not download $ReleaseUrl/${name}: $($_.Exception.Message)"
      } finally { $ProgressPreference = $prev }
    }

    Say "Getting the SuperBased Observer installer."
    [void](& $get "SHA256SUMS" $false)
    [void](& $get "install.ps1" $false)
    $sums = Join-Path $work "SHA256SUMS"
    $installer = Join-Path $work "install.ps1"
    $want = $null
    foreach ($line in (Get-Content -LiteralPath $sums)) {
      $f = $line -split '\s+', 2
      if ($f.Count -eq 2 -and $f[1].TrimStart('*') -eq "install.ps1") { $want = $f[0].ToLowerInvariant(); break }
    }
    if (-not $want) { Fail "SHA256SUMS lists no install.ps1" }
    $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash.ToLowerInvariant()
    if ($got -ne $want) { Fail "install.ps1 does not match SHA256SUMS (want $want, got $got); refusing to run it" }

    if (& $get "SHA256SUMS.sig" $true) {
      if (-not (Test-VerifierSelfCheck)) { Fail "the built-in Ed25519 verifier failed its self-check; refusing to run install.ps1" }
      $sig = [IO.File]::ReadAllBytes((Join-Path $work "SHA256SUMS.sig"))
      $ok = $false
      foreach ($k in $keys) {
        if (Test-Ed25519 ([Convert]::FromBase64String($k)) $sig $sums) { $ok = $true; break }
      }
      if (-not $ok) { Fail "SHA256SUMS.sig does not verify against the vendor key; refusing to run install.ps1" }
      Say "  signature ok"
    } elseif ($requireSig) {
      Fail "the release publishes no SHA256SUMS.sig and SBO_REQUIRE_SIGNATURE=1"
    } else {
      Warn "the release publishes no SHA256SUMS.sig; install.ps1 was checked against SHA256SUMS only"
    }

    # A child PowerShell with -ExecutionPolicy Bypass for that one process,
    # so a machine whose policy refuses script files still runs the verified
    # installer; no system setting changes.
    $ps = (Get-Process -Id $PID).Path
    $installArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $installer, "-Connect")
    if ($team) { $installArgs += @("-ConnectTeam", $team) }
    if ($fromDir) { $installArgs += @("-FromDir", $fromDir) }
    if ($requireSig) { $installArgs += "-RequireSignature" }
    & $ps @installArgs
    if ($LASTEXITCODE -ne 0) { Fail "the installer reported a problem (exit $LASTEXITCODE)" }
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Invoke-Connect
