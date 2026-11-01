# scripts/mxc-authenticode.ps1: the Authenticode check of the bundled MXC
# files (sandbox plan v2 section 11.3, ledger SBX-BE-15; lane SBX-P6). Runs
# on a Windows release runner after scripts/mxc-files.sh fetch: every file
# must carry a Valid signature whose signer is Microsoft Corporation. It
# writes <Dir>\authenticode.txt ("valid <signer thumbprints>") for the
# manifest and exits non-zero on any other answer, so the release refuses
# to bundle an unsigned or re-signed file.
param([Parameter(Mandatory = $true)][string]$Dir)
$ErrorActionPreference = 'Stop'
$files = @('mxc_ffi.dll', 'wxc-exec.exe')
$thumbs = @()
foreach ($f in $files) {
    $p = Join-Path $Dir $f
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "mxc-authenticode: $f is missing" }
    $sig = Get-AuthenticodeSignature -LiteralPath $p
    if ($sig.Status -ne 'Valid') { throw "mxc-authenticode: ${f}: signature status $($sig.Status)" }
    $subject = $sig.SignerCertificate.Subject
    if ($subject -notmatch '(^|, )O=Microsoft Corporation(,|$)') { throw "mxc-authenticode: ${f}: signer '$subject' is not Microsoft Corporation" }
    $thumbs += "${f}=$($sig.SignerCertificate.Thumbprint)"
    Write-Output "mxc-authenticode: $f Valid ($subject)"
}
Set-Content -LiteralPath (Join-Path $Dir 'authenticode.txt') -Value ("valid " + ($thumbs -join ' ')) -NoNewline -Encoding ascii
