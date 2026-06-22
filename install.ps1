<#
.SYNOPSIS
  Sigil installer (Windows). Downloads the prebuilt binaries from the latest
  GitHub release, verifies their SHA-256 checksum, and installs them.

  irm https://raw.githubusercontent.com/Ju571nK/sigil/main/install.ps1 | iex

  Environment overrides:
    SIGIL_VERSION       pin a release tag (default: latest), e.g. v0.6.1
    SIGIL_INSTALL_DIR   install directory (default: %LOCALAPPDATA%\Programs\sigil)
    SIGIL_PROFILE       personal (default) | fleet
                        personal = sigil + sigil-mcp + sigil-hook (local self-assessment)
                        fleet    = + sigil-sender + sigil-server + sigil-sign
    SIGIL_BASE_URL      fetch artifacts from here instead of GitHub Releases, e.g.
                        an air-gapped sigil-server: https://sigil.example:8443/v1/artifacts
                        (requires SIGIL_VERSION — no "latest" resolution off GitHub).
    SIGIL_BASE_TOKEN    bearer token sent to SIGIL_BASE_URL (the server read token);
                        requires SIGIL_BASE_URL.

  Provenance: every release archive also carries a GitHub build-provenance
  attestation. To verify it (optional, needs the gh CLI):
    gh attestation verify <archive> --repo Ju571nK/sigil

  This is the Windows counterpart to install.sh; the two keep parity (#172).
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # the progress UI throttles Invoke-WebRequest
# Windows PowerShell 5.1 defaults to TLS 1.0; GitHub requires 1.2+.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$Repo = 'Ju571nK/sigil'

function Say($m) { [Console]::Error.WriteLine("sigil-install: $m") }
function Die($m) { [Console]::Error.WriteLine("sigil-install: error: $m"); exit 1 }

# --- resolve profile -------------------------------------------------------
$profileName = if ($env:SIGIL_PROFILE) { $env:SIGIL_PROFILE } else { 'personal' }
switch ($profileName) {
  'personal' { $binaries = @('sigil', 'sigil-mcp', 'sigil-hook') }
  'fleet'    { $binaries = @('sigil', 'sigil-mcp', 'sigil-hook', 'sigil-sender', 'sigil-server', 'sigil-sign') }
  default    { Die "unknown SIGIL_PROFILE '$profileName' (expected: personal | fleet)" }
}

# dry-run hook: print the resolved binary set and exit before any network I/O.
# Mirrors install.sh; used by tests to verify profile->binaries mapping.
if ($env:SIGIL_PROFILE_DRYRUN -eq '1') {
  Write-Output ($binaries -join ' ')
  exit 0
}

# --- detect platform -------------------------------------------------------
# SIGIL_ARCH_OVERRIDE lets the tests drive arch detection without spoofing the
# OS; unset in normal use. Values match RuntimeInformation.OSArchitecture.
$archName = if ($env:SIGIL_ARCH_OVERRIDE) {
  $env:SIGIL_ARCH_OVERRIDE
} else {
  [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
}
switch ($archName) {
  'X64'   { $target = 'x86_64-pc-windows-msvc' }
  'Arm64' { $target = 'aarch64-pc-windows-msvc' }
  default { Die "unsupported architecture '$archName' — see https://github.com/$Repo#installation" }
}

# dry-run hook: print the resolved release target and exit before any network I/O.
if ($env:SIGIL_TARGET_DRYRUN -eq '1') {
  Write-Output $target
  exit 0
}

# A bearer token only makes sense against a SIGIL_BASE_URL artifact server;
# requiring the pair keeps it from ever reaching GitHub's API (#182).
if ($env:SIGIL_BASE_TOKEN -and -not $env:SIGIL_BASE_URL) {
  Die "SIGIL_BASE_TOKEN requires SIGIL_BASE_URL (it authenticates to your sigil-server)"
}

# --- resolve version -------------------------------------------------------
$ver = $env:SIGIL_VERSION
if (-not $ver) {
  if ($env:SIGIL_BASE_URL) {
    Die "set SIGIL_VERSION when using SIGIL_BASE_URL (no 'latest' resolution off GitHub)"
  }
  try {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
      -Headers @{ 'User-Agent' = 'sigil-install' }
    $ver = $rel.tag_name
  } catch {
    Die "could not resolve the latest release (set SIGIL_VERSION to pin one)"
  }
}
if (-not $ver) { Die "could not resolve the latest release (set SIGIL_VERSION to pin one)" }
$verN = $ver -replace '^v', ''
$asset = "sigil-$verN-$target.zip"
# Default base = GitHub Releases; SIGIL_BASE_URL points at a sigil-server
# artifact endpoint (.../v1/artifacts) instead. Both resolve <base>/<name>. (#182)
$base = if ($env:SIGIL_BASE_URL) { $env:SIGIL_BASE_URL } else { "https://github.com/$Repo/releases/download/$ver" }

# Bearer header sent to a SIGIL_BASE_URL artifact server, if any.
$dlHeaders = @{}
if ($env:SIGIL_BASE_TOKEN) { $dlHeaders['Authorization'] = "Bearer $($env:SIGIL_BASE_TOKEN)" }

# dry-run hook: print the resolved asset + checksum URLs and exit before any
# download. Mirrors install.sh SIGIL_URL_DRYRUN; used by the parity test.
if ($env:SIGIL_URL_DRYRUN -eq '1') {
  Write-Output "$base/$asset"
  Write-Output "$base/SHA256SUMS"
  exit 0
}

# --- download + verify -----------------------------------------------------
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("sigil-install-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  $zip = Join-Path $tmp $asset
  $sums = Join-Path $tmp 'SHA256SUMS'

  Say "downloading $asset ($ver)"
  try { Invoke-WebRequest -Uri "$base/$asset"  -OutFile $zip  -Headers $dlHeaders -UseBasicParsing }
  catch { Die "download failed: $base/$asset" }
  try { Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sums -Headers $dlHeaders -UseBasicParsing }
  catch { Die "download failed: $base/SHA256SUMS" }

  Say "verifying checksum"
  $expected = $null
  foreach ($line in Get-Content $sums) {
    # sha256sum format: "<hex>  <filename>"
    $parts = $line -split '\s+', 2
    if ($parts.Count -eq 2 -and $parts[1].Trim() -eq $asset) { $expected = $parts[0].Trim(); break }
  }
  if (-not $expected) { Die "no checksum entry for $asset in SHA256SUMS" }
  $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash
  if ($actual -ine $expected) {
    Die "checksum verification FAILED for $asset — refusing to install"
  }

  # --- install -------------------------------------------------------------
  $unpack = Join-Path $tmp 'unpack'
  Expand-Archive -Path $zip -DestinationPath $unpack -Force
  $inner = Join-Path $unpack "sigil-$verN-$target"

  $installDir = if ($env:SIGIL_INSTALL_DIR) { $env:SIGIL_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\sigil' }
  New-Item -ItemType Directory -Force -Path $installDir | Out-Null

  foreach ($b in $binaries) {
    $src = Join-Path $inner "$b.exe"
    if (-not (Test-Path $src)) { Die "archive is missing expected binary: $b.exe" }
    Copy-Item -Path $src -Destination (Join-Path $installDir "$b.exe") -Force
  }

  Say "installed into $installDir`: $($binaries -join ' ')"
  Say "profile: $profileName — start the agent with 'sigil run' (sigil-mcp/sigil-hook need the running daemon)"

  # --- PATH ----------------------------------------------------------------
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($userPath -split ';') -notcontains $installDir) {
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $installDir } else { $userPath.TrimEnd(';') + ';' + $installDir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Say "added $installDir to your user PATH (open a new terminal to pick it up)"
  }
  # Make 'sigil' resolvable in the current session too.
  if (($env:Path -split ';') -notcontains $installDir) {
    $env:Path = $env:Path.TrimEnd(';') + ';' + $installDir
  }

  Say "next: sigil doctor"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
