#!/usr/bin/env pwsh
# install.ps1의 프로파일->binaries / 플랫폼->target 매핑을 dry-run으로 검증 (#172).
# install_profile_test.sh의 PowerShell 짝. 네트워크 없이 매핑 로직만 확인한다.
#   pwsh tests/install_profile_test.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$ps1 = Join-Path $root 'install.ps1'

$fail = 0
function Assert-Eq($desc, $expected, $actual) {
  if ($expected -ne $actual) {
    Write-Host "FAIL: $desc`n  want: $expected`n  got:  $actual"
    $script:fail = 1
  } else {
    Write-Host "ok: $desc"
  }
}

# profile -> binaries
function Profile-Run($p) {
  $env:SIGIL_PROFILE = $p
  $env:SIGIL_PROFILE_DRYRUN = '1'
  try { (& pwsh -NoProfile -File $ps1).Trim() } finally {
    Remove-Item Env:SIGIL_PROFILE -ErrorAction SilentlyContinue
    Remove-Item Env:SIGIL_PROFILE_DRYRUN -ErrorAction SilentlyContinue
  }
}
Assert-Eq 'personal subset'    'sigil sigil-mcp sigil-hook' (Profile-Run 'personal')
Assert-Eq 'fleet superset'     'sigil sigil-mcp sigil-hook sigil-sender sigil-server sigil-sign' (Profile-Run 'fleet')

$env:SIGIL_PROFILE_DRYRUN = '1'
$defaultBins = (& pwsh -NoProfile -File $ps1).Trim()
Remove-Item Env:SIGIL_PROFILE_DRYRUN -ErrorAction SilentlyContinue
Assert-Eq 'default is personal' 'sigil sigil-mcp sigil-hook' $defaultBins

$env:SIGIL_PROFILE = 'bogus'; $env:SIGIL_PROFILE_DRYRUN = '1'
& pwsh -NoProfile -File $ps1 *> $null
if ($LASTEXITCODE -eq 0) { Write-Host 'FAIL: bogus profile should exit non-zero'; $fail = 1 }
else { Write-Host 'ok: bogus profile rejected' }
Remove-Item Env:SIGIL_PROFILE, Env:SIGIL_PROFILE_DRYRUN -ErrorAction SilentlyContinue

# arch -> release target (#172: both Windows targets resolve)
function Target-Run($arch) {
  $env:SIGIL_ARCH_OVERRIDE = $arch
  $env:SIGIL_TARGET_DRYRUN = '1'
  try { (& pwsh -NoProfile -File $ps1).Trim() } finally {
    Remove-Item Env:SIGIL_ARCH_OVERRIDE -ErrorAction SilentlyContinue
    Remove-Item Env:SIGIL_TARGET_DRYRUN -ErrorAction SilentlyContinue
  }
}
Assert-Eq 'x64 target'   'x86_64-pc-windows-msvc'  (Target-Run 'X64')
Assert-Eq 'arm64 target' 'aarch64-pc-windows-msvc' (Target-Run 'Arm64')

$env:SIGIL_ARCH_OVERRIDE = 'X86'; $env:SIGIL_TARGET_DRYRUN = '1'
& pwsh -NoProfile -File $ps1 *> $null
if ($LASTEXITCODE -eq 0) { Write-Host 'FAIL: x86 (32-bit) should exit non-zero'; $fail = 1 }
else { Write-Host 'ok: 32-bit x86 rejected' }
Remove-Item Env:SIGIL_ARCH_OVERRIDE, Env:SIGIL_TARGET_DRYRUN -ErrorAction SilentlyContinue

exit $fail
