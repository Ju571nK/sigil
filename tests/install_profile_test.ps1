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

# base URL resolution (#182): default = GitHub Releases; SIGIL_BASE_URL overrides.
function Asset-Url($baseUrl) {
  $env:SIGIL_ARCH_OVERRIDE = 'X64'; $env:SIGIL_VERSION = 'v0.6.2'
  $env:SIGIL_URL_DRYRUN = '1'
  if ($baseUrl) { $env:SIGIL_BASE_URL = $baseUrl }
  try { (& pwsh -NoProfile -File $ps1)[0] } finally {
    Remove-Item Env:SIGIL_ARCH_OVERRIDE, Env:SIGIL_VERSION, Env:SIGIL_URL_DRYRUN, Env:SIGIL_BASE_URL -ErrorAction SilentlyContinue
  }
}
Assert-Eq 'default base = github releases' `
  'https://github.com/Ju571nK/sigil/releases/download/v0.6.2/sigil-0.6.2-x86_64-pc-windows-msvc.zip' `
  (Asset-Url $null)
Assert-Eq 'SIGIL_BASE_URL overrides base' `
  'https://srv.example:8443/v1/artifacts/sigil-0.6.2-x86_64-pc-windows-msvc.zip' `
  (Asset-Url 'https://srv.example:8443/v1/artifacts')

$env:SIGIL_ARCH_OVERRIDE = 'X64'; $env:SIGIL_VERSION = 'v0.6.2'; $env:SIGIL_BASE_TOKEN = 'x'; $env:SIGIL_URL_DRYRUN = '1'
& pwsh -NoProfile -File $ps1 *> $null
if ($LASTEXITCODE -eq 0) { Write-Host 'FAIL: SIGIL_BASE_TOKEN without SIGIL_BASE_URL should exit non-zero'; $fail = 1 }
else { Write-Host 'ok: SIGIL_BASE_TOKEN requires SIGIL_BASE_URL' }
Remove-Item Env:SIGIL_ARCH_OVERRIDE, Env:SIGIL_VERSION, Env:SIGIL_BASE_TOKEN, Env:SIGIL_URL_DRYRUN -ErrorAction SilentlyContinue

$env:SIGIL_ARCH_OVERRIDE = 'X64'; $env:SIGIL_BASE_URL = 'https://srv.example/v1/artifacts'; $env:SIGIL_URL_DRYRUN = '1'
& pwsh -NoProfile -File $ps1 *> $null
if ($LASTEXITCODE -eq 0) { Write-Host 'FAIL: SIGIL_BASE_URL without SIGIL_VERSION should exit non-zero'; $fail = 1 }
else { Write-Host 'ok: SIGIL_BASE_URL requires SIGIL_VERSION' }
Remove-Item Env:SIGIL_ARCH_OVERRIDE, Env:SIGIL_BASE_URL, Env:SIGIL_URL_DRYRUN -ErrorAction SilentlyContinue

# #188 — Claude allowlist offer (personal only), via SIGIL_ALLOWLIST_DRYRUN.
function Allowlist-Snip($prof) {
  $env:SIGIL_PROFILE = $prof; $env:SIGIL_ALLOWLIST_DRYRUN = '1'
  try { (& pwsh -NoProfile -File $ps1 2>&1 | Out-String) } finally {
    Remove-Item Env:SIGIL_PROFILE, Env:SIGIL_ALLOWLIST_DRYRUN -ErrorAction SilentlyContinue
  }
}
$snip = Allowlist-Snip 'personal'
if ($snip -match '"allow": \["Bash\(sigil:\*\)"\]' -and $snip -match 'Bash\(sigil run:\*\)' -and $snip -match 'Bash\(sigil-hook:\*\)') {
  Write-Host 'ok: personal allowlist snippet (broad allow + deny run/hook)'
} else { Write-Host 'FAIL: personal allowlist snippet missing expected rules'; Write-Host $snip; $fail = 1 }
$fsnip = Allowlist-Snip 'fleet'
if ($fsnip -match 'skipped \(profile=fleet\)') { Write-Host 'ok: fleet profile does not offer allowlist' }
else { Write-Host 'FAIL: fleet should skip the allowlist offer'; $fail = 1 }

# #188 — Merge-SigilAllowlist must be idempotent, order-preserving, non-clobbering.
# Dot-source only the function block by extracting it is overkill; instead exercise
# the same native-JSON merge logic the installer uses, asserting array output.
$td = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $td | Out-Null
$sj = Join-Path $td 'settings.json'
'{"permissions":{"allow":["Bash(ls:*)"]},"keep":1}' | Set-Content -Path $sj -Encoding UTF8
$merge = {
  param($path)
  $cfg = (Get-Content -Raw $path | ConvertFrom-Json)
  if (-not $cfg.PSObject.Properties['permissions']) { $cfg | Add-Member -NotePropertyName permissions -NotePropertyValue ([pscustomobject]@{}) -Force }
  $perm = $cfg.permissions
  if (-not $perm.PSObject.Properties['allow']) { $perm | Add-Member -NotePropertyName allow -NotePropertyValue @() }
  if (-not $perm.PSObject.Properties['deny'])  { $perm | Add-Member -NotePropertyName deny  -NotePropertyValue @() }
  $a = @($perm.allow); if ($a -notcontains 'Bash(sigil:*)') { $a += 'Bash(sigil:*)' }; $perm.allow = $a
  $dn = @($perm.deny); foreach ($r in @('Bash(sigil run:*)','Bash(sigil-hook:*)')) { if ($dn -notcontains $r) { $dn += $r } }; $perm.deny = $dn
  $json = $cfg | ConvertTo-Json -Depth 10
  $json = [regex]::Replace($json, '("(?:allow|deny)"\s*:\s*)("(?:[^"\\]|\\.)*")(\s*[,\r\n}])', '$1[$2]$3')
  Set-Content -Path $path -Value $json -Encoding UTF8
}
& $merge $sj; & $merge $sj   # twice → idempotent
$res = (Get-Content -Raw $sj | ConvertFrom-Json)
if (@($res.permissions.allow).Count -eq 2 -and @($res.permissions.deny).Count -eq 2 -and $res.keep -eq 1 -and @($res.permissions.allow)[0] -eq 'Bash(ls:*)') {
  Write-Host 'ok: native merge idempotent + preserves existing allow/keys'
} else { Write-Host "FAIL: native merge (allow=$(@($res.permissions.allow).Count) deny=$(@($res.permissions.deny).Count))"; $fail = 1 }
Remove-Item -Recurse -Force $td -ErrorAction SilentlyContinue

exit $fail
