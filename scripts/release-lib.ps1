# Helpers for the release scripts of the product repositories (dot-source it):
#   . (Join-Path $PSScriptRoot '..\..\common\scripts\release-lib.ps1')
#
# Versions: each product repository has a VERSION file (MAJOR.MINOR.PATCH or
# MAJOR.MINOR.PATCH-PRERELEASE) and is tagged v<VERSION>. Cargo.toml /
# package.json / tauri.conf.json versions must match it (Test-NpwVersion
# checks, Publish-NpwVersion writes). Browser extension manifests get the
# numeric form from Get-NpwExtensionVersion.
# Runs on Windows PowerShell 5.1 and PowerShell 7.

$ErrorActionPreference = 'Stop'

$script:SemVer = '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$'

function Get-NpwVersion([string]$Repo) {
    $v = (Get-Content -LiteralPath (Join-Path $Repo 'VERSION') -Raw).Trim()
    if ($v -notmatch $script:SemVer) { throw "VERSION '$v' is not MAJOR.MINOR.PATCH[-PRERELEASE]" }
    return $v
}

# Chrome / Edge manifests only take 1-4 dot-separated integers. A release
# x.y.z becomes x.y.z.1000 and a prerelease x.y.z-beta.N becomes x.y.z.N
# (N < 1000), so a release always sorts after its prereleases.
function Get-NpwExtensionVersion([string]$Version) {
    if ($Version -notmatch $script:SemVer) { throw "'$Version' is not a version" }
    $core = "$($Matches[1]).$($Matches[2]).$($Matches[3])"
    if (-not $Matches[4]) { return "$core.1000" }
    if ($Matches[4] -notmatch '(\d+)$') { throw "prerelease '$($Matches[4])' must end in a number (e.g. -beta.2)" }
    $n = [int]$Matches[1]
    if ($n -ge 1000) { throw "prerelease number $n must be below 1000" }
    return "$core.$n"
}

function Get-CargoPackageVersion([string]$Toml) {
    $inPackage = $false
    foreach ($line in Get-Content -LiteralPath $Toml) {
        if ($line -match '^\s*\[(.+)\]\s*$') { $inPackage = ($Matches[1] -eq 'package'); continue }
        if ($inPackage -and $line -match '^\s*version\s*=\s*"([^"]+)"') { return $Matches[1] }
    }
    throw "$Toml has no [package] version"
}

function Set-CargoPackageVersion([string]$Toml, [string]$Version) {
    $inPackage = $false
    $done = $false
    $out = foreach ($line in Get-Content -LiteralPath $Toml) {
        if ($line -match '^\s*\[(.+)\]\s*$') { $inPackage = ($Matches[1] -eq 'package') }
        elseif ($inPackage -and -not $done -and $line -match '^(\s*version\s*=\s*)"[^"]+"(.*)$') {
            $line = "$($Matches[1])`"$Version`"$($Matches[2])"
            $done = $true
        }
        $line
    }
    if (-not $done) { throw "$Toml has no [package] version" }
    [IO.File]::WriteAllText($Toml, (($out -join "`n") + "`n"))
}

# The top-level "version" of a JSON file (package.json, tauri.conf.json, manifest.json).
function Get-JsonVersion([string]$Path) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -notmatch '(?m)^\s{2}"version"\s*:\s*"([^"]*)"') { throw "$Path has no top-level version" }
    return $Matches[1]
}

function Set-JsonVersion([string]$Path, [string]$Version) {
    $text = Get-Content -LiteralPath $Path -Raw
    $new = [regex]::Replace($text, '(?m)^(\s{2}"version"\s*:\s*")[^"]*(")', "`${1}$Version`${2}", 1)
    if ($new -eq $text -and (Get-JsonVersion $Path) -ne $Version) { throw "could not set the version in $Path" }
    [IO.File]::WriteAllText($Path, $new)
}

# VERSION, every listed Cargo.toml / JSON file and (if given) the tag agree.
function Test-NpwVersion([string]$Repo, [string[]]$Tomls = @(), [string[]]$Jsons = @(), [string]$Tag = '') {
    $v = Get-NpwVersion $Repo
    foreach ($t in $Tomls) {
        $c = Get-CargoPackageVersion (Join-Path $Repo $t)
        if ($c -ne $v) { throw "$t has version $c but VERSION says $v (run scripts\release.ps1 to bump both)" }
    }
    foreach ($j in $Jsons) {
        $c = Get-JsonVersion (Join-Path $Repo $j)
        if ($c -ne $v) { throw "$j has version $c but VERSION says $v" }
    }
    if ($Tag -and $Tag -ne "v$v") { throw "tag $Tag does not match VERSION $v (expected v$v)" }
    return $v
}

function Invoke-Checked([string]$FilePath, [string[]]$Arguments = @()) {
    # cargo / npm write progress to stderr; Windows PowerShell 5.1 turns that
    # into errors under 'Stop', so success is decided by the exit code alone.
    $ErrorActionPreference = 'Continue'
    & $FilePath @Arguments
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -ne 0) { throw "$FilePath $($Arguments -join ' ') failed with exit code $code" }
}

function Write-Sha256([string]$Path) {
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$Path.sha256" -Value "$hash  $(Split-Path -Leaf $Path)" -Encoding ascii
}

# The item format this common commit writes must be frozen before a client
# release ships it (design doc §5.6): format/history/vX.Y/schema.json equal to
# the current schema, plus the encrypted compat samples tests/compat/vX.Y/.
function Test-NpwFormatFrozen([string]$Common) {
    $model = Join-Path $Common 'crates\npw-model'
    $src = Get-Content -LiteralPath (Join-Path $model 'src\format.rs') -Raw
    if ($src -notmatch 'FORMAT_MAJOR: u16 = (\d+);') { throw 'FORMAT_MAJOR not found in npw-model' }
    $major = $Matches[1]
    if ($src -notmatch 'FORMAT_MINOR: u16 = (\d+);') { throw 'FORMAT_MINOR not found in npw-model' }
    $v = "v$major.$($Matches[1])"
    $frozen = Join-Path $model "format\history\$v\schema.json"
    $compat = Join-Path $Common "crates\npw-core\tests\compat\$v"
    $howTo = "copy crates\npw-model\format\schema.json to format\history\$v\ and run `$env:NPW_BLESS=1; cargo test -p npw-core --test compat` in common, then commit"
    if (-not (Test-Path -LiteralPath $frozen) -or -not (Test-Path -LiteralPath $compat)) {
        throw "item format $v is not frozen yet: $howTo"
    }
    $norm = { param($p) (Get-Content -LiteralPath $p -Raw) -replace "`r`n", "`n" }
    if ((& $norm $frozen) -ne (& $norm (Join-Path $model 'format\schema.json'))) {
        throw "format\schema.json differs from the frozen format\history\$v. If $v was already released, bump FORMAT_MINOR for the new keys; otherwise re-freeze: $howTo"
    }
}

# Bump VERSION and the listed manifests, pin the common commit (COMMON_REF,
# used by the release build), commit and tag v<Version>.
function Publish-NpwVersion {
    param(
        [string]$Repo, [string]$Product, [string[]]$Tomls = @(), [string[]]$Jsons = @(),
        [string]$Version, [switch]$Push, [switch]$NoCargoUpdate
    )
    if ($Version -notmatch $script:SemVer) { throw "'$Version' is not MAJOR.MINOR.PATCH[-PRERELEASE]" }
    $common = Resolve-Path (Join-Path $Repo '..\common')
    Push-Location $Repo
    try {
        if (git status --porcelain --untracked-files=no) { throw "$Product has uncommitted changes; commit them first" }
        if (git tag --list "v$Version") { throw "tag v$Version already exists" }
        if (git -C $common status --porcelain --untracked-files=no) { throw 'common has uncommitted changes; commit and push them first' }
        Test-NpwFormatFrozen $common
        $commonSha = (git -C $common rev-parse HEAD).Trim()
        Invoke-Checked git @('-C', $common, 'fetch', '--quiet', 'origin')
        if (-not (git -C $common branch -r --contains $commonSha)) { throw "common $commonSha is not pushed; push common first (the release build checks it out)" }

        Set-Content -LiteralPath 'VERSION' -Value $Version -Encoding ascii
        foreach ($t in $Tomls) { Set-CargoPackageVersion (Join-Path $Repo $t) $Version }
        foreach ($j in $Jsons) { Set-JsonVersion (Join-Path $Repo $j) $Version }
        Set-Content -LiteralPath 'COMMON_REF' -Value $commonSha -Encoding ascii
        $add = @('VERSION', 'COMMON_REF') + $Tomls + $Jsons
        if ($Tomls.Count -gt 0 -and -not $NoCargoUpdate) {
            Invoke-Checked cargo @('update', '--workspace', '--quiet')
            $add += 'Cargo.lock'
        }
        Invoke-Checked git (@('add') + $add)
        Invoke-Checked git @('commit', '--quiet', '-m', "Release $Product $Version")
        Invoke-Checked git @('tag', '-a', "v$Version", '-m', "$Product $Version")
        Write-Host "tagged v$Version (common $($commonSha.Substring(0, 8)))" -ForegroundColor Green
        if ($Push) {
            Invoke-Checked git @('push', 'origin', 'HEAD', "v$Version")
            Write-Host 'pushed; GitHub Actions builds and publishes the release' -ForegroundColor Green
        } else {
            Write-Host "push with: git push origin HEAD v$Version" -ForegroundColor Yellow
        }
    } finally { Pop-Location }
}
