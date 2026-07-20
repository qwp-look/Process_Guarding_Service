param(
    [string]$Release = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'release'),
    [string]$OutputDir = '',
    [string]$Version = '',
    [string[]]$Artifacts = @(),
    [string]$ArtifactsList = '',
    [switch]$WriteSbom,
    [switch]$WriteChecksums
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-Sha256Hex {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $sha.Dispose()
    }
}

function Get-CommandVersionText {
    param([string]$Command, [string[]]$Args = @('--version'))
    try {
        $output = & $Command @Args 2>$null
        if ($LASTEXITCODE -eq 0 -and $output) {
            return (($output | ForEach-Object { $_.ToString() }) -join ' ').Trim()
        }
    }
    catch {
    }
    return ''
}

function Get-RelativePathCompat {
    param([string]$Root, [string]$Path)
    $rootFull = [System.IO.Path]::GetFullPath($Root)
    if (-not $rootFull.EndsWith([System.IO.Path]::DirectorySeparatorChar) -and -not $rootFull.EndsWith([System.IO.Path]::AltDirectorySeparatorChar)) {
        $rootFull += [System.IO.Path]::DirectorySeparatorChar
    }
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $rootUri = New-Object System.Uri($rootFull)
    $pathUri = New-Object System.Uri($pathFull)
    return [System.Uri]::UnescapeDataString($rootUri.MakeRelativeUri($pathUri).ToString()).Replace('/', [System.IO.Path]::DirectorySeparatorChar)
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Release = [System.IO.Path]::GetFullPath($Release)
if (-not (Test-Path -LiteralPath $Release -PathType Container)) {
    throw "release directory not found: $Release"
}

if (-not $OutputDir) {
    $OutputDir = $Release
}
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

if ($ArtifactsList) {
    $Artifacts += ($ArtifactsList -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

if (-not $Version) {
    $versionFile = Join-Path $repoRoot 'VERSION'
    if (Test-Path -LiteralPath $versionFile) {
        $Version = (Get-Content -LiteralPath $versionFile -Raw).Trim()
    }
}
if (-not $Version) {
    $Version = '0.0.0-local'
}

$commit = ''
try {
    $commit = (& git -C $repoRoot rev-parse HEAD 2>$null).Trim()
}
catch {
}
$branch = ''
try {
    $branch = (& git -C $repoRoot rev-parse --abbrev-ref HEAD 2>$null).Trim()
}
catch {
}

$files = @()
Get-ChildItem -LiteralPath $Release -Recurse -File | Sort-Object FullName | ForEach-Object {
    $relative = (Get-RelativePathCompat $Release $_.FullName).Replace('\', '/')
    $files += [pscustomobject]@{
        path = $relative
        size = [int64]$_.Length
        sha256 = Get-Sha256Hex $_.FullName
    }
}

$artifactObjects = @()
foreach ($artifact in $Artifacts) {
    if ([string]::IsNullOrWhiteSpace($artifact)) {
        continue
    }
    $artifactPath = [System.IO.Path]::GetFullPath($artifact)
    if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
        throw "artifact not found: $artifactPath"
    }
    $item = Get-Item -LiteralPath $artifactPath
    $artifactObjects += [pscustomobject]@{
        name = $item.Name
        path = $artifactPath
        size = [int64]$item.Length
        sha256 = Get-Sha256Hex $artifactPath
    }
}

$modulesLockPath = Join-Path $Release 'modules\modules.lock'
$modulesLock = $null
if (Test-Path -LiteralPath $modulesLockPath) {
    try {
        $modulesLock = Get-Content -LiteralPath $modulesLockPath -Raw | ConvertFrom-Json
    }
    catch {
        $modulesLock = $null
    }
}

$manifest = [pscustomobject]@{
    schema = 'pgs.release-manifest.v1'
    version = $Version
    generated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    source = [pscustomobject]@{
        commit = $commit
        branch = $branch
    }
    toolchain = [pscustomobject]@{
        powershell = $PSVersionTable.PSVersion.ToString()
        cmake = Get-CommandVersionText 'cmake'
        git = Get-CommandVersionText 'git'
    }
    release_root = $Release
    file_count = $files.Count
    files = $files
    artifacts = $artifactObjects
    modules_lock = $modulesLock
}

$manifestPath = Join-Path $OutputDir 'release-manifest.json'
$manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

if ($WriteChecksums) {
    $checksumLines = @()
    foreach ($artifact in $artifactObjects) {
        $checksumLines += "$($artifact.sha256)  $($artifact.name)"
    }
    if (-not $checksumLines.Count) {
        foreach ($file in $files) {
            $checksumLines += "$($file.sha256)  $($file.path)"
        }
    }
    Set-Content -LiteralPath (Join-Path $OutputDir 'SHA256SUMS.txt') -Value $checksumLines -Encoding ASCII
}

if ($WriteSbom) {
    $namespaceVersion = $Version -replace '[^A-Za-z0-9_.-]', '-'
    $namespaceCommit = if ($commit) { $commit } else { [Guid]::NewGuid().ToString('N') }
    $spdxFiles = @()
    foreach ($file in $files) {
        $spdxFiles += [pscustomobject]@{
            SPDXID = 'SPDXRef-File-' + (($file.path -replace '[^A-Za-z0-9.-]', '-') -replace '-+', '-')
            fileName = $file.path
            checksums = @([pscustomobject]@{ algorithm = 'SHA256'; checksumValue = $file.sha256 })
            licenseConcluded = 'NOASSERTION'
            copyrightText = 'NOASSERTION'
        }
    }
    $sbom = [pscustomobject]@{
        spdxVersion = 'SPDX-2.3'
        dataLicense = 'CC0-1.0'
        SPDXID = 'SPDXRef-DOCUMENT'
        name = "ProcessGuardService-$Version"
        documentNamespace = "https://processguard.local/spdx/ProcessGuardService-$namespaceVersion-$namespaceCommit"
        creationInfo = [pscustomobject]@{
            created = [DateTimeOffset]::UtcNow.ToString('o')
            creators = @('Tool: tools/write_release_manifest.ps1')
        }
        packages = @([pscustomobject]@{
            SPDXID = 'SPDXRef-Package-ProcessGuardService'
            name = 'ProcessGuardService'
            versionInfo = $Version
            downloadLocation = 'NOASSERTION'
            filesAnalyzed = $true
            licenseConcluded = 'NOASSERTION'
            licenseDeclared = 'Apache-2.0'
            copyrightText = 'NOASSERTION'
        })
        files = $spdxFiles
        relationships = @([pscustomobject]@{
            spdxElementId = 'SPDXRef-DOCUMENT'
            relationshipType = 'DESCRIBES'
            relatedSpdxElement = 'SPDXRef-Package-ProcessGuardService'
        })
    }
    $sbom | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $OutputDir 'sbom.spdx.json') -Encoding UTF8
}

Write-Host "release manifest written: $manifestPath"
if ($WriteSbom) { Write-Host "SBOM written: $(Join-Path $OutputDir 'sbom.spdx.json')" }
if ($WriteChecksums) { Write-Host "checksums written: $(Join-Path $OutputDir 'SHA256SUMS.txt')" }
