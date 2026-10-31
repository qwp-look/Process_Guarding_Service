param(
    [Parameter(Mandatory = $true)]
    [string]$ModulesRoot,

    [Parameter(Mandatory = $true)]
    [string]$Output,

    [string]$GeneratedAt = 'build'
)

$ErrorActionPreference = 'Stop'

# Manifest-driven modules.lock generation (manifest v2).
# Each modules/<name>/module.manifest.json supplies name/version/capabilities/
# risk/class; the DLL hash anchors the supply chain. The module set is whatever
# module directories with a manifest + DLL exist under ModulesRoot, so adding a
# bundled module no longer requires touching a hardcoded list.

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = $sha.ComputeHash($stream)
            return ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

$ModulesRoot = [System.IO.Path]::GetFullPath($ModulesRoot)
$Output = [System.IO.Path]::GetFullPath($Output)

$items = @()
foreach ($dir in (Get-ChildItem -LiteralPath $ModulesRoot -Directory | Sort-Object Name)) {
    $manifestPath = Join-Path $dir.FullName 'module.manifest.json'
    $dll = Join-Path $dir.FullName ("pgs_{0}_module.dll" -f $dir.Name)
    if (-not (Test-Path -LiteralPath $manifestPath)) { continue }
    if (-not [System.IO.File]::Exists($dll)) {
        throw "module manifest present but DLL missing: $dll"
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if (-not $manifest.name) {
        throw "manifest missing name: $manifestPath"
    }
    $manifestName = [string]$manifest.name
    if ($manifestName -ne $dir.Name) {
        throw "manifest name '$manifestName' does not match module folder '$($dir.Name)'"
    }

    $capabilities = @()
    if ($manifest.capabilities) { $capabilities = @($manifest.capabilities) }

    $items += [ordered]@{
        name = $manifestName
        version = [string]$manifest.version
        class = [string]$manifest.class
        sha256 = Get-Sha256Hex -Path $dll
        publisher = 'PGS bundled'
        source = 'bundled'
        capabilities = $capabilities
        risk = [string]$manifest.risk
        trustedAt = $GeneratedAt
        signature_policy = 'hash'
        require_signed = $false
    }
}

if ($items.Count -eq 0) {
    throw "no module manifests found under $ModulesRoot"
}

$outDir = [System.IO.Path]::GetDirectoryName($Output)
if ($outDir -and -not [System.IO.Directory]::Exists($outDir)) {
    [System.IO.Directory]::CreateDirectory($outDir) | Out-Null
}

[ordered]@{
    version = 2
    generated_at = $GeneratedAt
    modules = $items
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Output -Encoding ASCII
