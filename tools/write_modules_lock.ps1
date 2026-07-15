param(
    [Parameter(Mandatory = $true)]
    [string]$ModulesRoot,

    [Parameter(Mandatory = $true)]
    [string]$Output,

    [string]$GeneratedAt = 'build'
)

$ErrorActionPreference = 'Stop'

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

$capabilities = @{
    sched = @('sched.add', 'sched.list', 'sched.remove', 'sched.enable', 'sched.disable', 'guard.register', 'guard.unregister', 'guard.intentional', 'guard.policy', 'guard.list')
    health = @('health.summary', 'health.stats', 'guard.list', 'event.read')
    profile = @('profile.set', 'profile.list', 'profile.apply', 'guard.policy')
    report = @('report.snapshot', 'report.backup', 'event.read', 'guard.list', 'health.stats')
    ppl = @('driver.kernel', 'driver.sirius.load', 'process.ppl.set', 'process.ppl.clear', 'ppl.set', 'ppl.get', 'ppl.clear')
}

$items = @()
foreach ($name in @('sched', 'health', 'profile', 'report', 'ppl')) {
    $dll = Join-Path $ModulesRoot (Join-Path $name ("pgs_{0}_module.dll" -f $name))
    if (-not [System.IO.File]::Exists($dll)) {
        throw "required module DLL missing: $dll"
    }

    $risk = 'low'
    if ($name -eq 'ppl') {
        $risk = 'critical'
    }
    elseif ($name -eq 'sched' -or $name -eq 'profile') {
        $risk = 'medium'
    }

    $items += [ordered]@{
        name = $name
        version = '1.0.0'
        sha256 = Get-Sha256Hex -Path $dll
        publisher = 'PGS bundled'
        source = 'bundled'
        capabilities = $capabilities[$name]
        risk = $risk
        trustedAt = $GeneratedAt
        signature_policy = 'hash'
        require_signed = $false
    }
}

if ($items.Count -ne 5) {
    throw "expected 5 bundled modules, got $($items.Count)"
}

$outDir = [System.IO.Path]::GetDirectoryName($Output)
if ($outDir -and -not [System.IO.Directory]::Exists($outDir)) {
    [System.IO.Directory]::CreateDirectory($outDir) | Out-Null
}

[ordered]@{
    version = 1
    generated_at = $GeneratedAt
    modules = $items
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Output -Encoding ASCII
