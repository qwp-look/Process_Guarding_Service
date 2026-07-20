param(
    [string]$ClusterExe = '',
    [string]$WorkRoot = '',
    [string]$Token = 'pgs-cluster-smoke-token',
    [int]$Port = 0,
    [string]$MingwBin = 'C:\msys64\mingw64\bin'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), 0)
    $listener.Start()
    try { return [int]$listener.LocalEndpoint.Port }
    finally { $listener.Stop() }
}

function Invoke-ClusterJson {
    param(
        [string]$Uri,
        [hashtable]$Headers,
        [string]$Method = 'GET',
        [object]$Body = $null,
        [int]$TimeoutSec = 5
    )
    $jsonBody = $null
    if ($null -ne $Body) { $jsonBody = $Body | ConvertTo-Json -Compress }
    if ($null -ne $jsonBody) {
        return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method -Body $jsonBody -ContentType 'application/json' -TimeoutSec $TimeoutSec
    }
    return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method -TimeoutSec $TimeoutSec
}

function Wait-ClusterReady {
    param([string]$BaseUrl, [hashtable]$Headers)
    for ($i = 0; $i -lt 50; $i++) {
        try {
            $summary = Invoke-ClusterJson -Uri "$BaseUrl/api/cluster/summary" -Headers $Headers -TimeoutSec 3
            if ($null -ne $summary.nodes) { return $summary }
        }
        catch { }
        Start-Sleep -Milliseconds 200
    }
    throw 'cluster server did not become ready'
}

function Stop-ProcessSafe {
    param([System.Diagnostics.Process]$Process)
    if ($Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $Process.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if ([string]::IsNullOrWhiteSpace($ClusterExe)) {
    $ClusterExe = Join-Path $repoRoot 'build\pgs_cluster_web\pgs_cluster_web.exe'
}
if ([string]::IsNullOrWhiteSpace($WorkRoot)) {
    $WorkRoot = Join-Path $repoRoot 'build\cluster_api_smoke'
}
if ($Port -le 0) { $Port = Get-FreeTcpPort }

Assert-True (Test-Path -LiteralPath $ClusterExe) "missing cluster executable: $ClusterExe"
New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
if (Test-Path -LiteralPath $MingwBin) {
    $env:PATH = "$MingwBin;$env:PATH"
}

$nodesFile = Join-Path $WorkRoot 'nodes.txt'
$stdoutLog = Join-Path $WorkRoot 'pgs_cluster_web.out.log'
$stderrLog = Join-Path $WorkRoot 'pgs_cluster_web.err.log'
Set-Content -LiteralPath $nodesFile -Value '' -Encoding ASCII
Remove-Item -LiteralPath $stdoutLog, $stderrLog -ErrorAction SilentlyContinue

$proc = $null
try {
    $proc = Start-Process -FilePath $ClusterExe `
        -ArgumentList @('--listen-address', '127.0.0.1', '--listen-port', "$Port", '--nodes-file', $nodesFile, '--api-token', $Token, '--node-insecure-tls') `
        -WorkingDirectory (Split-Path -Parent $ClusterExe) `
        -WindowStyle Hidden `
        -PassThru `
        -RedirectStandardOutput $stdoutLog `
        -RedirectStandardError $stderrLog

    $baseUrl = "http://127.0.0.1:$Port"
    $headers = @{ 'X-API-Token' = $Token }
    Wait-ClusterReady -BaseUrl $baseUrl -Headers $headers | Out-Null

    $unauthorized = $false
    try {
        Invoke-RestMethod -Uri "$baseUrl/api/cluster/nodes" -TimeoutSec 3 | Out-Null
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
        $unauthorized = ($statusCode -eq 401)
    }
    Assert-True $unauthorized 'cluster nodes endpoint accepted a request without API token'

    $secret = 'admin:cluster-secret'
    $add = Invoke-ClusterJson -Uri "$baseUrl/api/cluster/nodes" -Headers $headers -Method POST -Body @{ name = 'alpha'; url = 'https://127.0.0.1:65535'; credentials = $secret }
    Assert-True ($add.ok -eq $true -and $add.added -eq 'alpha') 'cluster node add failed'

    $nodes = Invoke-ClusterJson -Uri "$baseUrl/api/cluster/nodes" -Headers $headers
    $nodeArray = @($nodes.nodes)
    Assert-True ($nodeArray.Count -eq 1) 'cluster nodes list did not return one node after add'
    Assert-True ($nodeArray[0].name -eq 'alpha') 'cluster nodes list returned wrong node name after add'
    Assert-True ($nodeArray[0].url -eq 'https://127.0.0.1:65535') 'cluster nodes list returned wrong normalized URL after add'
    $nodesText = $nodes | ConvertTo-Json -Depth 8 -Compress
    Assert-True ($nodesText -notmatch [regex]::Escape($secret)) 'cluster nodes API echoed saved credentials'

    $registryText = Get-Content -LiteralPath $nodesFile -Raw
    Assert-True ($registryText -notmatch [regex]::Escape($secret)) 'cluster registry stored node credentials as plaintext'

    $test = Invoke-ClusterJson -Uri "$baseUrl/api/cluster/nodes/test" -Headers $headers -Method POST -Body @{ name = 'alpha' }
    Assert-True ($test.ok -eq $true) 'cluster node test did not return ok=true envelope'
    Assert-True ($test.reachable -eq $false) 'cluster node test unexpectedly reached closed test node'
    $testText = $test | ConvertTo-Json -Depth 8 -Compress
    Assert-True ($testText -notmatch [regex]::Escape($secret)) 'cluster node test echoed saved credentials'

    $update = Invoke-ClusterJson -Uri "$baseUrl/api/cluster/nodes" -Headers $headers -Method PUT -Body @{ current_name = 'alpha'; name = 'beta'; url = 'https://127.0.0.1:65534' }
    Assert-True ($update.ok -eq $true -and $update.updated -eq 'beta') 'cluster node update/rename failed'

    $clear = Invoke-ClusterJson -Uri "$baseUrl/api/cluster/nodes" -Headers $headers -Method PUT -Body @{ current_name = 'beta'; name = 'beta'; url = 'https://127.0.0.1:65534'; clear_credentials = $true }
    Assert-True ($clear.ok -eq $true -and $clear.updated -eq 'beta') 'cluster node credential clear failed'
    $registryText = Get-Content -LiteralPath $nodesFile -Raw
    Assert-True ($registryText -notmatch [regex]::Escape($secret)) 'cluster registry retained old plaintext credentials after clear'

    $nodes = Invoke-ClusterJson -Uri "$baseUrl/api/cluster/nodes" -Headers $headers
    $nodeArray = @($nodes.nodes)
    $nodesText = $nodes | ConvertTo-Json -Depth 8 -Compress
    Assert-True ($nodesText -notmatch 'credentials') 'cluster nodes API exposed a credentials field'
    Assert-True ($nodeArray[0].name -eq 'beta') 'cluster nodes list did not reflect rename'

    $remove = Invoke-ClusterJson -Uri "$baseUrl/api/cluster/nodes" -Headers $headers -Method DELETE -Body @{ name = 'beta' }
    Assert-True ($remove.ok -eq $true -and $remove.removed -eq 'beta') 'cluster node remove failed'
    $nodes = Invoke-ClusterJson -Uri "$baseUrl/api/cluster/nodes" -Headers $headers
    Assert-True (@($nodes.nodes).Count -eq 0) 'cluster node remained after remove'

    Write-Host 'CLUSTER_API_SMOKE_OK'
}
finally {
    Stop-ProcessSafe $proc
}
