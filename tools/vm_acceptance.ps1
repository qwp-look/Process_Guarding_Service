param(
    [string]$WorkRoot = 'C:\PGS_ACCEPTANCE',
    [string]$ReleaseZip = '',
    [string]$SetupExe = '',
    [int]$PortablePort = 55431,
    [int]$ServicePort = 55432,
    [int]$WebPort = 55433,
    [int]$ClusterPort = 55434,
    [string]$Token = 'pgs-acceptance-token',
    [string]$InstallDir = '',
    [switch]$SkipInstaller,
    [switch]$EnablePpl,
    [switch]$RunWinApp
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Step {
    param([string]$Name)
    Write-Host ""
    Write-Host "== $Name =="
}

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Path {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "missing path: $Path"
    }
}

function Stop-ByName {
    param([string[]]$Names)
    foreach ($name in $Names) {
        Get-Process -Name $name -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Logged {
    param(
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [int[]]$AllowedExitCodes = @(0),
        [string]$WorkingDirectory = ''
    )

    $oldLocation = Get-Location
    if ($WorkingDirectory) {
        Set-Location -LiteralPath $WorkingDirectory
    }
    try {
        $oldErrorAction = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = & $FilePath @Arguments 2>&1
            $code = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $oldErrorAction
        }
    }
    finally {
        if ($WorkingDirectory) {
            Set-Location $oldLocation
        }
    }

    $text = (($output | ForEach-Object { $_.ToString() }) -join "`n").Trim()
    if ($AllowedExitCodes -notcontains $code) {
        throw "command failed ($code): $FilePath $($Arguments -join ' ')`n$text"
    }
    [pscustomobject]@{ Code = $code; Text = $text }
}

function Invoke-Pgs {
    param(
        [string]$BlessExe,
        [int]$Port,
        [string]$Token,
        [string[]]$CommandArgs,
        [switch]$AllowError
    )

    $attempts = 10
    $text = ''
    $code = 1
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        $result = Invoke-Logged -FilePath $BlessExe -Arguments (@('--token', $Token, '--port', "$Port") + $CommandArgs) -AllowedExitCodes (0..255)
        $code = $result.Code
        $text = $result.Text
        if ($code -eq 0 -or $text -notmatch 'Failed to connect to PGS') {
            break
        }
        Start-Sleep -Milliseconds 300
    }

    if (-not $AllowError -and $code -ne 0) {
        throw "pgs_bless failed ($($CommandArgs -join ' ')): $text"
    }

    [pscustomobject]@{ Code = $code; Text = $text }
}

function Invoke-PgsOk {
    param(
        [string]$BlessExe,
        [int]$Port,
        [string]$Token,
        [string[]]$CommandArgs
    )
    (Invoke-Pgs -BlessExe $BlessExe -Port $Port -Token $Token -CommandArgs $CommandArgs).Text
}

function Wait-PgsReady {
    param(
        [string]$BlessExe,
        [int]$Port,
        [string]$Token
    )
    for ($i = 0; $i -lt 80; $i++) {
        $ping = Invoke-Pgs -BlessExe $BlessExe -Port $Port -Token $Token -CommandArgs @('ping') -AllowError
        if ($ping.Code -eq 0 -and $ping.Text -match '^OK pong') {
            return
        }
        Start-Sleep -Milliseconds 250
    }
    throw "PGS did not become ready on port $Port"
}

function Start-PgsConsole {
    param(
        [string]$ReleaseDir,
        [int]$Port,
        [string]$Token,
        [string]$ProgramDataRoot,
        [string]$LogPrefix,
        [switch]$WithoutTokenEnv,
        [switch]$EnablePpl
    )

    New-Item -ItemType Directory -Force -Path $ProgramDataRoot | Out-Null
    $stdout = "$LogPrefix.out.log"
    $stderr = "$LogPrefix.err.log"
    Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue

    $oldProgramData = $env:ProgramData
    $oldToken = $env:PGS_SERVICE_TOKEN
    $oldPpl = $env:PGS_ENABLE_PPL
    try {
        $env:ProgramData = $ProgramDataRoot
        if ($WithoutTokenEnv) {
            Remove-Item Env:PGS_SERVICE_TOKEN -ErrorAction SilentlyContinue
        }
        else {
            $env:PGS_SERVICE_TOKEN = $Token
        }
        if ($EnablePpl) {
            $env:PGS_ENABLE_PPL = '1'
        }
        else {
            Remove-Item Env:PGS_ENABLE_PPL -ErrorAction SilentlyContinue
        }
        $proc = Start-Process -FilePath (Join-Path $ReleaseDir 'pgs_service.exe') `
            -ArgumentList (@('run', '--port', "$Port") + ($(if ($EnablePpl) { @('--enable-ppl') } else { @() }))) `
            -WorkingDirectory $ReleaseDir `
            -WindowStyle Hidden `
            -PassThru `
            -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr
    }
    finally {
        if ($null -eq $oldProgramData) { Remove-Item Env:ProgramData -ErrorAction SilentlyContinue } else { $env:ProgramData = $oldProgramData }
        if ($null -eq $oldToken) { Remove-Item Env:PGS_SERVICE_TOKEN -ErrorAction SilentlyContinue } else { $env:PGS_SERVICE_TOKEN = $oldToken }
        if ($null -eq $oldPpl) { Remove-Item Env:PGS_ENABLE_PPL -ErrorAction SilentlyContinue } else { $env:PGS_ENABLE_PPL = $oldPpl }
    }

    Wait-PgsReady -BlessExe (Join-Path $ReleaseDir 'pgs_bless.exe') -Port $Port -Token $Token
    $proc
}

function Stop-ProcessSafe {
    param([System.Diagnostics.Process]$Process)
    if ($Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $Process.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
}

function Ensure-ModuleLoaded {
    param(
        [string]$BlessExe,
        [int]$Port,
        [string]$Token,
        [string]$Path
    )
    $load = Invoke-Pgs -BlessExe $BlessExe -Port $Port -Token $Token -CommandArgs @('module', 'load', '--path', $Path) -AllowError
    if ($load.Code -ne 0 -and $load.Text -notmatch 'module already loaded') {
        throw "module load failed for ${Path}: $($load.Text)"
    }
}

function Invoke-JsonWeb {
    param(
        [string]$Uri,
        [hashtable]$Headers = @{}
    )
    for ($i = 0; $i -lt 50; $i++) {
        try {
            return Invoke-RestMethod -Uri $Uri -Headers $Headers -TimeoutSec 3
        }
        catch {
            if ($i -eq 49) {
                throw
            }
            Start-Sleep -Milliseconds 250
        }
    }
}

function Invoke-WebContent {
    param(
        [string]$Uri,
        [hashtable]$Headers = @{}
    )
    for ($i = 0; $i -lt 50; $i++) {
        try {
            return (Invoke-WebRequest -Uri $Uri -Headers $Headers -TimeoutSec 3 -UseBasicParsing).Content
        }
        catch {
            if ($i -eq 49) {
                throw
            }
            Start-Sleep -Milliseconds 250
        }
    }
}

function Get-InitialToken {
    param([string]$Path)
    for ($i = 0; $i -lt 40; $i++) {
        if (Test-Path -LiteralPath $Path) {
            $text = (Get-Content -LiteralPath $Path -Raw).Trim()
            if ($text) {
                return $text
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw "initial token file was not written: $Path"
}

function Stop-And-Delete-PgsService {
    $null = & sc.exe stop PGS 2>$null
    for ($i = 0; $i -lt 30; $i++) {
        $query = & sc.exe query PGS 2>&1
        if ($LASTEXITCODE -ne 0) {
            break
        }
        $text = ($query | Out-String)
        if ($text -match 'STATE\s+:\s+1\s+STOPPED' -or $text -match 'does not exist|1060') {
            break
        }
        Start-Sleep -Seconds 1
    }
    $null = & sc.exe delete PGS 2>$null
    Start-Sleep -Seconds 1
}

function Remove-BrokenProgramInstall {
    $brokenDir = 'C:\Program'
    if (Test-Path -LiteralPath (Join-Path $brokenDir 'pgs_service.exe')) {
        Remove-Item -LiteralPath $brokenDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Wait-ServiceToolStatus {
    param(
        [string]$ServiceExe,
        [string]$Pattern,
        [int]$TimeoutSeconds = 30
    )
    $last = ''
    for ($i = 0; $i -lt $TimeoutSeconds; $i++) {
        $status = Invoke-Logged -FilePath $ServiceExe -Arguments @('status')
        $last = $status.Text
        if ($last -match $Pattern) {
            return $last
        }
        Start-Sleep -Seconds 1
    }
    throw "service status did not match '$Pattern' within ${TimeoutSeconds}s: $last"
}

$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (-not $ReleaseZip) { $ReleaseZip = Join-Path $WorkRoot 'pgs_release_3.1.0.zip' }
if (-not $SetupExe) { $SetupExe = Join-Path $WorkRoot 'pgs_setup_3.1.0.exe' }
if (-not $InstallDir) { $InstallDir = Join-Path ${env:ProgramFiles} 'ProcessGuard' }

$ReleaseZip = [System.IO.Path]::GetFullPath($ReleaseZip)
$SetupExe = [System.IO.Path]::GetFullPath($SetupExe)
$PortableRelease = Join-Path $WorkRoot 'portable-release'
$ProgramDataPortable = Join-Path $WorkRoot 'pd-portable'
$ProgramDataService = Join-Path $WorkRoot 'pd-service'
$TrustRoot = Join-Path $WorkRoot 'trust-root'
$LogsRoot = Join-Path $WorkRoot 'logs'

$portableProc = $null
$serviceProc = $null
$webProc = $null
$clusterProc = $null
$qtProc = $null
$guardPid = $null

try {
    Write-Step 'Clean VM state'
    Assert-Path $ReleaseZip
    if (-not $SkipInstaller) { Assert-Path $SetupExe }
    New-Item -ItemType Directory -Force -Path $WorkRoot, $LogsRoot | Out-Null
    Stop-ByName @('pgs_service', 'pgs_bless', 'pgs_admin_web', 'pgs_cluster_web', 'pgs_admin_qt', 'smoke_worker')
    Stop-And-Delete-PgsService
    Remove-BrokenProgramInstall
    Remove-Item -LiteralPath $PortableRelease, $ProgramDataPortable, $ProgramDataService, $TrustRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path ${env:ProgramData} 'ProcessGuard') -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $InstallDir) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Step 'Extract portable release'
    New-Item -ItemType Directory -Force -Path $PortableRelease | Out-Null
    Expand-Archive -LiteralPath $ReleaseZip -DestinationPath $PortableRelease -Force

    $BlessExe = Join-Path $PortableRelease 'pgs_bless.exe'
    $ServiceExe = Join-Path $PortableRelease 'pgs_service.exe'
    $WebExe = Join-Path $PortableRelease 'pgs_admin_web.exe'
    $ClusterExe = Join-Path $PortableRelease 'pgs_cluster_web.exe'
    $QtExe = Join-Path $PortableRelease 'pgs_admin_qt.exe'
    $WorkerExe = Join-Path $PortableRelease 'examples\smoke_worker.exe'
    $ModulesDir = Join-Path $PortableRelease 'modules'
    $SchedDll = Join-Path $ModulesDir 'sched\pgs_sched_module.dll'
    $HealthDll = Join-Path $ModulesDir 'health\pgs_health_module.dll'
    $ProfileDll = Join-Path $ModulesDir 'profile\pgs_profile_module.dll'
    $ReportDll = Join-Path $ModulesDir 'report\pgs_report_module.dll'
    $PplDll = Join-Path $ModulesDir 'ppl\pgs_ppl_module.dll'

    foreach ($path in @(
        $BlessExe, $ServiceExe, $WebExe, $ClusterExe, $QtExe, $WorkerExe,
        $SchedDll, $HealthDll, $ProfileDll, $ReportDll, $PplDll,
        (Join-Path $ModulesDir 'modules.allow'),
        (Join-Path $PortableRelease 'Qt6Core.dll'),
        (Join-Path $PortableRelease 'libstdc++-6.dll'),
        (Join-Path $PortableRelease 'platforms\qwindows.dll'),
        (Join-Path $PortableRelease 'tls\qopensslbackend.dll')
    )) {
        Assert-Path $path
    }
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $ModulesDir 'notify'))) 'notify module should not be present'
    Write-Host '[acceptance] release layout ok'

    Write-Step 'Offline module trust inspection'
    $expectedModules = @(
        @{ Name = 'sched'; Path = $SchedDll },
        @{ Name = 'health'; Path = $HealthDll },
        @{ Name = 'profile'; Path = $ProfileDll },
        @{ Name = 'report'; Path = $ReportDll },
        @{ Name = 'ppl'; Path = $PplDll }
    )
    foreach ($module in $expectedModules) {
        $infoText = (Invoke-Logged -FilePath $BlessExe -Arguments @('module', 'info', '--path', $module.Path, '--json')).Text
        $info = $infoText | ConvertFrom-Json
        Assert-True ($info.name -eq $module.Name) "module name mismatch for $($module.Path): $($info.name)"
        Assert-True ($info.allow_entry_found -eq $true) "allowlist entry missing for $($module.Name)"
        Assert-True ($info.allow_entry_satisfied -eq $true) "allowlist entry not satisfied for $($module.Name)"
    }
    New-Item -ItemType Directory -Force -Path $TrustRoot | Out-Null
    Invoke-Logged -FilePath $BlessExe -Arguments @('module', 'trust', '--path', $HealthDll, '--modules-dir', $TrustRoot, '--hash', 'auto') | Out-Null
    $trustAllow = Get-Content -LiteralPath (Join-Path $TrustRoot 'modules.allow') -Raw
    Assert-True ($trustAllow -match 'health\|[0-9a-f]{64}') 'module trust did not write a pinned health entry'
    $signedTrust = Invoke-Logged -FilePath $BlessExe -Arguments @('module', 'trust', '--path', $HealthDll, '--modules-dir', $TrustRoot, '--require-signed') -AllowedExitCodes @(1)
    Assert-True ($signedTrust.Text -match 'require-signed|Authenticode') 'unsigned module unexpectedly satisfied --require-signed'
    Write-Host '[acceptance] offline module info/trust ok'

    Write-Step 'Portable service runtime'
    $portableProc = Start-PgsConsole -ReleaseDir $PortableRelease -Port $PortablePort -Token $Token -ProgramDataRoot $ProgramDataPortable -LogPrefix (Join-Path $LogsRoot 'portable-service')
    $ping = Invoke-PgsOk -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('ping')
    Assert-True ($ping -match '^OK pong') "unexpected ping response: $ping"
    $badAuth = Invoke-Pgs -BlessExe $BlessExe -Port $PortablePort -Token 'wrong-token' -CommandArgs @('ping') -AllowError
    Assert-True ($badAuth.Code -ne 0 -or $badAuth.Text -notmatch '^OK pong') 'wrong token was accepted'

    $pplLoad = Invoke-Pgs -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('module', 'load', '--path', $PplDll) -AllowError
    Assert-True ($pplLoad.Code -ne 0 -and $pplLoad.Text -match 'enable-kernel-modules|enable-risk critical|PGS_ENABLE_KERNEL_MODULES|PGS_ENABLE_PPL|enable-ppl') "PPL gate did not reject default load: $($pplLoad.Text)"

    if ($EnablePpl) {
        Write-Step 'PPL opt-in runtime smoke'
        Stop-ProcessSafe $portableProc
        $portableProc = Start-PgsConsole -ReleaseDir $PortableRelease -Port $PortablePort -Token $Token -ProgramDataRoot $ProgramDataPortable -LogPrefix (Join-Path $LogsRoot 'portable-ppl-enabled') -EnablePpl
        $pplOptInLoad = Invoke-Pgs -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('module', 'load', '--path', $PplDll) -AllowError
        Assert-True (($pplOptInLoad.Code -eq 0 -and $pplOptInLoad.Text -match '^OK loaded') -or $pplOptInLoad.Text -match 'module already loaded') "PPL opt-in load failed: $($pplOptInLoad.Text)"
    }

    foreach ($dll in @($SchedDll, $HealthDll, $ProfileDll, $ReportDll)) {
        Ensure-ModuleLoaded -BlessExe $BlessExe -Port $PortablePort -Token $Token -Path $dll
    }
    $modules = Invoke-PgsOk -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('module', 'list')
    foreach ($name in @('sched', 'health', 'profile', 'report')) {
        Assert-True ($modules -match $name) "module list missing $name`: $modules"
    }

    $sched = Invoke-PgsOk -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('schedule', 'list')
    Assert-True ($sched -match '^OK') "schedule list failed: $sched"
    $health = Invoke-PgsOk -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('health', 'summary')
    Assert-True ($health -match '^OK status=') "health summary failed: $health"
    $profileSet = Invoke-PgsOk -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('profile', 'set', '--name', 'acceptance', '--max-restarts', '2')
    Assert-True ($profileSet -match '^OK profile saved') "profile set failed: $profileSet"
    $profileList = Invoke-PgsOk -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('profile', 'list')
    Assert-True ($profileList -match 'NAME=acceptance') "profile list missing acceptance: $profileList"
    $report = Invoke-PgsOk -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('report', 'snapshot', '--limit', '10')
    Assert-True ($report -match '^OK mode=snapshot') "report snapshot failed: $report"
    $events = Invoke-PgsOk -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('events', 'list', '--limit', '10')
    Assert-True ($events -match '^OK count=') "events list failed: $events"

    $outsideDir = Join-Path $WorkRoot 'outside'
    New-Item -ItemType Directory -Force -Path $outsideDir | Out-Null
    $outsideDll = Join-Path $outsideDir 'pgs_sched_module.dll'
    Copy-Item -LiteralPath $SchedDll -Destination $outsideDll -Force
    $outsideLoad = Invoke-Pgs -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('module', 'load', '--path', $outsideDll) -AllowError
    Assert-True ($outsideLoad.Code -ne 0 -and $outsideLoad.Text -match 'restricted to modules directory|outside modules') "outside module load was not rejected: $($outsideLoad.Text)"

    Stop-ProcessSafe $portableProc
    $portableProc = $null

    Write-Step 'Module hash/signature negative runtime'
    $HashRelease = Join-Path $WorkRoot 'hash-negative-release'
    Remove-Item -LiteralPath $HashRelease -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $PortableRelease -Destination $HashRelease -Recurse
    $HashModulesDir = Join-Path $HashRelease 'modules'
    $HashBadDir = Join-Path $HashModulesDir 'hashbad'
    New-Item -ItemType Directory -Force -Path $HashBadDir | Out-Null
    Copy-Item -LiteralPath $SchedDll -Destination (Join-Path $HashBadDir 'pgs_sched_module.dll') -Force
    Set-Content -LiteralPath (Join-Path $HashModulesDir 'modules.allow') -Value ("hashbad|{0}" -f ('0' * 64)) -Encoding ASCII
    $hashProc = Start-PgsConsole -ReleaseDir $HashRelease -Port ($PortablePort + 10) -Token $Token -ProgramDataRoot (Join-Path $WorkRoot 'pd-hash-negative') -LogPrefix (Join-Path $LogsRoot 'hash-negative-service')
    try {
        $hashLoad = Invoke-Pgs -BlessExe (Join-Path $HashRelease 'pgs_bless.exe') -Port ($PortablePort + 10) -Token $Token -CommandArgs @('module', 'load', '--path', (Join-Path $HashBadDir 'pgs_sched_module.dll')) -AllowError
        Assert-True ($hashLoad.Code -ne 0 -and $hashLoad.Text -match 'hash mismatch') "hash mismatch was not rejected: $($hashLoad.Text)"
    }
    finally {
        Stop-ProcessSafe $hashProc
    }

    $SignedRelease = Join-Path $WorkRoot 'signed-negative-release'
    Remove-Item -LiteralPath $SignedRelease -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $PortableRelease -Destination $SignedRelease -Recurse
    $SignedModulesDir = Join-Path $SignedRelease 'modules'
    Set-Content -LiteralPath (Join-Path $SignedModulesDir 'modules.allow') -Value 'health||signed' -Encoding ASCII
    $signedProc = Start-PgsConsole -ReleaseDir $SignedRelease -Port ($PortablePort + 20) -Token $Token -ProgramDataRoot (Join-Path $WorkRoot 'pd-signed-negative') -LogPrefix (Join-Path $LogsRoot 'signed-negative-service')
    try {
        $signedLoad = Invoke-Pgs -BlessExe (Join-Path $SignedRelease 'pgs_bless.exe') -Port ($PortablePort + 20) -Token $Token -CommandArgs @('module', 'load', '--path', (Join-Path $SignedModulesDir 'health\pgs_health_module.dll')) -AllowError
        Assert-True ($signedLoad.Code -ne 0 -and $signedLoad.Text -match 'signature verification failed') "signed requirement was not rejected: $($signedLoad.Text)"
    }
    finally {
        Stop-ProcessSafe $signedProc
    }
    Write-Host '[acceptance] module security negatives ok'

    Write-Step 'Persistence after service restart'
    $portableProc = Start-PgsConsole -ReleaseDir $PortableRelease -Port $PortablePort -Token $Token -ProgramDataRoot $ProgramDataPortable -LogPrefix (Join-Path $LogsRoot 'portable-persist-1')
    foreach ($dll in @($HealthDll, $ProfileDll, $ReportDll)) {
        Ensure-ModuleLoaded -BlessExe $BlessExe -Port $PortablePort -Token $Token -Path $dll
    }
    $start = Invoke-PgsOk -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('bless-start', '--path', $WorkerExe, '--start-args', '--sleep-ms 60000', '--max-restarts', '1', '--hash', 'auto')
    $match = [regex]::Match($start, 'pid=([0-9]+)')
    Assert-True $match.Success "failed to parse bless-start pid: $start"
    $guardPid = [int]$match.Groups[1].Value
    Stop-ProcessSafe $portableProc
    $portableProc = $null
    $portableProc = Start-PgsConsole -ReleaseDir $PortableRelease -Port $PortablePort -Token $Token -ProgramDataRoot $ProgramDataPortable -LogPrefix (Join-Path $LogsRoot 'portable-persist-2') -WithoutTokenEnv
    $getGuard = Invoke-PgsOk -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('get', '--pid', "$guardPid")
    Assert-True ($getGuard -match '^OK') "persisted guard was not restored: $getGuard"
    Ensure-ModuleLoaded -BlessExe $BlessExe -Port $PortablePort -Token $Token -Path $ProfileDll
    $profileApply = Invoke-PgsOk -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('profile', 'apply', '--name', 'acceptance', '--pid', "$guardPid")
    Assert-True ($profileApply -match '^OK') "profile apply failed: $profileApply"
    Invoke-Pgs -BlessExe $BlessExe -Port $PortablePort -Token $Token -CommandArgs @('unbless', '--pid', "$guardPid") -AllowError | Out-Null
    Stop-Process -Id $guardPid -Force -ErrorAction SilentlyContinue
    $guardPid = $null
    Write-Host '[acceptance] token and guard persistence ok'

    Write-Step 'Web and cluster API'
    $webLog = Join-Path $LogsRoot 'pgs_admin_web.out.log'
    $webErr = Join-Path $LogsRoot 'pgs_admin_web.err.log'
    $webProc = Start-Process -FilePath $WebExe `
        -ArgumentList @('--bind', '127.0.0.1', '--http-port', "$WebPort", '--pgs-port', "$PortablePort", '--pgs-token', $Token, '--bless-tool', $BlessExe, '--service-tool', $ServiceExe, '--audit-log', (Join-Path $LogsRoot 'web-audit.log')) `
        -WorkingDirectory $PortableRelease `
        -WindowStyle Hidden `
        -PassThru `
        -RedirectStandardOutput $webLog `
        -RedirectStandardError $webErr
    $indexContent = Invoke-WebContent -Uri "http://127.0.0.1:$WebPort/"
    $apiTokenMatch = [regex]::Match($indexContent, 'window\.PGS_API_TOKEN="([^"]+)"')
    Assert-True $apiTokenMatch.Success 'web index did not expose the loopback API token'
    $headers = @{ 'X-PGS-Token' = $apiTokenMatch.Groups[1].Value }
    $webHealth = Invoke-JsonWeb -Uri "http://127.0.0.1:$WebPort/api/health" -Headers $headers
    Assert-True ($webHealth.ok -eq $true) 'web /api/health did not return ok=true'
    $webPing = Invoke-JsonWeb -Uri "http://127.0.0.1:$WebPort/api/ping" -Headers $headers
    Assert-True ((($webPing.stdout -as [string]) -match '^OK pong') -or (($webPing.message -as [string]) -match 'pong')) 'web /api/ping did not return pong'
    $webGuards = Invoke-JsonWeb -Uri "http://127.0.0.1:$WebPort/api/guards" -Headers $headers
    Assert-True ($null -ne $webGuards.guards) 'web /api/guards missing guards field'
    $webAudit = Invoke-JsonWeb -Uri "http://127.0.0.1:$WebPort/api/audit?limit=10" -Headers $headers
    Assert-True ($null -ne $webAudit.events) 'web /api/audit missing events field'

    $nodesFile = Join-Path $WorkRoot 'cluster_nodes.txt'
    Set-Content -LiteralPath $nodesFile -Value '' -Encoding ASCII
    $clusterLog = Join-Path $LogsRoot 'pgs_cluster_web.out.log'
    $clusterErr = Join-Path $LogsRoot 'pgs_cluster_web.err.log'
    $clusterProc = Start-Process -FilePath $ClusterExe `
        -ArgumentList @('--listen-address', '127.0.0.1', '--listen-port', "$ClusterPort", '--nodes-file', $nodesFile, '--api-token', $Token) `
        -WorkingDirectory $PortableRelease `
        -WindowStyle Hidden `
        -PassThru `
        -RedirectStandardOutput $clusterLog `
        -RedirectStandardError $clusterErr
    $clusterHeaders = @{ 'X-API-Token' = $Token }
    $clusterSummary = Invoke-JsonWeb -Uri "http://127.0.0.1:$ClusterPort/api/cluster/summary" -Headers $clusterHeaders
    Assert-True ($null -ne $clusterSummary.nodes) 'cluster summary missing nodes field'
    $clusterNodes = Invoke-JsonWeb -Uri "http://127.0.0.1:$ClusterPort/api/cluster/nodes" -Headers $clusterHeaders
    Assert-True ($null -ne $clusterNodes.nodes) 'cluster nodes missing nodes field'
    $nodeBody = @{ name = 'self'; url = "https://127.0.0.1:$WebPort"; credentials = 'admin:acceptance' } | ConvertTo-Json -Compress
    $nodeAdd = Invoke-WebRequest -Uri "http://127.0.0.1:$ClusterPort/api/cluster/nodes" -Headers $clusterHeaders -Method Post -Body $nodeBody -ContentType 'application/json' -TimeoutSec 3 -UseBasicParsing
    Assert-True ($nodeAdd.StatusCode -ge 200 -and $nodeAdd.StatusCode -lt 300) 'cluster node add failed'
    $nodeRemoveBody = @{ name = 'self' } | ConvertTo-Json -Compress
    $nodeRemove = Invoke-WebRequest -Uri "http://127.0.0.1:$ClusterPort/api/cluster/nodes" -Headers $clusterHeaders -Method Delete -Body $nodeRemoveBody -ContentType 'application/json' -TimeoutSec 3 -UseBasicParsing
    Assert-True ($nodeRemove.StatusCode -ge 200 -and $nodeRemove.StatusCode -lt 300) 'cluster node remove failed'
    Write-Host '[acceptance] web and cluster API ok'

    Write-Step 'Qt GUI launch smoke'
    $qtProc = Start-Process -FilePath $QtExe -WorkingDirectory $PortableRelease -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 3
    Assert-True (-not $qtProc.HasExited) 'pgs_admin_qt exited during launch smoke'
    Stop-ProcessSafe $qtProc
    $qtProc = $null
    Write-Host '[acceptance] Qt GUI launch ok'

    Stop-ProcessSafe $clusterProc
    $clusterProc = $null
    Stop-ProcessSafe $webProc
    $webProc = $null
    Stop-ProcessSafe $portableProc
    $portableProc = $null

    Write-Step 'SCM service mode'
    Remove-Item -LiteralPath (Join-Path ${env:ProgramData} 'ProcessGuard') -Recurse -Force -ErrorAction SilentlyContinue
    Stop-And-Delete-PgsService
    $install = Invoke-Logged -FilePath $ServiceExe -Arguments @('install', '--port', "$ServicePort")
    Assert-True ($install.Text -match 'Service installed') "service install unexpected output: $($install.Text)"
    $status1 = Invoke-Logged -FilePath $ServiceExe -Arguments @('status')
    Assert-True ($status1.Text -match 'Stopped|StartPending|Running') "service status after install unexpected: $($status1.Text)"
    Invoke-Logged -FilePath $ServiceExe -Arguments @('start') | Out-Null
    $initialTokenPath = Join-Path ${env:ProgramData} 'ProcessGuard\state\pgs_initial_token.txt'
    $serviceToken = Get-InitialToken -Path $initialTokenPath
    Wait-PgsReady -BlessExe $BlessExe -Port $ServicePort -Token $serviceToken
    $servicePing = Invoke-PgsOk -BlessExe $BlessExe -Port $ServicePort -Token $serviceToken -CommandArgs @('ping')
    Assert-True ($servicePing -match '^OK pong') "SCM service ping failed: $servicePing"
    Ensure-ModuleLoaded -BlessExe $BlessExe -Port $ServicePort -Token $serviceToken -Path $HealthDll
    $serviceHealth = Invoke-PgsOk -BlessExe $BlessExe -Port $ServicePort -Token $serviceToken -CommandArgs @('health', 'summary')
    Assert-True ($serviceHealth -match '^OK status=') "SCM service health failed: $serviceHealth"
    Invoke-Logged -FilePath $ServiceExe -Arguments @('stop') | Out-Null
    Wait-ServiceToolStatus -ServiceExe $ServiceExe -Pattern 'Stopped' -TimeoutSeconds 45 | Out-Null
    Invoke-Logged -FilePath $ServiceExe -Arguments @('uninstall') | Out-Null
    $statusGone = Invoke-Logged -FilePath $ServiceExe -Arguments @('status')
    Assert-True ($statusGone.Text -match 'Not installed') "service did not uninstall: $($statusGone.Text)"
    Write-Host '[acceptance] SCM service mode ok'

    if (-not $SkipInstaller) {
        Write-Step 'Installer silent install/uninstall'
        Stop-ByName @('pgs_service', 'pgs_admin_qt', 'pgs_admin_web', 'pgs_cluster_web')
        Stop-And-Delete-PgsService
        Remove-BrokenProgramInstall
        Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path ${env:ProgramData} 'ProcessGuard') -Recurse -Force -ErrorAction SilentlyContinue
        $installerLog = Join-Path $LogsRoot 'installer.log'
        Remove-Item -LiteralPath $installerLog -Force -ErrorAction SilentlyContinue
        $installArgs = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR=""$InstallDir"" /TASKS=installservice /LOG=""$installerLog"""
        $setup = Start-Process -FilePath $SetupExe -ArgumentList $installArgs -Wait -PassThru -WindowStyle Hidden
        Assert-True ($setup.ExitCode -eq 0) "installer failed with exit code $($setup.ExitCode)"
        foreach ($path in @(
            (Join-Path $InstallDir 'pgs_service.exe'),
            (Join-Path $InstallDir 'pgs_bless.exe'),
            (Join-Path $InstallDir 'pgs_admin_qt.exe'),
            (Join-Path $InstallDir 'pgs_admin_web.exe'),
            (Join-Path $InstallDir 'pgs_cluster_web.exe'),
            (Join-Path $InstallDir 'modules\modules.allow'),
            (Join-Path $InstallDir 'modules\sched\pgs_sched_module.dll'),
            (Join-Path $InstallDir 'modules\health\pgs_health_module.dll'),
            (Join-Path $InstallDir 'modules\profile\pgs_profile_module.dll'),
            (Join-Path $InstallDir 'modules\report\pgs_report_module.dll'),
            (Join-Path $InstallDir 'modules\ppl\pgs_ppl_module.dll'),
            (Join-Path $InstallDir 'modules\ppl\Sirius.sys')
        )) {
            Assert-Path $path
        }
        $installedStatus = Invoke-Logged -FilePath (Join-Path $InstallDir 'pgs_service.exe') -Arguments @('status')
        Assert-True ($installedStatus.Text -match 'Running|StartPending|Stopped') "installed service status unexpected: $($installedStatus.Text)"
        if ($installedStatus.Text -match 'Stopped') {
            Invoke-Logged -FilePath (Join-Path $InstallDir 'pgs_service.exe') -Arguments @('start') | Out-Null
        }
        $installedToken = Get-InitialToken -Path (Join-Path ${env:ProgramData} 'ProcessGuard\state\pgs_initial_token.txt')
        Wait-PgsReady -BlessExe (Join-Path $InstallDir 'pgs_bless.exe') -Port 12345 -Token $installedToken
        $installedPing = Invoke-PgsOk -BlessExe (Join-Path $InstallDir 'pgs_bless.exe') -Port 12345 -Token $installedToken -CommandArgs @('ping')
        Assert-True ($installedPing -match '^OK pong') "installed service ping failed: $installedPing"

        $uninstaller = Get-ChildItem -LiteralPath $InstallDir -Filter 'unins*.exe' | Select-Object -First 1
        Assert-True ($null -ne $uninstaller) 'installer did not create uninstaller'
        $uninstall = Start-Process -FilePath $uninstaller.FullName -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') -Wait -PassThru -WindowStyle Hidden
        Assert-True ($uninstall.ExitCode -eq 0) "uninstaller failed with exit code $($uninstall.ExitCode)"
        Start-Sleep -Seconds 2
        $sc = & sc.exe query PGS 2>&1
        Assert-True (($LASTEXITCODE -ne 0) -or (($sc | Out-String) -match 'does not exist|1060')) 'PGS service still exists after uninstall'
        Assert-True (-not (Test-Path -LiteralPath $InstallDir)) "install dir still exists after uninstall: $InstallDir"
        Write-Host '[acceptance] installer install/uninstall ok'
    }

    if ($RunWinApp) {
        Write-Step 'WindowsApps verification helper'
        Invoke-Logged -FilePath 'pwsh' -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path (Get-Location) 'tools\verify_winapp.ps1'), '-Here', $PortableRelease) | Out-Null
        Write-Host '[acceptance] WindowsApps helper ok'
    }

    Write-Step 'Final cleanup'
    Stop-ByName @('pgs_service', 'pgs_bless', 'pgs_admin_web', 'pgs_cluster_web', 'pgs_admin_qt', 'smoke_worker')
    Stop-And-Delete-PgsService
    Remove-BrokenProgramInstall
    Write-Host 'ACCEPTANCE_OK'
}
finally {
    if ($guardPid) {
        Stop-Process -Id $guardPid -Force -ErrorAction SilentlyContinue
    }
    Stop-ProcessSafe $clusterProc
    Stop-ProcessSafe $webProc
    Stop-ProcessSafe $qtProc
    Stop-ProcessSafe $portableProc
    Stop-ProcessSafe $serviceProc
    Stop-ByName @('smoke_worker')
}
