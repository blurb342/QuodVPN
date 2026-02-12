<#
.SYNOPSIS
    Connects securely to Quod Financial VPN.

.DESCRIPTION
    PowerShell script to manage Cisco VPN connections.
    
    Update 5.29 (2026-02-12):
    - Auto-Update: Now uses GitHub API to detect updates by commit SHA.
      No manual version bumping required - any commit triggers update.
    - Auto-Update: Shows latest commit message and date when update available.

    Update 5.28 (2026-02-12):
    - Security: Force change update URL to public GIT

    Update 5.27 (2026-02-12):
    - Security: OTP secret now stored as SecureString with BSTR cleanup,
        matching the protection level of the VPN password.
    - Security: Credential payload uses char[] with explicit Array.Clear
        zeroing instead of immutable .NET strings.
    - Security: Auto-updater now verifies download integrity (size,
        structure, and SHA256 hash when published by remote script).
    - Security: TLS protocol setting no longer replaces existing protocols.
    - Robustness: Fixed potential stdout deadlock by reading asynchronously
        before WaitForExit in all process interactions.
    - Robustness: Connection step now uses a fresh ProcessStartInfo instead
        of reusing the query-step object.
    - Robustness: OTP generation errors are now surfaced to the user
        instead of silently injecting an invalid code.
    - Robustness: Test-QuodNetwork retries now bypass cache via -Force
        so DNS is actually re-queried on each attempt.
    - Robustness: Added parameter validation for VPN timeout values.
    - Code Quality: Extracted duplicated VPN address selection into
        Invoke-VpnAddressSelection helper function.
    - Code Quality: Normalized mixed tab/space indentation throughout.
    - UX: OTP screen validates secret upfront and uses fixed-width
        output to eliminate flicker.

    Update 5.26 (2026-02-11):
    - UX: Quality indicator now shows immediately on startup if already
        connected to Quod network (no manual test required).
    - UX: Quality check runs automatically after VPN connects, so menu
        displays quality indicator without needing to press 'T'.

    Update 5.25 (2026-02-09):
    - UX: Update check now shows immediate "Checking for updates..." feedback
        and has a 5-second timeout to prevent blank screen hangs.
    - UX: Status messages shown for update result (up to date/skipped).
    - Reliability: Added network stabilization delay (1.5s) after VPN connects
        to allow DNS/routing to initialize before menu refresh.
    - Reliability: Menu now retries Quod network detection (up to 3x 500ms)
        when VPN shows connected but network not yet detected.

    (See git history for older changelog entries)

.NOTES
    Original Author: Medan Gabbay
    Updated: 2026-02-12
#>
param (
    [string]$VpnName,
    [string]$VpnUsername,
    [securestring]$VpnPassword,
    [string]$LogDirectory,
    [int]$MaxLogSizeMB,
    [string]$CiscoVpnCliPath,
    [string]$CiscoVpnUiPath,
    [string[]]$QuodDnsSuffixes,
    [securestring]$OtpSecret,
    [string]$VpnProfile,
    [string[]]$VpnAddresses,
    [ValidateRange(1000, 120000)][int]$VpnQueryTimeoutMs = 10000,
    [ValidateRange(1000, 120000)][int]$VpnConnectTimeoutMs = 25000
)

# =====================
# CONSTANTS & VERSION
# =====================
# --- VERSION CONTROL ---
$SCRIPT_VERSION = "5.29"
$VERSION_DATE   = "12FEB26"

# High-level notes for the current version (shown in Help screen)
$script:VERSION_NOTES = @"
- Auto-Update: Git-native updates via GitHub API (no manual version bumping).
- Auto-Update: Shows commit message and date when update is available.
"@

$QUOD_SETTINGS_FILENAME = "settings.xml"
$QUOD_SECURE_SETTINGS_FILENAME = "secure_settings.dat"
$QUOD_LOG_FILENAME = "VPNConnectionLog.txt"
$QUOD_LOG_ARCHIVE_PREFIX = "VPNConnectionLog_"
$QUOD_LOGS_DIRNAME = "Logs"

# --- UPDATE CONFIGURATION ---
$UPDATE_SOURCE_URL = "https://raw.githubusercontent.com/blurb342/QuodVPN/main/Connect-QuodVPN.ps1"
$UPDATE_API_URL    = "https://api.github.com/repos/blurb342/QuodVPN/contents/Connect-QuodVPN.ps1"
$UPDATE_COMMITS_URL = "https://api.github.com/repos/blurb342/QuodVPN/commits?path=Connect-QuodVPN.ps1&per_page=1"

# Defaults
if (-not $MaxLogSizeMB) { $MaxLogSizeMB = 5 }

# Dynamic Program Files detection to support non-C: drives or 32-bit systems
$progFiles = if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} } else { $env:ProgramFiles }
if (-not $CiscoVpnCliPath) { $CiscoVpnCliPath = Join-Path $progFiles "Cisco\Cisco Secure Client\vpncli.exe" }
if (-not $CiscoVpnUiPath) { $CiscoVpnUiPath = Join-Path $progFiles "Cisco\Cisco Secure Client\UI\csc_ui.exe" }

#region GLOBAL INITIALIZATION

# --- PATH RESOLUTION LOGIC ---
if ($PSScriptRoot) {
    # Standard PowerShell Script execution
    $scriptRoot = $PSScriptRoot
    $scriptPath = $PSCommandPath
    $isExe = $false
}
else {
    # Fallback: Compiled EXE or older PowerShell host
    try {
        $currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
        $scriptPath = $currentProcess.MainModule.FileName
        $scriptRoot = [System.IO.Path]::GetDirectoryName($scriptPath)
        $isExe = ($scriptPath.EndsWith(".exe", [StringComparison]::OrdinalIgnoreCase))
    }
    catch {
        # Ultimate fallback (rare)
        $scriptRoot = $PWD.Path
        $scriptPath = Join-Path $scriptRoot "Connect-QuodVPN.ps1"
        $isExe = $false
    }
}

$script:SettingsFilePath = Join-Path $scriptRoot $QUOD_SETTINGS_FILENAME
$script:SecureSettingsFilePath = Join-Path $scriptRoot $QUOD_SECURE_SETTINGS_FILENAME

if (-not $LogDirectory) {
    $script:LogDirectory = Join-Path $scriptRoot $QUOD_LOGS_DIRNAME
} else {
    $script:LogDirectory = $LogDirectory
}
if (-not (Test-Path $script:LogDirectory)) {
    New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
}

$script:LogFilePath = Join-Path $script:LogDirectory $QUOD_LOG_FILENAME
$script:MaxLogSizeBytes = $MaxLogSizeMB * 1MB

# Track the most recent Warning/Error log for user-facing feedback
$script:LastUserLogMessage   = $null
$script:LastUserLogType      = $null
$script:LastUserLogTimestamp = $null

function Write-Log {
    param(
        [string]$Message,
        [string]$LogType = "Information"
    )
    try {
        if ((Test-Path $script:LogFilePath) -and ((Get-Item $script:LogFilePath -ErrorAction Stop).Length -gt $script:MaxLogSizeBytes)) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            Rename-Item -Path $script:LogFilePath -NewName ("$QUOD_LOG_ARCHIVE_PREFIX$timestamp.txt") -Force
        }
    } catch {
        # Silently continue if log file check fails
    }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$LogType] - $Message"
    try {
        $entry | Out-File -FilePath $script:LogFilePath -Append -Encoding utf8
    } catch {
        Write-Host "[LOGFAIL] $entry"
    }
    # Cache most recent Warning/Error for main menu display
    if ($LogType -eq "Warning" -or $LogType -eq "Error") {
        $script:LastUserLogMessage   = $Message
        $script:LastUserLogType      = $LogType
        $script:LastUserLogTimestamp = Get-Date
    }
    switch ($LogType) {
        "Information" { Write-Verbose $entry }
        "Warning"     { <# Warnings displayed in Errors/Warnings section #> }
        "Error"       { <# Errors displayed in Errors/Warnings section #> }
        default       { Write-Host  $entry }
    }
}

function Initialize-ProtectedData {
    if (-not ("System.Security.Cryptography.ProtectedData" -as [type])) {
        Add-Type -AssemblyName System.Security
    }
}

function New-DesktopShortcut {
    try {
        $wshShell = New-Object -ComObject WScript.Shell
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $shortcutFile = Join-Path $desktopPath "Quod VPN.lnk"
        $shortcut = $wshShell.CreateShortcut($shortcutFile)

        if ($isExe) {
            # Direct link to EXE
            $shortcut.TargetPath = $scriptPath
            $shortcut.WorkingDirectory = $scriptRoot
        } else {
            # Powershell Wrapper to bypass ExecutionPolicy
            $shortcut.TargetPath = "powershell.exe"
            $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
            $shortcut.WorkingDirectory = $scriptRoot
            # Optional: Attempt to set icon to powershell's icon or a generic system icon
            $shortcut.IconLocation = "powershell.exe,0" 
        }

        $shortcut.HotKey = "CTRL+ALT+V"
        $shortcut.Description = "Connect to Quod Financial VPN"
        $shortcut.Save()

        Write-Host "Shortcut created successfully on Desktop!" -ForegroundColor Green
        Write-Host "HotKey assigned: Ctrl + Alt + V" -ForegroundColor Green
        Start-Sleep -Seconds 2
    } catch {
        Write-Log "Failed to create shortcut: $_" -LogType "Error"
        Write-Host "Error creating shortcut. See logs." -ForegroundColor Red
        Start-Sleep -Seconds 2
    }
}

function Get-GitBlobSha {
    <#
    .SYNOPSIS
        Calculates the Git blob SHA1 hash for a file (same algorithm Git uses).
    #>
    param([string]$FilePath)
    
    # Git blob format: "blob <size>\0<content>"
    $content = [System.IO.File]::ReadAllBytes($FilePath)
    $header = [System.Text.Encoding]::UTF8.GetBytes("blob $($content.Length)`0")
    $fullBlob = $header + $content
    
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    $hashBytes = $sha1.ComputeHash($fullBlob)
    $sha1.Dispose()
    
    return ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ''
}

function Test-ScriptUpdate {
    if (-not $UPDATE_SOURCE_URL -or -not $UPDATE_API_URL) { return }

    # Show immediate feedback - user sees this before any network call
    Write-Host "Checking for updates... " -ForegroundColor Gray -NoNewline
    Write-Log "Checking for updates via GitHub API..."

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        
        # 1. Get local file's git blob SHA
        $localScriptPath = $PSCommandPath
        if (-not $localScriptPath) { $localScriptPath = $MyInvocation.MyCommand.Definition }
        if ([string]::IsNullOrWhiteSpace($localScriptPath) -or -not (Test-Path $localScriptPath)) {
            Write-Host "skipped (cannot determine local script path)." -ForegroundColor DarkGray
            return
        }
        $localBlobSha = Get-GitBlobSha -FilePath $localScriptPath
        
        # 2. Query GitHub API for remote file's blob SHA
        $apiResponse = Invoke-RestMethod -Uri $UPDATE_API_URL -UseBasicParsing -TimeoutSec 5 `
            -Headers @{ "Accept" = "application/vnd.github.v3+json"; "User-Agent" = "QuodVPN-Updater" }
        $remoteBlobSha = $apiResponse.sha
        
        # 3. Compare blob SHAs - if different, update is available
        if ($localBlobSha -eq $remoteBlobSha) {
            Write-Host "up to date." -ForegroundColor Green
            Write-Log "Script is up to date (SHA: $($localBlobSha.Substring(0,7)))"
            return
        }
        
        # 4. Fetch latest commit info to show what changed
        $commitMessage = ""
        $commitDate = ""
        $remoteVersion = "unknown"
        try {
            $commitInfo = Invoke-RestMethod -Uri $UPDATE_COMMITS_URL -UseBasicParsing -TimeoutSec 3 `
                -Headers @{ "Accept" = "application/vnd.github.v3+json"; "User-Agent" = "QuodVPN-Updater" }
            if ($commitInfo -and $commitInfo.Count -gt 0) {
                $latestCommit = $commitInfo[0]
                $commitMessage = $latestCommit.commit.message -split "`n" | Select-Object -First 1
                $commitDate = ([datetime]$latestCommit.commit.committer.date).ToString("yyyy-MM-dd HH:mm")
            }
        } catch {
            Write-Log "Could not fetch commit details: $_" -LogType "Warning"
        }
        
        # 5. Download the new script to extract version number for display
        $rnd = Get-Random
        $tempFile = Join-Path $env:TEMP "Connect-QuodVPN_Update_$rnd.ps1"
        Invoke-WebRequest -Uri $UPDATE_SOURCE_URL -OutFile $tempFile -UseBasicParsing -TimeoutSec 5
        
        if (-not (Test-Path $tempFile)) {
            Write-Host "skipped (download failed)." -ForegroundColor Red
            return
        }
        
        # Extract version from downloaded file for display
        $contentArr = Get-Content -Path $tempFile -TotalCount 150
        $contentStr = $contentArr -join "`n"
        if ($contentStr -match '\$SCRIPT_VERSION\s*=\s*[''\"](\d+(\.\d+)+)[''\"]') {
            $remoteVersion = $matches[1]
        }
        
        # Integrity check: verify the download is a valid PowerShell script
        $downloadedSize = (Get-Item $tempFile).Length
        $fullContent = Get-Content -Path $tempFile -Raw
        if ($downloadedSize -lt 1024 -or $fullContent -notmatch 'function\s+') {
            Write-Host "skipped (download appears corrupt)." -ForegroundColor Red
            Write-Log "Update integrity check failed: file too small or missing expected content." -LogType "Warning"
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            return
        }
        
        Write-Host "update available!" -ForegroundColor Yellow
        Clear-Host
        Write-Host "--- UPDATE AVAILABLE ---" -ForegroundColor Cyan
        Write-Host "Remote Version : $remoteVersion" -ForegroundColor Yellow
        Write-Host "Current Version: $SCRIPT_VERSION" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Latest Commit:" -ForegroundColor Cyan
        if ($commitDate) { Write-Host "  Date   : $commitDate" -ForegroundColor Gray }
        if ($commitMessage) { Write-Host "  Message: $commitMessage" -ForegroundColor White }
        Write-Host ""
        Write-Host "Local SHA : $($localBlobSha.Substring(0,12))..." -ForegroundColor DarkGray
        Write-Host "Remote SHA: $($remoteBlobSha.Substring(0,12))..." -ForegroundColor DarkGray
        
        [Console]::Out.Flush()
        $choice = Read-Host "`nDo you want to update now? (Y/N)"
        
        if ($choice -eq "Y") {
            Write-Log "Initializing update sequence via Robust Batch..."
            
            # Use $PSCommandPath first (Most reliable), fall back to MyInvocation
            $rawPath = $PSCommandPath
            if (-not $rawPath) { $rawPath = $MyInvocation.MyCommand.Definition }
            
            # Sanitize quotes just in case
            if ($rawPath -match '^".*"$') { $rawPath = $rawPath.Trim('"') }
            
            # SAFETY GUARD 1: Check if path is empty
            if ([string]::IsNullOrWhiteSpace($rawPath)) {
                Write-Log "CRITICAL: Update Aborted. Could not determine script path." -LogType "Error"
                return
            }
            # SAFETY GUARD 2: Check extension
            if (-not $rawPath.EndsWith(".ps1")) {
                Write-Log "CRITICAL: Update Aborted. Target is not a .ps1 file: $rawPath" -LogType "Error"
                return
            }
            # SAFETY GUARD 3: Check if Directory
            if ((Get-Item $rawPath).PSIsContainer) {
                Write-Log "CRITICAL: Update Aborted. Target is a DIRECTORY: $rawPath" -LogType "Error"
                return
            }
            
            $batPath = Join-Path $env:TEMP "VPN_Update.bat"
            $logPath = Join-Path $env:TEMP "VPN_Update_Log.txt"
            
            # --- BATCH FILE ---
            $batContent = @" 
@echo off
echo Starting Update Sequence > "$logPath"
timeout /t 1 > NUL

:WAIT_LOCK
echo Attempting delete of file... >> "$logPath"
if exist "$rawPath" del "$rawPath" /q
if exist "$rawPath" (
    echo File still locked, waiting... >> "$logPath"
    timeout /t 1 > NUL
    goto WAIT_LOCK
)

echo File deleted. Moving new version... >> "$logPath"
move /y "$tempFile" "$rawPath"

echo Relaunching PowerShell... >> "$logPath"
start "" powershell -ExecutionPolicy Bypass -File "$rawPath"
del "%~f0"
"@
            Set-Content -Path $batPath -Value $batContent -Encoding Ascii
            Start-Process -FilePath $batPath 
            exit 
        } else {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "skipped (timeout or network error)." -ForegroundColor DarkGray
        Write-Log "Update check failed: $_" -LogType "Warning"
    }
}

<#
.SYNOPSIS
    Checks if the machine is currently connected to the Corporate Network.
#>
function Test-QuodNetwork {
    param([switch]$Force)
    try {
        $now = Get-Date
        $cacheWindowSeconds = 10

        # Lightweight cache so we don't hit DNS APIs on every refresh
        if (-not $Force -and $script:LastQuodNetworkCheckedAt -and $null -ne $script:LastQuodNetworkStatus) {
            if (($now - $script:LastQuodNetworkCheckedAt).TotalSeconds -lt $cacheWindowSeconds) {
                return $script:LastQuodNetworkStatus
            }
        }

        $searchList = (Get-DnsClientGlobalSetting).SuffixSearchList
        $interfaceList = (Get-DnsClient).ConnectionSpecificSuffix | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $allSuffixes = @($searchList) + @($interfaceList)

        foreach ($suffix in $script:QuodDnsSuffixes) {
            if ($allSuffixes -contains $suffix) {
                $script:LastQuodNetworkStatus = $true
                $script:LastQuodNetworkCheckedAt = $now
                return $true
            }
        }

        $script:LastQuodNetworkStatus = $false
        $script:LastQuodNetworkCheckedAt = $now
    } catch {
        Write-Log "Warning: Network detection failed: $_" -LogType "Warning"
    }
    return $false
}

<#
.SYNOPSIS
    Gets the current VPN CLI connection status (Synchronous).
    Uses fast-path adapter check to avoid slow vpncli calls when disconnected.
#>
function Get-VpnCliConnectionStatus {
    try {
        if (-not (Test-Path $script:CiscoVpnCliPath)) {
            return "Error: VPNCLI missing"
        }

        $now = Get-Date

        # Cache when disconnected (10s), shorter for connected/unknown (5s).
        # 10s balances UI responsiveness against vpncli call overhead; the cache
        # is also explicitly cleared on connect/disconnect actions.
        $cacheWindowSeconds = if ($script:LastVpnCliStateCached -eq "Disconnected") { 10 } else { 5 }

        if ($script:LastVpnCliStateCached -and $script:LastVpnCliStateCheckedAt) {
            if (($now - $script:LastVpnCliStateCheckedAt).TotalSeconds -lt $cacheWindowSeconds) {
                return $script:LastVpnCliStateCached
            }
        }

        # --- FAST PATH: no Cisco adapter up => disconnected ---
        $adapterUp = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Status -eq 'Up' -and
                $_.InterfaceDescription -match 'Cisco AnyConnect'
            }

        if (-not $adapterUp) {
            $script:LastVpnCliStateCached     = "Disconnected"
            $script:LastVpnCliStateCheckedAt = $now
            return "Disconnected"
        }

        # --- SLOW PATH: adapter is up, confirm via vpncli ---
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $script:CiscoVpnCliPath
        $processInfo.Arguments = "state"
        $processInfo.RedirectStandardOutput = $true
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true

        $process = [System.Diagnostics.Process]::Start($processInfo)

        # Read stdout before WaitForExit to prevent deadlock when the
        # output buffer fills (process blocks on write until buffer is drained).
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()

        if (-not $process.WaitForExit(8000)) {
            try { $process.Kill() } catch {}
            Write-Log "vpncli state timed out after 8000ms" -LogType "Warning"
            return "Unknown"
        }

        $stdout = $stdoutTask.GetAwaiter().GetResult()

        $state = "Unknown"
        if ($stdout -match 'state:\s*Connected') {
            $state = "Connected"
        }
        elseif ($stdout -match 'state:\s*Disconnected' -or $stdout -match 'Ready to connect') {
            $state = "Disconnected"
        }

        $script:LastVpnCliStateCached     = $state
        $script:LastVpnCliStateCheckedAt = $now
        return $state
    }
    catch {
        Write-Log "Failed to determine VPN CLI state: $_" -LogType "Error"
        return "Unknown"
    }
}
#endregion

#region CONNECTIVITY METRICS

function Get-VpnConnectionQuality {
    [CmdletBinding()]
    param(
        [string]$TargetHost,
        [int]$PingCount = 3,
        [int]$TcpTestCount = 3
    )

    $result = [PSCustomObject]@{
        TargetHost       = $null
        AverageLatencyMs = $null
        Quality          = "Unknown"
        Method           = $null
    }

    # Build list of candidate hosts
    $hostsToTry = @()
    if ($TargetHost) {
        $hostsToTry += $TargetHost
    }
    else {
        if ($script:LastVpnAddress) {
            $hostsToTry += $script:LastVpnAddress
        }
        if ($script:VpnAddresses -and $script:VpnAddresses.Count -gt 0) {
            $hostsToTry += $script:VpnAddresses
        }
        if ($hostsToTry.Count -eq 0) {
            $hostsToTry += '8.8.8.8'
        }
    }

    foreach ($candidateHost in $hostsToTry) {
        # Parse hostname and port from address (e.g., "host.com:8443")
        $hostname = $candidateHost
        $port = 443  # Default port for TCP fallback
        if ($candidateHost -match '^([^:]+):(\d+)$') {
            $hostname = $matches[1].Trim()
            $port = [int]$matches[2]
        }
        elseif ($candidateHost -match '^([^:]+)$') {
            $hostname = $matches[1].Trim()
        }

        # Track the hostname for result output
        if (-not $result.TargetHost) {
            $result.TargetHost = $hostname
        }

        $avg = $null

        # --- METHOD 1: Try ICMP ping first (preferred, faster) ---
        try {
            $pings = Test-Connection -ComputerName $hostname -Count $PingCount -ErrorAction Stop
            if ($pings) {
                $sample = $pings | Select-Object -First 1
                $propNames = $sample.PSObject.Properties.Name

                $latencyProperty = $null
                if ($propNames -contains 'ResponseTime') {
                    $latencyProperty = 'ResponseTime'
                }
                elseif ($propNames -contains 'Latency') {
                    $latencyProperty = 'Latency'
                }

                if ($latencyProperty) {
                    $measurement = $pings | Measure-Object -Property $latencyProperty -Average -ErrorAction Stop
                    $avg = $measurement.Average
                    $result.Method = 'ICMP'
                }
            }
        }
        catch {
            # ICMP failed - this is expected if ping is blocked
        }

        # --- METHOD 2: TCP port connection fallback ---
        if ($null -eq $avg) {
            try {
                $latencies = @()
                for ($i = 0; $i -lt $TcpTestCount; $i++) {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    
                    # Use BeginConnect with WaitOne for proper timeout (2 seconds)
                    $asyncResult = $tcpClient.BeginConnect($hostname, $port, $null, $null)
                    $completed = $asyncResult.AsyncWaitHandle.WaitOne(2000, $false)
                    
                    $stopwatch.Stop()
                    
                    if ($completed) {
                        try {
                            $tcpClient.EndConnect($asyncResult)
                            if ($tcpClient.Connected) {
                                $latencies += $stopwatch.ElapsedMilliseconds
                            }
                        }
                        catch {
                            # Connection failed (refused, etc.)
                        }
                    }
                    
                    try { $tcpClient.Close() } catch {}
                    
                    # Small delay between attempts
                    if ($i -lt ($TcpTestCount - 1)) {
                        Start-Sleep -Milliseconds 100
                    }
                }
                
                if ($latencies.Count -gt 0) {
                    $avg = ($latencies | Measure-Object -Average).Average
                    $result.Method = 'TCP'
                }
            }
            catch {
                Write-Log "TCP connectivity test failed for ${hostname}:${port}: $_" -LogType 'Warning'
            }
        }

        # If we got a measurement, calculate quality and return
        if ($null -ne $avg) {
            $avg = [math]::Round($avg, 0)
            $result.TargetHost = $hostname
            $result.AverageLatencyMs = $avg

            # Map average latency to quality label
            # TCP latency thresholds are slightly higher than ICMP (TCP includes handshake overhead)
            $excellent = if ($result.Method -eq 'TCP') { 60 } else { 40 }
            $good = if ($result.Method -eq 'TCP') { 120 } else { 80 }
            $poor = if ($result.Method -eq 'TCP') { 200 } else { 150 }

            if ($avg -le $excellent) {
                $result.Quality = 'Excellent'
            }
            elseif ($avg -le $good) {
                $result.Quality = 'Good'
            }
            elseif ($avg -le $poor) {
                $result.Quality = 'Poor'
            }
            else {
                $result.Quality = 'Bad'
            }

            return $result
        }
    }

    # If we reach here, all methods failed
    $result.Quality = 'Unknown'
    return $result
}

#endregion

#region SETTINGS MANAGEMENT

function Save-Settings {
    [CmdletBinding()]
    param()
    try {
        Initialize-ProtectedData

        $xml = New-Object -TypeName System.Xml.XmlDocument
        $root = $xml.CreateElement("settings")
        $xml.AppendChild($root) | Out-Null

        # FIX: Added "$script:" prefix to all variables to ensure we save the
        # values modified in the Setup Menu, not empty defaults.
        $settingsData = @{
            VpnName         = $script:VpnName
            VpnUsername     = $script:VpnUsername
            LogDirectory    = $script:LogDirectory
            MaxLogSizeMB    = $script:MaxLogSizeMB
            CiscoVpnCliPath = $script:CiscoVpnCliPath
            CiscoVpnUiPath  = $script:CiscoVpnUiPath
            VpnProfile      = $script:VpnProfile
            LastVpnAddress  = $script:LastVpnAddress
            
            # Handle arrays safely
            QuodDnsSuffixes = if ($script:QuodDnsSuffixes) { ($script:QuodDnsSuffixes -join ",") } else { "" }
            VpnAddresses    = if ($script:VpnAddresses) { ($script:VpnAddresses -join ",") } else { "" }
        }

        foreach ($key in $settingsData.Keys) {
            $value = $settingsData[$key]
            # Create element only if Key is valid
            if (-not [string]::IsNullOrWhiteSpace($key)) {
                $elem = $xml.CreateElement($key)
                $elem.InnerText = [string]$value
                $root.AppendChild($elem) | Out-Null
            }
        }
        $xml.Save($script:SettingsFilePath)

        # --- SECURE DATA HANDLING ---
        $secureData = @{}
        
        # 1. Handle Password (with secure BSTR cleanup)
        $bstrPtr = [IntPtr]::Zero
        if ($script:VpnPassword) {
            $bstrPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:VpnPassword)
            try {
                $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrPtr)
                $secureData.VpnPassword = $plainPassword
            } finally {
                if ($bstrPtr -ne [IntPtr]::Zero) {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrPtr)
                }
            }
        }
        
        # 2. Handle OTP Secret (with secure BSTR cleanup)
        $otpBstrPtr = [IntPtr]::Zero
        if ($script:OtpSecret) {
            $otpBstrPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:OtpSecret)
            try {
                $plainOtpSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($otpBstrPtr)
                $secureData.OtpSecret = $plainOtpSecret
            } finally {
                if ($otpBstrPtr -ne [IntPtr]::Zero) {
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($otpBstrPtr)
                }
            }
        }

        # 3. Save to Disk (Atomic Write)
        if ($secureData.Count -gt 0) {
            $secureDataJson = ConvertTo-Json -InputObject $secureData
            $protectedData = [System.Security.Cryptography.ProtectedData]::Protect(
                [System.Text.Encoding]::UTF8.GetBytes($secureDataJson), 
                $null,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            )
            $base64ProtectedData = [Convert]::ToBase64String($protectedData)
            
            # Use WriteAllText to prevent 0-byte corruption
            [System.IO.File]::WriteAllText($script:SecureSettingsFilePath, $base64ProtectedData)
            
            Write-Log "Secure settings saved."
        } else {
            if (Test-Path $script:SecureSettingsFilePath) { 
                Remove-Item $script:SecureSettingsFilePath
                Write-Log "Secure file cleared (no data provided)." 
            }
        }
        Write-Log "Settings saved successfully."
    } catch {
        Write-Log "Error saving settings: $_" -LogType "Error"
        throw
    } finally {
        # Security Cleanup - note: string interning means this doesn't truly clear memory,
        # but combined with ZeroFreeBSTR above, we minimize exposure
        if ($plainPassword) { $plainPassword = $null }
        if ($plainOtpSecret) { $plainOtpSecret = $null }
        [System.GC]::Collect()
    }
}

function Get-Settings {
    [CmdletBinding()]
    param()
    try {
        Initialize-ProtectedData

        if (Test-Path $script:SettingsFilePath) {
            [xml]$xml = Get-Content $script:SettingsFilePath -ErrorAction Stop
            
            # Basic Strings
            $script:VpnName         = $xml.settings.VpnName
            $script:VpnUsername     = $xml.settings.VpnUsername
            $script:LogDirectory    = $xml.settings.LogDirectory
            $script:MaxLogSizeMB    = if ($xml.settings.MaxLogSizeMB) { [int]$xml.settings.MaxLogSizeMB } else { 5 }
            $script:CiscoVpnCliPath = $xml.settings.CiscoVpnCliPath
            $script:CiscoVpnUiPath  = $xml.settings.CiscoVpnUiPath
            $script:VpnProfile      = $xml.settings.VpnProfile
            $script:LastVpnAddress  = $xml.settings.LastVpnAddress

            # Arrays (Safe Splitting)
            if (-not [string]::IsNullOrWhiteSpace($xml.settings.QuodDnsSuffixes)) {
                $script:QuodDnsSuffixes = $xml.settings.QuodDnsSuffixes.Split(',')
            } else { $script:QuodDnsSuffixes = @() }

            if (-not [string]::IsNullOrWhiteSpace($xml.settings.VpnAddresses)) {
                $script:VpnAddresses = $xml.settings.VpnAddresses.Split(',')
            } else { $script:VpnAddresses = @() }

            Write-Log "Settings loaded successfully."
        } else {
            Write-Log "Settings file not found. Using defaults." -LogType "Warning"
            $script:VpnAddresses = @()
            $script:QuodDnsSuffixes = @()
            $script:VpnProfile = ""
            $script:LogDirectory = Join-Path $scriptRoot "Logs"
        }

        # Load secure settings (Existing logic is fine, kept for brevity)
        if (Test-Path $script:SecureSettingsFilePath) {
            $base64ProtectedData = Get-Content -Path $script:SecureSettingsFilePath -Raw
            if ([string]::IsNullOrWhiteSpace($base64ProtectedData)) {
                $script:VpnPassword = $null; $script:OtpSecret = $null; return
            }
            $protectedData = [Convert]::FromBase64String($base64ProtectedData)
            try {
                $secureDataJson = [System.Text.Encoding]::UTF8.GetString(
                    [System.Security.Cryptography.ProtectedData]::Unprotect(
                        $protectedData, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                    )
                )
                $secureData = ConvertFrom-Json -InputObject $secureDataJson
                if ($secureData.VpnPassword) {
                    $script:VpnPassword = ConvertTo-SecureString $secureData.VpnPassword -AsPlainText -Force
                }
                if ($secureData.OtpSecret) {
                    $script:OtpSecret = ConvertTo-SecureString $secureData.OtpSecret -AsPlainText -Force
                }
            }
            catch {
                Write-Log "Error: Failed to unprotect secure data." -LogType "Warning"
                $script:VpnPassword = $null; $script:OtpSecret = $null
            }
        }
    } catch {
        Write-Log "Error loading settings: $_" -LogType "Error"
    }
}
#endregion

#region MENUS

function Show-MainMenu {
    Clear-Host
    Write-Host "   ____                  _  __      _______  _   _ " -ForegroundColor Cyan
    Write-Host "  / __ \                | | \ \    / /  __ \| \ | |" -ForegroundColor Cyan
    Write-Host " | |  | |_   _  ___   __| |  \ \  / /| |__) |  \| |" -ForegroundColor Cyan
    Write-Host " | |  | | | | |/ _ \ / _`  |   \ \/ / |  ___/| . \` |" -ForegroundColor Cyan
    Write-Host " | |__| | |_| | (_) | (_| |    \  /  | |    | |\  |" -ForegroundColor Cyan
    Write-Host "  \___\_\\__,_|\___/ \__,_|     \/   |_|    |_| \_|" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "        Quod Financial - VPN Connector" -ForegroundColor White
    Write-Host "             Version $SCRIPT_VERSION | $VERSION_DATE" -ForegroundColor DarkGray
    Write-Host ""

    $boxWidth = 50
    $boxTitle = 'Networking / Connectivity'
    $boxLine = ('=' * $boxWidth)
    Write-Host $boxLine -ForegroundColor Cyan
    $titlePad = [Math]::Floor(($boxWidth - $boxTitle.Length) / 2)
    Write-Host ((' ' * $titlePad) + $boxTitle) -ForegroundColor Cyan
    Write-Host $boxLine -ForegroundColor Cyan

    # 1. VPN CLI connection state (Synchronous)
    $vpnState = Get-VpnCliConnectionStatus

    # 2. Quod network presence (Helper Function)
    #    When VPN just connected, allow brief stabilization for DNS/routing
    $connectedToQuod = Test-QuodNetwork
    if ($vpnState -eq 'Connected' -and -not $connectedToQuod) {
        # Network may still be initializing - retry with brief delays
        # Use -Force to bypass cache so retries actually re-query DNS
        for ($retry = 1; $retry -le 3; $retry++) {
            Start-Sleep -Milliseconds 500
            $connectedToQuod = Test-QuodNetwork -Force
            if ($connectedToQuod) { break }
        }
    }

    # 3. Connectivity quality when either VPN is connected or Quod network is detected
    #    (with basic caching so we don't ping on every single refresh)
    $qualityInfo = $null
    $qualityColor = 'Yellow'
    $qualityScenario = 'None'
    if ($vpnState -eq 'Connected') {
        $qualityScenario = 'VpnConnected'
    }
    elseif ($connectedToQuod) {
        $qualityScenario = 'OnNetNoVpn'
    }

    $now = Get-Date
    $qualityCacheWindowSeconds = 15

    if ($qualityScenario -ne 'None') {
        # Only use cached quality info - never block menu to fetch new quality data
        # User can press "T" to run manual quality test
        if ($script:LastQualityInfo -and $script:LastQualityScenario -and $script:LastQualityCheckedAt) {
            if ($script:LastQualityScenario -eq $qualityScenario -and (($now - $script:LastQualityCheckedAt).TotalSeconds -lt $qualityCacheWindowSeconds)) {
                $qualityInfo = $script:LastQualityInfo
            }
        }
    }

    if ($qualityInfo) {
        switch ($qualityInfo.Quality) {
            'Excellent' { $qualityColor = 'Green' }
            'Good'      { $qualityColor = 'Green' }
            'Poor'      { $qualityColor = 'Yellow' }
            'Bad'       { $qualityColor = 'Red' }
            default     { $qualityColor = 'Yellow' }
        }
    }

    # 4. Quod header line with inline quality when Quod network is detected
    if ($connectedToQuod) {
        if ($qualityInfo) {
            $qualityLabel = $qualityInfo.Quality
            $quodText = "| Quod Financial Network: Detected [$qualityLabel]".PadRight($boxWidth - 1) + '|'
            Write-Host $quodText -ForegroundColor $qualityColor
        } else {
            Write-Host ("| Quod Financial Network: Detected".PadRight($boxWidth - 1) + '|') -ForegroundColor Green
        }
    } else {
        Write-Host ("| Quod Financial Network: Not Detected".PadRight($boxWidth - 1) + '|') -ForegroundColor Red
    }

    # 5. VPN connection status line
    $statusColor = 'Yellow'
    if ($vpnState -eq "Connected") { $statusColor = 'Green' }
    elseif ($vpnState -eq "Disconnected") { $statusColor = 'Red' }
    elseif ($vpnState -like "Error:*") { $statusColor = 'Red' }

    $vpnText = "| VPN Connection Status : $vpnState".PadRight($boxWidth - 1) + '|'
    Write-Host $vpnText -ForegroundColor $statusColor

    # Highlight if the VPN appears to have dropped since the last refresh
    if ($script:LastVpnCliState -and $script:LastVpnCliState -eq "Connected" -and $vpnState -ne "Connected") {
        Write-Host "| WARNING: VPN connection appears to have dropped since last check.".PadRight($boxWidth - 1) + '|' -ForegroundColor Red
        Write-Log "VPN connection state changed from Connected to $vpnState" -LogType "Warning"
    }

    # When connected, show a simple quality estimate based on ping latency
    if ($vpnState -eq "Connected" -and $qualityInfo) {
        $methodSuffix = if ($qualityInfo.Method) { " via $($qualityInfo.Method)" } else { "" }
        $latencyText = if ($null -ne $qualityInfo.AverageLatencyMs) { " ($($qualityInfo.AverageLatencyMs)ms$methodSuffix)" } else { "" }
        $qualityLine = "| VPN Link Quality    : $($qualityInfo.Quality)$latencyText".PadRight($boxWidth - 1) + '|'
        Write-Host $qualityLine -ForegroundColor $qualityColor
    }

    # 6. Recent warning/error feedback (e.g., unreachable VPN gateway)
    #    (captured here, rendered *below* the box for more space)
    $recentAlert = $null
    if ($script:LastUserLogMessage -and $script:LastUserLogTimestamp) {
        $ageSeconds = (New-TimeSpan -Start $script:LastUserLogTimestamp -End (Get-Date)).TotalSeconds
        # Only show very recent issues (last 5 minutes) to avoid stale noise
        if ($ageSeconds -lt 300) {
            $alertColor = if ($script:LastUserLogType -eq "Error") { 'Red' } else { 'Yellow' }
            $prefix = if ($script:LastUserLogType -eq "Error") { "Recent ERROR" } else { "Recent WARNING" }
            $msg = "${prefix}: $($script:LastUserLogMessage)"
            # Allow a longer message but cap extreme length
            if ($msg.Length -gt 200) {
                $msg = $msg.Substring(0, 197) + "..."
            }
            $recentAlert = [PSCustomObject]@{
                Message = $msg
                Color   = $alertColor
            }
        }
    }

    $script:LastVpnCliState = $vpnState
    Write-Host $boxLine -ForegroundColor Cyan
    Write-Host "" 

    # --- Errors / Warnings (below connectivity box for more room) ---
    if ($recentAlert) {
        Write-Host "Errors / Warnings" -ForegroundColor Yellow
        Write-Host "-----------------" -ForegroundColor DarkYellow
        Write-Host $recentAlert.Message -ForegroundColor $recentAlert.Color
        Write-Host ""
    }

    # --- Quod Financial App Section ---
    $quodProcs = Get-Process | Where-Object { $_.ProcessName -ieq 'QuodFrontEnd' }
    # Keep this header colour constant regardless of warnings above
    Write-Host "Quod Financial Applications Running:" -ForegroundColor Gray
    if ($quodProcs -and $quodProcs.Count -gt 0) {
        $idx = 1
        foreach ($proc in $quodProcs) {
            $label = "k$idx"
            $desc = "[PID $($proc.Id)] $($proc.ProcessName) - $($proc.MainWindowTitle)"
            Write-Host ("  " + $label + ": " + $desc) -ForegroundColor Green
            $idx++
        }
        Write-Host "  K: Kill All QuodFrontEnd" -ForegroundColor Red
    } else {
        Write-Host "  None" -ForegroundColor DarkGray
    }
    Write-Host "" 

    $settingsAvailable = $true
    if (-not $script:VpnUsername -or -not $script:VpnPassword -or -not $script:VpnProfile -or -not $script:CiscoVpnCliPath) {
        $settingsAvailable = $false
    }

    if ($settingsAvailable) {
        Write-Host "1. Connect / Disconnect VPN"
    } else {
        Write-Host "1. Connect VPN Disabled - run Setup first" -ForegroundColor DarkGray
    }
    Write-Host "2. Setup Options"
    Write-Host "O. Show Current OTP"
    Write-Host "H. README / Help"

    $lastVpnDisplay = if ($script:LastVpnAddress) { $script:LastVpnAddress } else { "[None]" }
    Write-Host ("Q. Quick Connect ({0})" -f $lastVpnDisplay) -ForegroundColor Cyan
    Write-Host "T. Connectivity Quality Test" -ForegroundColor White
    Write-Host "L. Open Logs" -ForegroundColor White
    Write-Host "9. Exit"
    Write-Host "" 

    $userInput = Read-Host "Enter your choice (or press Enter to refresh)"

    # Handle Quod App kill options
    if ($quodProcs -and $quodProcs.Count -gt 0) {
        if ($userInput -match "^k([0-9]+)$") {
            $killIdx = [int]$matches[1] - 1
            if ($killIdx -ge 0 -and $killIdx -lt $quodProcs.Count) {
                $procToKill = $quodProcs[$killIdx]
                try {
                    Write-Log "User requested kill of QuodFrontEnd index $($killIdx + 1): PID=$($procToKill.Id), Name=$($procToKill.ProcessName), Title='$($procToKill.MainWindowTitle)'"
                    Stop-Process -Id $procToKill.Id -Force -ErrorAction Stop
                    Start-Sleep -Milliseconds 300
                    if (Get-Process -Id $procToKill.Id -ErrorAction SilentlyContinue) {
                        Write-Log "WARNING: Process still running after Stop-Process: PID=$($procToKill.Id)" -LogType "Warning"
                        Write-Host "Warning: process appears to still be running (PID $($procToKill.Id))." -ForegroundColor Yellow
                    } else {
                        Write-Log "Successfully terminated QuodFrontEnd process PID=$($procToKill.Id)."
                    }
                } catch {
                    Write-Log "Failed to kill QuodFrontEnd process PID=$($procToKill.Id): $_" -LogType "Error"
                    Write-Host "Error killing process PID $($procToKill.Id). See VPN log for details." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                }
            }
        } elseif ($userInput -ieq "K") {
            foreach ($proc in $quodProcs) {
                try {
                    Write-Log "User requested kill-all of QuodFrontEnd: PID=$($proc.Id), Name=$($proc.ProcessName), Title='$($proc.MainWindowTitle)'"
                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    Start-Sleep -Milliseconds 100
                    if (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue) {
                        Write-Log "WARNING: Process still running after Stop-Process (kill-all): PID=$($proc.Id)" -LogType "Warning"
                    } else {
                        Write-Log "Successfully terminated QuodFrontEnd (kill-all) PID=$($proc.Id)."
                    }
                } catch {
                    Write-Log "Failed to kill QuodFrontEnd (kill-all) PID=$($proc.Id): $_" -LogType "Error"
                }
            }
        }
    }
    return $userInput
}

function Format-ListDisplay {
    param([string]$Label, [string[]]$Items)
    if ($Items -and $Items.Count -gt 0) {
        $firstLine = "{0} : [{1}" -f $Label, ($Items[0])
        $restLines = ($Items[1..($Items.Length-1)] | ForEach-Object {"`n" + (' ' * ($Label.Length + 4)) + $_}) -join ""
        return "$firstLine$restLines]"
    } else { return "{0} : [None]" -f $Label }
}

# --- IMPROVED CONSOLE PROMPTS ---
function Read-EditField {
    param([string]$Prompt, [string]$CurrentValue, [switch]$IsSecure)
    
    Write-Host "`n--- EDIT: $Prompt ---" -ForegroundColor Cyan
    if ($IsSecure) {
        Write-Host "Current: [Secure Value Hidden]" -ForegroundColor DarkGray
        $val = Read-Host "Enter new value (or press Enter to keep current)" -AsSecureString
        if (-not $val) { return $CurrentValue } 
        return $val
    } else {
        Write-Host "Current: $CurrentValue" -ForegroundColor Yellow
        $val = Read-Host "Enter new value (or press Enter to keep current)"
        if ([string]::IsNullOrWhiteSpace($val)) { 
            Write-Host "Value unchanged." -ForegroundColor DarkGray
            Start-Sleep -Milliseconds 500
            return $CurrentValue 
        }
        return $val.Trim()
    }
}

# --- NEW LIST EDITOR MENU (Parses CSV into manageable items) ---
function Read-EditList {
    param([string]$Name, [string[]]$CurrentItems)
    
    # Convert to ArrayList for easy adding/removing
    $list = New-Object System.Collections.ArrayList
    if ($CurrentItems) { $list.AddRange($CurrentItems) }

    while ($true) {
        Clear-Host
        Write-Host "--- EDIT LIST: $Name ---" -ForegroundColor Cyan
        
        # Display Indexed List
        if ($list.Count -gt 0) {
            for ($i = 0; $i -lt $list.Count; $i++) {
                Write-Host ("  {0}. {1}" -f ($i + 1), $list[$i]) -ForegroundColor White
            }
        } else {
            Write-Host "  [List is Empty]" -ForegroundColor DarkGray
        }

        Write-Host "`nActions:" -ForegroundColor Yellow
        Write-Host "[#] Edit Item (Enter number)"
        Write-Host "[A] Add New Item"
        Write-Host "[D] Delete Item"
        Write-Host "[S] Save & Return"
        Write-Host "[C] Cancel (Discard Changes)"
        Write-Host ""
        
        $userChoice = Read-Host "Choose action"
        
        switch -Regex ($userChoice) {
            "^A$" { # ADD
                $newItem = Read-Host "Enter new item"
                if (-not [string]::IsNullOrWhiteSpace($newItem)) {
                    [void]$list.Add($newItem.Trim())
                }
            }
            "^D$" { # DELETE
                $delIdx = Read-Host "Enter number to delete"
                if ($delIdx -match '^\d+$') {
                    $idx = [int]$delIdx - 1
                    if ($idx -ge 0 -and $idx -lt $list.Count) {
                        $removed = $list[$idx]
                        $list.RemoveAt($idx)
                        Write-Host "Removed: $removed" -ForegroundColor Red
                        Start-Sleep -Milliseconds 800
                    }
                }
            }
            "^\d+$" { # EDIT EXISTING
                $idx = [int]$userChoice - 1
                if ($idx -ge 0 -and $idx -lt $list.Count) {
                    Write-Host "Editing: $($list[$idx])" -ForegroundColor Cyan
                    $editVal = Read-Host "Enter new value (or Enter to keep)"
                    if (-not [string]::IsNullOrWhiteSpace($editVal)) {
                        $list[$idx] = $editVal.Trim()
                    }
                }
            }
            "^S$" { # SAVE
                return $list.ToArray()
            }
            "^C$" { # CANCEL
                return $CurrentItems
            }
        }
    }
}
# ------------------------------

function Show-SetupMenu {
    $exitSetupMenu = $false
    while (-not $exitSetupMenu) {
        Clear-Host
        Write-Host "VPN Setup Menu" -ForegroundColor Yellow
        Write-Host "--------------"
        Write-Host ("1. Set VPN Username            : [{0}]" -f ($script:VpnUsername))
        Write-Host ("2. Set VPN Password            : [{0}]" -f $(if ($script:VpnPassword) {"Stored Securely"} else {"Not Set"}))
        Write-Host ("3. Set VPN Profile             : [{0}]" -f ($script:VpnProfile))
        Write-Host ("4. Set OTP Secret              : [{0}]" -f $(if ($script:OtpSecret) {"Stored Securely"} else {"Not Set"}))
        Write-Host ("5. Set Cisco VPN CLI Path      : [{0}]" -f ($script:CiscoVpnCliPath))
        Write-Host ("6. Set Cisco VPN UI Path       : [{0}]" -f ($script:CiscoVpnUiPath))
        Write-Host (Format-ListDisplay -Label "7. Set VPN Addresses           " -Items $script:VpnAddresses)
        Write-Host (Format-ListDisplay -Label "8. Set DNS Suffixes            " -Items $script:QuodDnsSuffixes)
        Write-Host "9. Save and Return"
        Write-Host "0. Exit without Saving"
        Write-Host "D. Create Desktop Shortcut (Ctrl+Alt+V)"

        $setupChoice = Read-Host "Choose option"

        if ($setupChoice -eq "9") {
            Save-Settings
            return
        }
        elseif ($setupChoice -eq "0") {
            Write-Host "Exiting setup without saving changes." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            return
        }

        switch ($setupChoice) {
            # Updated to use Console Safe Prompts
            "1" { $script:VpnUsername = Read-EditField -Prompt "VPN Username" -CurrentValue $script:VpnUsername }
            "2" { $script:VpnPassword = Read-EditField -Prompt "VPN Password" -CurrentValue "" -IsSecure }
            "3" { $script:VpnProfile = Read-EditField -Prompt "VPN Profile" -CurrentValue $script:VpnProfile }
            "4" {
                $s = Read-Host "Enter OTP Secret (Base32)"
                if (-not [string]::IsNullOrWhiteSpace($s)) {
                    $script:OtpSecret = ConvertTo-SecureString ($s.Trim().ToUpper()) -AsPlainText -Force
                    $s = $null
                }
            }
            "5" { $script:CiscoVpnCliPath = Read-EditField -Prompt "Cisco VPN CLI Path" -CurrentValue $script:CiscoVpnCliPath }
            "6" { $script:CiscoVpnUiPath = Read-EditField -Prompt "Cisco VPN UI Path" -CurrentValue $script:CiscoVpnUiPath }
            "7" { $script:VpnAddresses = Read-EditList -Name "VPN Addresses" -CurrentItems $script:VpnAddresses }
            "8" { $script:QuodDnsSuffixes = Read-EditList -Name "DNS Suffixes" -CurrentItems $script:QuodDnsSuffixes }
            "D" { New-DesktopShortcut }
        }
    }
}

function Show-HelpScreen {
    Clear-Host
    $hColor = "Cyan"      # Headers
    $tColor = "Gray"      # Text
    $vColor = "Yellow"    # Variables/Options
    $wColor = "Green"     # Highlights

    Write-Host "================================================================" -ForegroundColor $hColor
    Write-Host "QUOD FINANCIAL VPN CONNECTOR - USER MANUAL" -ForegroundColor White
    Write-Host "================================================================" -ForegroundColor $hColor
    Write-Host ""

    # --- SECTION 1: OVERVIEW ---
    Write-Host "1. OVERVIEW & CAPABILITIES" -ForegroundColor $hColor
    Write-Host "--------------------------" -ForegroundColor $tColor
    Write-Host "This tool is a secure wrapper for the Cisco Secure Client (AnyConnect)." -ForegroundColor $tColor
    Write-Host "It automates the login process, handles Multi-Factor Authentication (OTP)," -ForegroundColor $tColor
    Write-Host "and manages connection states without requiring manual data entry every time." -ForegroundColor $tColor
    Write-Host ""

    # --- SECTION 2: SECURITY ---
    Write-Host "2. SECURITY ARCHITECTURE" -ForegroundColor $hColor
    Write-Host "------------------------" -ForegroundColor $tColor
    Write-Host "A. Credential Storage (DPAPI):" -ForegroundColor $wColor
    Write-Host "   Your VPN Password and OTP Secret are NOT stored in plain text." -ForegroundColor $tColor
    Write-Host "   They are encrypted using Windows Data Protection API (DPAPI) with" -ForegroundColor $tColor
    Write-Host "   'CurrentUser' scope. Only your specific Windows User Account on this" -ForegroundColor $tColor
    Write-Host "   specific PC can decrypt them. Copied files cannot be decrypted elsewhere." -ForegroundColor $tColor
    Write-Host ""
    Write-Host "B. Injection Security (RAM-Only):" -ForegroundColor $wColor
    Write-Host "   Credentials are never written to a temporary file during connection." -ForegroundColor $tColor
    Write-Host "   They are injected directly into the Cisco process memory pipe (StandardInput)," -ForegroundColor $tColor
    Write-Host "   preventing credential leakage to disk recovery tools." -ForegroundColor $tColor
    Write-Host ""

    # --- SECTION 3: OTP (MFA) ---
    Write-Host "3. OTP & MULTI-FACTOR AUTH" -ForegroundColor $hColor
    Write-Host "--------------------------" -ForegroundColor $tColor
    Write-Host "The script includes a built-in TOTP (Time-based One-Time Password) generator." -ForegroundColor $tColor
    Write-Host "If you provide your Base32 Secret Key in the Setup menu:" -ForegroundColor $tColor
    Write-Host "   - The script automatically generates the 6-digit code during login." -ForegroundColor $tColor
    Write-Host "   - It appends it to your password seamlessly." -ForegroundColor $tColor
    Write-Host "   - You can view the live code via menu option [O] to use on other devices." -ForegroundColor $tColor
    Write-Host ""

    # --- SECTION 4: MENU FUNCTIONS ---
    Write-Host "4. MENU OPTIONS EXPLAINED" -ForegroundColor $hColor
    Write-Host "-------------------------" -ForegroundColor $tColor
    Write-Host "[1] Connect / Disconnect" -ForegroundColor $vColor
    Write-Host "    Smart toggle. If connected, it cleanly disconnects. If disconnected," -ForegroundColor $tColor
    Write-Host "    it prompts you to select a gateway from your saved list." -ForegroundColor $tColor
    Write-Host ""
    Write-Host "[2] Setup Options" -ForegroundColor $vColor
    Write-Host "    Configure your Username, Password, VPN Profile, and Gateway Addresses." -ForegroundColor $tColor
    Write-Host "    Use this menu if your password changes or you need to add a new server." -ForegroundColor $tColor
    Write-Host "    From this menu you can also press 'D' to create the desktop" -ForegroundColor $tColor
    Write-Host "    shortcut with the Ctrl+Alt+V hotkey." -ForegroundColor $tColor
    Write-Host "" 
    Write-Host "[O] Show Current OTP" -ForegroundColor $vColor
    Write-Host "    Opens a live TOTP viewer that refreshes every few hundred ms so you" -ForegroundColor $tColor
    Write-Host "    can read the current 6-digit MFA code without unlocking another app." -ForegroundColor $tColor
    Write-Host "" 
    Write-Host "[H] README / Help" -ForegroundColor $vColor
    Write-Host "    Shows this detailed help screen, including security model, menu" -ForegroundColor $tColor
    Write-Host "    behaviour, connectivity tests, updater and version notes." -ForegroundColor $tColor
    Write-Host "" 
    Write-Host "[Q] Quick Connect" -ForegroundColor $vColor
    Write-Host "    Bypasses the server list and connects immediately to the last used" -ForegroundColor $tColor
    Write-Host "    gateway. The main menu shows 'Quick Connect (VPN name)' where the" -ForegroundColor $tColor
    Write-Host "    VPN name is your last endpoint, or [None] if you haven't connected yet." -ForegroundColor $tColor
    Write-Host "" 
    Write-Host "[T] Connectivity Quality Test" -ForegroundColor $vColor
    Write-Host "    Runs an on-demand quality test against all configured VPN endpoints" -ForegroundColor $tColor
    Write-Host "    and reports a color-coded quality rating plus average latency in ms." -ForegroundColor $tColor
    Write-Host "" 
    Write-Host "[L] Open Logs" -ForegroundColor $vColor
    Write-Host "    Opens the current VPN log file in your default text viewer so you" -ForegroundColor $tColor
    Write-Host "    can quickly inspect connection history and any error messages." -ForegroundColor $tColor
    Write-Host ""
    # Desktop shortcut creation now lives in the Setup menu (option 2 -> 'D').

    # --- SECTION 5: CONFIGURATION ---
    Write-Host "5. CONFIGURATION DETAILS" -ForegroundColor $hColor
    Write-Host "------------------------" -ForegroundColor $tColor
    Write-Host "VPN Profile:" -ForegroundColor $vColor
    Write-Host "   This must match the 'Group' name configured on the Cisco Firewall" -ForegroundColor $tColor
    Write-Host "   (e.g., 'SaaSVPN_RD_Profile'). If this is wrong, login will fail." -ForegroundColor $tColor
    Write-Host ""
    Write-Host "VPN Addresses:" -ForegroundColor $vColor
    Write-Host "   A comma-separated list of your entry points (e.g., london.quod:8443)." -ForegroundColor $tColor
    Write-Host "   You can manage this list using the List Editor in the Setup menu." -ForegroundColor $tColor
    Write-Host ""

    # --- SECTION 6: AUTO-UPDATER ---
    Write-Host "6. AUTO-UPDATER ENGINE" -ForegroundColor $hColor
    Write-Host "----------------------" -ForegroundColor $tColor
    Write-Host "The application features a robust, self-healing update engine." -ForegroundColor $tColor
    Write-Host ""
    Write-Host "How it works:" -ForegroundColor $wColor
    Write-Host "1. Check:" -ForegroundColor $tColor
    Write-Host "   On launch, it checks a central OneDrive/SharePoint URL for a newer version." -ForegroundColor $tColor
    Write-Host "2. Safe Download:" -ForegroundColor $tColor
    Write-Host "   Downloads the update to a randomized temporary file to avoid file locks." -ForegroundColor $tColor
    Write-Host "3. Execution Lock Bypass:" -ForegroundColor $tColor
    Write-Host "   Since a running program cannot overwrite itself, the script spawns a" -ForegroundColor $tColor
    Write-Host "   separate background 'Batch' process." -ForegroundColor $tColor
    Write-Host "4. The Swap:" -ForegroundColor $tColor
    Write-Host "   The script closes itself. The background process waits for the lock to release," -ForegroundColor $tColor
    Write-Host "   swaps the old file for the new one, and relaunches the application." -ForegroundColor $tColor
    Write-Host "5. Compatibility:" -ForegroundColor $tColor
    Write-Host "   Works for both the raw PowerShell script (.ps1) and compiled executable (.exe)." -ForegroundColor $tColor
    Write-Host ""
    
    # --- SECTION 7: RELEASE NOTES ---
    if (-not [string]::IsNullOrWhiteSpace($script:VERSION_NOTES)) {
        Write-Host "7. CURRENT VERSION NOTES ($script:SCRIPT_VERSION)" -ForegroundColor $hColor
        Write-Host "----------------------------" -ForegroundColor $tColor
        Write-Host $script:VERSION_NOTES -ForegroundColor $wColor
        Write-Host ""
    }

    Write-Host "Logs are located at: $script:LogDirectory" -ForegroundColor DarkGray
    Write-Host ""
    Read-Host "Press Enter to return to the Main Menu"
}

#endregion

#region VPN FUNCTIONS

function ConvertFrom-Base32 {
    param([string]$Base32String)
    $Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $Base32String = $Base32String.TrimEnd('=').ToUpper()
    $bits = 0; $bitBuffer = 0; $output = New-Object System.Collections.Generic.List[byte]
    foreach ($char in $Base32String.ToCharArray()) {
        $val = $Base32Alphabet.IndexOf($char)
        if ($val -lt 0) { throw "Invalid Base32 character: $char" }
        $bitBuffer = ($bitBuffer -shl 5) -bor $val
        $bits += 5
        if ($bits -ge 8) { $bits -= 8; $output.Add(($bitBuffer -shr $bits) -band 0xFF) }
    }
    return ,$output.ToArray()
}

function New-Otp {
    param(
        [Parameter(Mandatory=$false)]$Secret
    )
    if (-not $Secret) { return "" }

    $plainSecret = $null
    $bstrPtr = [IntPtr]::Zero
    try {
        # Accept both SecureString and plain string for backwards compatibility.
        # Use [securestring] accelerator (always available in PS 5.0+) rather than
        # [System.Security.SecureString] which may fail to resolve in some hosts.
        if ($Secret -is [securestring]) {
            $bstrPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
            $plainSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstrPtr)
        } else {
            $plainSecret = [string]$Secret
        }

        $keyBytes = ConvertFrom-Base32 -Base32String $plainSecret
        $timestamp = [Math]::Floor(([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) / 30)
        $counterBytes = [BitConverter]::GetBytes([Int64]$timestamp)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($counterBytes) }
        $hmac = New-Object System.Security.Cryptography.HMACSHA1
        $hmac.Key = $keyBytes
        $hash = $hmac.ComputeHash($counterBytes)
        $offset = $hash[-1] -band 0x0F
        $binaryCode = ((($hash[$offset] -band 0x7F) -shl 24) -bor (($hash[$offset+1] -band 0xFF) -shl 16) -bor (($hash[$offset+2] -band 0xFF) -shl 8) -bor (($hash[$offset+3] -band 0xFF)))
        return ($binaryCode % 1000000).ToString("D6")
    } catch {
        Write-Log "OTP generation failed: $_" -LogType "Error"
        return $null
    } finally {
        if ($bstrPtr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrPtr)
        }
        $plainSecret = $null
    }
}

function Stop-VpnUi {
    try {
        $uiProcesses = Get-Process | Where-Object { $_.Name -like "csc_ui*" }
        if ($uiProcesses) { Stop-Process -Id $uiProcesses.Id -Force -ErrorAction SilentlyContinue }
    } catch { }
}

function Start-VpnUi {
    try {
        if (Test-Path $script:CiscoVpnUiPath) {
            Start-Process -FilePath $script:CiscoVpnUiPath -WindowStyle Minimized
        }
    } catch { }
}

function Disconnect-Vpn {
    [CmdletBinding()]
    param([switch]$WaitForReset)

    try {
        if (-not (Test-Path $script:CiscoVpnCliPath)) {
            Write-Host "CLI not found." -ForegroundColor Red; return
        }
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $script:CiscoVpnCliPath
        $processInfo.Arguments = "disconnect"
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true
        $process = New-Object System.Diagnostics.Process; $process.StartInfo = $processInfo
        $process.Start() | Out-Null; $process.WaitForExit()
        
        # Clear cached VPN status so menu shows fresh state after disconnect
        $script:LastVpnCliStateCached = $null
        $script:LastVpnCliStateCheckedAt = $null
        
        Write-Host "VPN Disconnected." -ForegroundColor Green

        # COOLDOWN LOGIC (Consolidated here)
        if ($WaitForReset) {
             Write-Host "Waiting for VPN Service to fully reset..." -ForegroundColor DarkGray
             $spinner = @('.   ', '..  ', '... ')
             for ($i = 0; $i -lt 5; $i++) { # Wait 5 seconds
                  Write-Host "`rresetting $($spinner[$i % 3])" -NoNewline
                  Start-Sleep -Seconds 1
             }
             Write-Host "`rReady.             " 
        }

    } catch { Write-Host "Error disconnecting." -ForegroundColor Red }
    finally { Start-VpnUi; Start-Sleep -Seconds 1 }
}

function Connect-Vpn {
    param([string]$VpnAddress)

    try {
        # PERFORMANCE: Target specific process instead of listing all (Replaces Stop-VpnUi)
        Get-Process -Name "csc_ui" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        
        # Clear cached VPN status so menu shows fresh state after connection
        $script:LastVpnCliStateCached = $null
        $script:LastVpnCliStateCheckedAt = $null
        
        Write-Log "Starting VPN connection to $VpnAddress."

        # --- 1. PREPARE CREDENTIALS ---
        if ($script:OtpSecret) {
            $otp = New-Otp -Secret $script:OtpSecret
            if ($null -eq $otp) {
                Write-Host "OTP generation failed. Check your OTP secret in Setup." -ForegroundColor Red
                Write-Log "Aborting connection: OTP generation returned null (invalid secret?)." -LogType "Error"
                return $false
            }
            $otp = $otp.Trim()
        } else {
            $otp = (Read-Host "Manual OTP").Trim()
        }

        # Decrypt Password into char[] so we can zero it after use.
        # .NET strings are immutable/interned so char[] gives us explicit cleanup.
        $bstrPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:VpnPassword)
        $passwordChars = $null
        try {
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrPtr)
            $trimmedPw = $plainPassword.Trim()
            $passwordChars = New-Object char[] ($trimmedPw.Length + $otp.Length)
            $trimmedPw.CopyTo(0, $passwordChars, 0, $trimmedPw.Length)
            $otp.CopyTo(0, $passwordChars, $trimmedPw.Length, $otp.Length)
        } finally {
            if ($bstrPtr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrPtr)
            }
            # Clear intermediary string references immediately
            $plainPassword = $null
            $trimmedPw = $null
        }

        # --- 2. GET PROFILE ID (Query Step) ---
        Write-Log "Querying VPN profiles..."
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $script:CiscoVpnCliPath
        $processInfo.Arguments = "-s"
        $processInfo.RedirectStandardInput = $true
        $processInfo.RedirectStandardOutput = $true
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        $process.Start() | Out-Null

        # Query the profiles
        $process.StandardInput.WriteLine("connect $VpnAddress")
        $process.StandardInput.Close()

        # Read stdout asynchronously to prevent deadlock when output buffer fills
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()

        # ANTI-FREEZE: Configurable timeout for profile query
        if (-not $process.WaitForExit($VpnQueryTimeoutMs)) {
            try { $process.Kill() } catch {}
            try { $stdoutTask.GetAwaiter().GetResult() | Out-Null } catch {}
            Write-Log "VPN CLI timed out while querying profiles. This often means the VPN gateway is unreachable or blocked from your current network." -LogType "Warning"
            Write-Host "The VPN gateway did not respond in time. This usually indicates a local network or firewall issue rather than a problem with this script." -ForegroundColor Yellow
            return $false
        }

        $stdout = $stdoutTask.GetAwaiter().GetResult()

        # Parse the output to find the profile index
        $profileLines = $stdout -split "`n" 
        $profileMapping = @{}
        
        foreach ($line in $profileLines) {
            if ($line -match '^\s*(\d+)\)\s+(.+)$') {
                $profileMapping[$matches[2].Trim()] = [int]$matches[1]
            }
        }

        if ($profileMapping.Count -eq 0) {
            Write-Log "Warning: Could not parse profile list. Defaulting to index 1." -LogType "Warning"
            $profileNumber = 1
        }
        else {
            $matchedProfile = $profileMapping.Keys | Where-Object { $_ -like "*$($script:VpnProfile)*" } | Select-Object -First 1
            
            if (-not $matchedProfile) {
                if ($profileMapping.Count -eq 1) {
                    $matchedProfile = $profileMapping.Keys | Select-Object -First 1
                    Write-Log "Profile name mismatch, but only 1 profile available. Using: $matchedProfile" -LogType "Warning"
                } else {
                    Write-Host "No matching VPN profile found for '$($script:VpnProfile)'." -ForegroundColor Red
                    Write-Host "Available profiles: $($profileMapping.Keys -join ', ')" -ForegroundColor Yellow
                    return $false
                }
            }
            $profileNumber = $profileMapping[$matchedProfile]
            Write-Log "Selected Profile: $matchedProfile ($profileNumber)"
        }

        # --- 3. CONNECTION INJECTION (Secure & Buffered) ---
        Write-Log "Injecting credentials via Buffered StandardInput..."

        # Fresh ProcessStartInfo for connection (avoid reusing query-step object)
        $connectProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $connectProcessInfo.FileName = $script:CiscoVpnCliPath
        $connectProcessInfo.Arguments = "-s"
        $connectProcessInfo.RedirectStandardInput = $true
        $connectProcessInfo.RedirectStandardOutput = $true
        $connectProcessInfo.UseShellExecute = $false
        $connectProcessInfo.CreateNoWindow = $true

        $connectProcess = New-Object System.Diagnostics.Process
        $connectProcess.StartInfo = $connectProcessInfo

        $connectProcess.Start() | Out-Null
        Start-Sleep -Seconds 1

        # Write credentials line-by-line to StandardInput, then zero the char[]
        $connectProcess.StandardInput.WriteLine("connect $VpnAddress")
        $connectProcess.StandardInput.WriteLine($profileNumber)
        $connectProcess.StandardInput.WriteLine($script:VpnUsername)
        $connectProcess.StandardInput.Write($passwordChars, 0, $passwordChars.Length)
        $connectProcess.StandardInput.WriteLine()
        $connectProcess.StandardInput.WriteLine("y")
        $connectProcess.StandardInput.Close()

        # SECURITY: Zero the credential char[] immediately after injection
        [Array]::Clear($passwordChars, 0, $passwordChars.Length)
        $passwordChars = $null

        # Read stdout asynchronously to prevent deadlock when output buffer fills
        $connectStdoutTask = $connectProcess.StandardOutput.ReadToEndAsync()

        # ANTI-FREEZE: Configurable timeout for connection handshake
        if (-not $connectProcess.WaitForExit($VpnConnectTimeoutMs)) {
            try { $connectProcess.Kill() } catch {}
            try { $connectStdoutTask.GetAwaiter().GetResult() | Out-Null } catch {}
            Write-Log "VPN CLI timed out during connection attempt. This may indicate the VPN gateway is not reachable from this network." -LogType "Warning"
            Write-Host "Connection timed out. This often points to a network/firewall issue reaching the VPN gateway, not a fault in this script." -ForegroundColor Yellow
            return $false
        }

        $stdout2 = ""
        try { $stdout2 = $connectStdoutTask.GetAwaiter().GetResult() } catch { }

        # --- 4. ANALYZE RESULT ---
        if ($stdout2 -match "Connected" -or $connectProcess.ExitCode -eq 0) {
            Write-Host "Connected successfully." -ForegroundColor Green
            # Allow network stack to stabilize (DNS, routing) before menu refresh
            Write-Host "Waiting for network to stabilize..." -ForegroundColor Gray
            Start-Sleep -Milliseconds 1500
            $script:LastVpnAddress = $VpnAddress
            Save-Settings
            
            # Run quality check for connected VPN so menu shows quality immediately
            Write-Host "Checking connection quality..." -ForegroundColor Gray
            $qualityResult = Get-VpnConnectionQuality -TargetHost $VpnAddress
            if ($qualityResult) {
                $script:LastQualityInfo = $qualityResult
                $script:LastQualityScenario = 'VpnConnected'
                $script:LastQualityCheckedAt = Get-Date
            }
            
            return $true
        } else {
            Write-Host "Connection failed. Check logs." -ForegroundColor Red
            Write-Log "Connect Output: $stdout2" -LogType "Error"
            return $false
        }
    } catch {
        Write-Log "Exception during connect: $_" -LogType "Error"
        return $false
    } finally {
        # Security: Double check cleanup and force GC
        if ($passwordChars) {
            [Array]::Clear($passwordChars, 0, $passwordChars.Length)
            $passwordChars = $null
        }
        if ($plainPassword) { $plainPassword = $null }
        [System.GC]::Collect()
        Start-VpnUi
    }
}

function Show-OtpScreen {
    Clear-Host
    Write-Host "Live OTP Viewer (Press any key to exit)" -ForegroundColor Cyan

    if (-not $script:OtpSecret) {
        Write-Host "No OTP secret configured. Set it in Setup Options." -ForegroundColor Yellow
        Read-Host "Press Enter to return"
        return
    }

    # Verify OTP generation works before entering loop
    $testOtp = New-Otp -Secret $script:OtpSecret
    if ($null -eq $testOtp) {
        Write-Host "OTP generation failed. Your OTP secret may be invalid." -ForegroundColor Red
        Read-Host "Press Enter to return"
        return
    }

    # Drain any leftover keystrokes from the menu's Read-Host so they
    # don't trigger the "press any key to exit" check immediately.
    while ([System.Console]::KeyAvailable) {
        [void][System.Console]::ReadKey($true)
    }

    while ($true) {
        $otp = New-Otp -Secret $script:OtpSecret
        if ($null -eq $otp) { $otp = "ERROR" }
        $epoch = [DateTime]::UtcNow - (Get-Date "1970-01-01Z")
        $seconds = [math]::Floor($epoch.TotalSeconds)
        $remain = 30 - ($seconds % 30)
        # Use fixed-width output to prevent flicker from varying string lengths
        $display = "OTP: {0}  ({1,2}s remaining)" -f $otp, $remain
        Write-Host ("`r$($display.PadRight(40))") -ForegroundColor Green -NoNewline
        if ([System.Console]::KeyAvailable) {
            [void][System.Console]::ReadKey($true)
            Write-Host ""
            return
        }
        Start-Sleep -Milliseconds 200
    }
}

#endregion

function Invoke-VpnAddressSelection {
    if (-not (Test-Path $script:SettingsFilePath)) {
        Write-Host "Please Setup first." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }
    if ($script:VpnAddresses.Count -eq 1) {
        Connect-Vpn -VpnAddress $script:VpnAddresses[0]
    } else {
        $i = 1
        foreach ($a in $script:VpnAddresses) { Write-Host "$i. $a"; $i++ }
        $idx = Read-Host "Select Address"
        if ($idx -match '^\d+$' -and [int]$idx -ge 1 -and [int]$idx -le $script:VpnAddresses.Count) {
            Connect-Vpn -VpnAddress $script:VpnAddresses[[int]$idx - 1]
        } else {
            Write-Host "Invalid selection." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
        }
    }
}

#region SCRIPT ENTRYPOINT
try
{
    Get-Settings 
    
    # Check for update on start
    Test-ScriptUpdate

    # Initial quality check if already connected to Quod network
    # This ensures quality indicator shows on first menu display
    if (Test-QuodNetwork) {
        $targetForQuality = if ($script:LastVpnAddress) { $script:LastVpnAddress } 
                           elseif ($script:VpnAddresses -and $script:VpnAddresses.Count -gt 0) { $script:VpnAddresses[0] }
                           else { $null }
        if ($targetForQuality) {
            Write-Host "Checking connection quality..." -ForegroundColor Gray
            $initialQuality = Get-VpnConnectionQuality -TargetHost $targetForQuality
            if ($initialQuality) {
                $script:LastQualityInfo = $initialQuality
                $vpnState = Get-VpnCliConnectionStatus
                $script:LastQualityScenario = if ($vpnState -eq 'Connected') { 'VpnConnected' } else { 'OnNetNoVpn' }
                $script:LastQualityCheckedAt = Get-Date
            }
        }
    }

    while ($true) {
        $choice = Show-MainMenu
        switch ($choice) {
            "1" {
                if (Test-QuodNetwork) {
                    # Already on Quod network - offer choice to disconnect or reconnect to different endpoint
                    Write-Host ""
                    Write-Host "Already connected to Quod network." -ForegroundColor Green
                    Write-Host "[D] Disconnect VPN" -ForegroundColor Yellow
                    Write-Host "[R] Reconnect to different endpoint" -ForegroundColor Cyan
                    Write-Host "[Enter] Return to menu" -ForegroundColor Gray
                    $subChoice = Read-Host "Choice"
                    if ($subChoice -ieq 'D') {
                        Disconnect-Vpn -WaitForReset
                    } elseif ($subChoice -ieq 'R') {
                        Disconnect-Vpn -WaitForReset
                        Invoke-VpnAddressSelection
                    }
                } else {
                    Invoke-VpnAddressSelection
                }
            }
            "2" { Show-SetupMenu }
            "O" { Show-OtpScreen }
            "H" { Show-HelpScreen }
            "Q" {
                if ($script:LastVpnAddress) {
                    if (Test-QuodNetwork) {
                        # Mirror option 1 behaviour: when Quod network is already
                        # detected, treat Quick Connect as a disconnect-only toggle.
                        Write-Host "Quod network already detected. Disconnecting VPN..." -ForegroundColor Yellow
                        Disconnect-Vpn -WaitForReset
                    }
                    else {
                        Write-Host "Quick connecting to: $($script:LastVpnAddress)" -ForegroundColor Cyan

                        # Proceed with connection (no pre-disconnect here, matching
                        # option 1's behaviour when the network is not already present).
                        $result = Connect-Vpn -VpnAddress $script:LastVpnAddress
                        
                        if (-not $result) {
                            Write-Host "Quick connect failed. Please use option 1 to reset." -ForegroundColor Yellow
                            Start-Sleep -Seconds 3
                        }
                    }
                } else {
                    Write-Host "No previous VPN address saved." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                }
            }
            "T" {
                Clear-Host
                Write-Host "Connectivity Quality Test - All VPN Endpoints" -ForegroundColor Cyan
                Write-Host "--------------------------------------------" -ForegroundColor Cyan
                Write-Host "Tests each VPN address using ICMP ping (preferred) or TCP port" -ForegroundColor DarkGray
                Write-Host "connection (fallback if ICMP is blocked)." -ForegroundColor DarkGray

                # Build ordered, de-duplicated list of VPN targets
                $targets = New-Object System.Collections.Generic.List[string]
                if ($script:LastVpnAddress) { [void]$targets.Add($script:LastVpnAddress) }
                if ($script:VpnAddresses) {
                    foreach ($addr in $script:VpnAddresses) {
                        if (-not [string]::IsNullOrWhiteSpace($addr) -and -not $targets.Contains($addr)) {
                            [void]$targets.Add($addr)
                        }
                    }
                }

                if ($targets.Count -eq 0) {
                    Write-Host "No VPN addresses configured. Use Setup Options to add endpoints." -ForegroundColor Yellow
                    Write-Host ""; Read-Host "Press Enter to return to the Main Menu" | Out-Null
                }
                else {
                    $firstQualityInfo = $null
                    foreach ($addr in $targets) {
                        Write-Host ""
                        Write-Host ("Testing {0}..." -f $addr) -ForegroundColor Cyan

                        $qualityInfo = Get-VpnConnectionQuality -TargetHost $addr
                        
                        # Cache first result for main menu display
                        if (-not $firstQualityInfo) {
                            $firstQualityInfo = $qualityInfo
                        }

                        $qualityColor = 'Yellow'
                        switch ($qualityInfo.Quality) {
                            'Excellent' { $qualityColor = 'Green' }
                            'Good'      { $qualityColor = 'Green' }
                            'Poor'      { $qualityColor = 'Yellow' }
                            'Bad'       { $qualityColor = 'Red' }
                        }

                        if ($null -ne $qualityInfo.AverageLatencyMs) {
                            $methodLabel = if ($qualityInfo.Method) { " via $($qualityInfo.Method)" } else { "" }
                            Write-Host ("Result: {0} (avg {1} ms{2})" -f $qualityInfo.Quality, $qualityInfo.AverageLatencyMs, $methodLabel) -ForegroundColor $qualityColor
                        } else {
                            Write-Host ("Result: {0} (target {1})" -f $qualityInfo.Quality, $qualityInfo.TargetHost) -ForegroundColor $qualityColor
                        }
                    }
                    
                    # Cache results for main menu
                    if ($firstQualityInfo) {
                        $script:LastQualityInfo = $firstQualityInfo
                        $script:LastQualityScenario = if (Test-QuodNetwork) { 'OnNetNoVpn' } else { 'VpnConnected' }
                        $script:LastQualityCheckedAt = Get-Date
                    }

                    Write-Host ""; Read-Host "Press Enter to return to the Main Menu" | Out-Null
                }
            }
            "L" {
                if (Test-Path $script:LogFilePath) {
                    try {
                        Invoke-Item -Path $script:LogFilePath
                    } catch {
                        Write-Host "Unable to open log file: $_" -ForegroundColor Red
                        Start-Sleep -Seconds 2
                    }
                } else {
                    Write-Host "Log file not found at $script:LogFilePath" -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                }
            }
            "9" { exit }
        }
    }
}
catch { Write-Log "Critical Error: $_" -LogType "Error"; Write-Error $_ }
#endregion
