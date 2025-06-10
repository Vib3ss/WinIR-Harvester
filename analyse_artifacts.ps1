<#
.SYNOPSIS
    Forensic artifact extraction pipeline.

.DESCRIPTION
    Parses Prefetch, Amcache, ShimCache, EVTX logs, APT-Hunter output,
    network logs for known malicious domains, scheduled tasks, Avast logs,
    and hunts for critical indicators in APT-Hunter TimeSketch CSV and ShimCache CSV.

.PARAMETER IR
    Path to the folder containing raw IR artifacts.

.PARAMETER Tools
    Path to the folder containing all tooling (PECmd.exe, AmcacheParser.exe, chainsaw, APT-Hunter.exe, etc.).
    Defaults to ".\Tools" under the current working directory if not specified.

.PARAMETER Parsed
    Path to the folder where parsed output will be written.
    Defaults to ".\IR_Parsed" under the current working directory if not specified.

.EXAMPLE
    .\Parse-IR.ps1 -IR "C:\Users\<user>\Desktop\artifacts"
    .\Parse-IR.ps1 -IR "C:\IR_Raw" -Tools "D:\MyTools" -Parsed "D:\IR_Output"
#>

param (
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Path to the IR folder")]
    [ValidateNotNullOrEmpty()]
    [string]$IR,

    [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Path to the tools folder")]
    [string]$Tools,

    [Parameter(Mandatory = $false, Position = 2, HelpMessage = "Path to the parsed-output folder")]
    [string]$Parsed
)

# Resolve the base directory from where the script is run
$BaseDir = (Get-Location).ProviderPath

# Default tools and parsed paths if not provided
if (-not $Tools)  { $Tools  = Join-Path $BaseDir 'Tools' }
if (-not $Parsed) { $Parsed = Join-Path $BaseDir 'IR_Parsed' }

# Create output directories
New-Item -ItemType Directory -Path $Parsed -Force | Out-Null
New-Item -ItemType Directory -Path $Tools  -Force | Out-Null

Write-Host "`n[+] IR source path:     $IR"
Write-Host "[+] Tools folder path:   $Tools"
Write-Host "[+] Parsed output path:  $Parsed`n"

# === 1. Prefetch: parse everything except whitelisted apps ===
$prefetchDir   = Join-Path $IR 'Prefetch'
$prefetchFiles = Get-ChildItem "$prefetchDir\*.pf" -ErrorAction SilentlyContinue

# Define your whitelist of benign executables (lower-case)
$whitelist = @(
    # Windows System Files
    'explorer.exe',
    'svchost.exe',
    'winlogon.exe',
    'csrss.exe',
    'smss.exe',
    'wininit.exe',
    'services.exe',
    'lsass.exe',
    'dwm.exe',
    'taskhost.exe',
    'taskhostw.exe',
    'sihost.exe',
    'winlogon.exe',
    'fontdrvhost.exe',
    'audiodg.exe',
    'conhost.exe',
    'dllhost.exe',
    'rundll32.exe',
    'mmc.exe',
    'msiexec.exe',
    'spoolsv.exe',
    'wmiprvse.exe',
    'searchindexer.exe',
    'searchprotocolhost.exe',
    'searchfilterhost.exe',
    
    # Windows Update & Maintenance
    'wuauclt.exe',
    'trustedinstaller.exe',
    'tiworker.exe',
    'dismhost.exe',
    'compattelrunner.exe',
    'musnotification.exe',
    'usoclient.exe',
    
    # Windows Defender
    'msmpeng.exe',
    'antimalwareservice.exe',
    'nissrv.exe',
    'mpcmdrun.exe',
    'securityhealthsystray.exe',
    'securityhealthservice.exe',
    
    # Common Applications
    'notepad.exe',
    'notepad++.exe',
    'powershell.exe',
    'powershell_ise.exe',
    'cmd.exe',
    'pwsh.exe',
    
    # Web Browsers
    'chrome.exe',
    'firefox.exe',
    'msedge.exe',
    'iexplore.exe',
    'opera.exe',
    
    # Microsoft Office
    'winword.exe',
    'excel.exe',
    'powerpnt.exe',
    'outlook.exe',
    'onenote.exe',
    'teams.exe',
    'skype.exe',
    
    # Media Players
    'wmplayer.exe',
    'vlc.exe',
    'spotify.exe',
    'groove.exe',
    
    # System Utilities
    'regedit.exe',
    'msconfig.exe',
    'taskmgr.exe',
    'control.exe',
    'calc.exe',
    'magnify.exe',
    'osk.exe',
    'narrator.exe',
    'mspaint.exe',
    'snipingtool.exe',
    'snippingtool.exe',
    'winver.exe',
    'msinfo32.exe',
    'dxdiag.exe',
    'perfmon.exe',
    'resmon.exe',
    'eventvwr.exe',
    'devmgmt.exe',
    'compmgmt.exe',
    
    # Windows Store & Apps
    'winstore.app.exe',
    'applicationframehost.exe',
    'runtimebroker.exe',
    'startmenuexperiencehost.exe',
    'shellexperiencehost.exe',
    'cortana.exe',
    'searchui.exe',
    'lockapp.exe',
    
    # Network & Communication
    'ping.exe',
    'ipconfig.exe',
    'netstat.exe',
    'nslookup.exe',
    'telnet.exe',
    'ftp.exe',
    'ssh.exe',
    
    # Development Tools (if applicable)
    'devenv.exe',
    'code.exe',
    'git.exe',
    'node.exe',
    'python.exe',
    'java.exe',
    'javaw.exe'
    
    # Add any additional organization-specific applications here
)

if ($prefetchFiles.Count -gt 0) {
    $outDir = Join-Path $Parsed 'Prefetch'
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null

    foreach ($file in $prefetchFiles) {
        # Extract the executable name (everything before the first hyphen)
        $exeName = ($file.BaseName -split '-')[0].ToLower() + '.exe'

        if ($whitelist -contains $exeName) {
            Write-Host "Skipping whitelisted prefetch: $exeName" -ForegroundColor Yellow
        } else {
            Write-Host "Parsing Prefetch file: $($file.Name)" -ForegroundColor Green
            & (Join-Path $Tools 'PECmd.exe') -f $file.FullName --csv $outDir | Out-Null
        }
    }
} else {
    Write-Host "No Prefetch files found." -ForegroundColor Red
}

# === 2. Amcache Parsing ===
$amcachePath = Join-Path $IR 'Amcache\Amcache.hve'
if (Test-Path $amcachePath) {
    $outDir = Join-Path $Parsed 'Amcache'
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    & (Join-Path $Tools 'AmcacheParser.exe') -f $amcachePath --nl --csv $outDir | Out-Null
    Write-Host "Amcache parsed."
} else {
    Write-Host "Amcache.hve not found."
}

# === 3. ShimCache via Chainsaw ===
$shimOutputDir = Join-Path $Parsed 'Shimcache'
New-Item -ItemType Directory -Path $shimOutputDir -Force | Out-Null

$systemHive   = Join-Path $IR 'Registry\SYSTEM.hiv'
$shimRegex    = Join-Path $Tools 'chainsaw\shimcache_patterns.txt'
$outputCsv    = Join-Path $shimOutputDir 'output.csv'
$chainsawExe  = Join-Path $Tools 'chainsaw\chainsaw.exe'

if (Test-Path $systemHive) {
    # First attempt with tspair and amcache
    $result = & $chainsawExe analyse shimcache $systemHive `
        --regexfile $shimRegex `
        --amcache $amcachePath `
        --tspair `
        --output $outputCsv 2>&1

    if ($result -match 'input\s+is\s+out\s+of\s+range') {
        Write-Host "Input out-of-range error detected. Rerunning without --tspair and --amcache..."
        & $chainsawExe analyse shimcache $systemHive `
            --regexfile $shimRegex `
            --output $outputCsv | Out-Null
    }

    Write-Host "ShimCache analysis complete."
} else {
    Write-Host "SYSTEM hive for ShimCache not found."
}

# === 4. EVTX Log Hunting via Chainsaw ===
$evtxOut = Join-Path $Parsed 'EVTX_Results'
New-Item -ItemType Directory -Path $evtxOut -Force | Out-Null

& (Join-Path $Tools 'chainsaw\chainsaw.exe') hunt `
    (Join-Path $IR 'EventLogs') `
    -s (Join-Path $Tools 'chainsaw\sigma') `
    --mapping (Join-Path $Tools 'chainsaw\mappings\sigma-event-logs-all.yml') `
    -r (Join-Path $Tools 'chainsaw\rules') `
    --csv --output $evtxOut | Out-Null
Write-Host "EVTX Sigma hunting complete."

# === 5. EVTX Parsing via APT-Hunter ===
$aptHunterExe = Join-Path $Tools 'APT-Hunter.exe'
$aptFinalDir  = Join-Path $Parsed 'APT_Hunter'
New-Item -ItemType Directory -Path $aptFinalDir -Force | Out-Null

if (Test-Path $aptHunterExe) {
    & $aptHunterExe -p (Join-Path $IR 'EventLogs') -o 'APT_Hunter' | Out-Null
    Start-Sleep -Seconds 3

    Get-ChildItem -Path $BaseDir -Filter 'APT_Hunter*' -Directory | ForEach-Object {
        $dest = Join-Path $aptFinalDir $_.Name
        Move-Item -Path $_.FullName -Destination $dest -Force
        Write-Host "Moved APT-Hunter output: $_ -> $dest"
    }
} else {
    Write-Host "APT-Hunter.exe not found at $aptHunterExe"
}

# === 6. Search for unexpected domains in network logs ===
$domainDir  = Join-Path $Parsed 'Indicators'
$domainHits = Join-Path $domainDir 'domain_hits.txt'
New-Item -ItemType Directory -Path $domainDir -Force | Out-Null

$networkLogs = @(
    Join-Path $IR 'Network\arp.txt'
    Join-Path $IR 'Network\dns_cache.txt'
    Join-Path $IR 'Network\netstat.txt'
)

# Define your whitelist of expected/benign domains (lower-case)
$domainwhitelist = @(
    # Microsoft Services
    'microsoft.com',
    'microsoftonline.com',
    'live.com',
    'outlook.com',
    'hotmail.com',
    'msn.com',
    'bing.com',
    'office.com',
    'office365.com',
    'sharepoint.com',
    'onedrive.com',
    'skype.com',
    'teams.microsoft.com',
    'windowsupdate.microsoft.com',
    'update.microsoft.com',
    'download.microsoft.com',
    'azureedge.net',
    'azure.com',
    'windows.com',
    'xbox.com',
    'msftconnecttest.com',
    'msftncsi.com',
    'visualstudio.com',
    'github.com',
    'githubusercontent.com',
    
    # Google Services
    'google.com',
    'googleapis.com',
    'googleusercontent.com',
    'gstatic.com',
    'gmail.com',
    'youtube.com',
    'ytimg.com',
    'googlevideo.com',
    'googletagmanager.com',
    'googleadservices.com',
    'googlesyndication.com',
    'doubleclick.net',
    'ggpht.com',
    'android.com',
    'chrome.com',
    'chromium.org',
    'googlecode.com',
    'google-analytics.com',
    'googleapi.com',
    'appspot.com',
    'blogspot.com',
    
    # Amazon/AWS Services
    'amazon.com',
    'amazonaws.com',
    'awsstatic.com',
    'cloudfront.net',
    'ssl-images-amazon.com',
    'amazonwebservices.com',
    'amazontrust.com',
    'amazonses.com',
    
    # Content Delivery Networks (CDNs)
    'cloudflare.com',
    'cdnjs.cloudflare.com',
    'jsdelivr.net',
    'unpkg.com',
    'bootstrapcdn.com',
    'maxcdn.com',
    'stackpath.com',
    'keycdn.com',
    'fastly.com',
    'akamai.com',
    'akamaized.net',
    'edgecastcdn.net',
    'rackcdn.com',
    
    # Social Media Platforms
    'facebook.com',
    'fbcdn.net',
    'instagram.com',
    'twitter.com',
    'twimg.com',
    'linkedin.com',
    'licdn.com',
    'pinterest.com',
    'reddit.com',
    'redditmedia.com',
    'snapchat.com',
    'tiktok.com',
    'whatsapp.com',
    'telegram.org',
    'discord.com',
    'discordapp.com',
    
    # Media & Streaming
    'netflix.com',
    'nflxvideo.net',
    'nflximg.net',
    'spotify.com',
    'scdn.co',
    'hulu.com',
    'disney.com',
    'disneyplus.com',
    'primevideo.com',
    'twitch.tv',
    'ttvnw.net',
    'vimeo.com',
    'dailymotion.com',
    'soundcloud.com',
    
    # News & Information
    'cnn.com',
    'bbc.com',
    'reuters.com',
    'wikipedia.org',
    'wikimedia.org',
    'stackoverflow.com',
    'stackexchange.com',
    'medium.com',
    'quora.com',
    
    # Security & Antivirus Vendors
    'symantec.com',
    'norton.com',
    'mcafee.com',
    'kaspersky.com',
    'bitdefender.com',
    'avast.com',
    'avg.com',
    'eset.com',
    'trendmicro.com',
    'sophos.com',
    'malwarebytes.com',
    'virustotal.com',
    'clamav.net',
    'f-secure.com',
    
    # Certificate Authorities & Trust Services
    'digicert.com',
    'verisign.com',
    'symantec.com',
    'godaddy.com',
    'letsencrypt.org',
    'comodo.com',
    'globalsign.com',
    'entrust.com',
    'sectigo.com',
    'thawte.com',
    'geotrust.com',
    'rapidssl.com',
    'ssls.com',
    
    # Common Web Services & Tools
    'jquery.com',
    'jquery.org',
    'ajax.googleapis.com',
    'fonts.googleapis.com',
    'gravatar.com',
    'wordpress.com',
    'wp.com',
    'wix.com',
    'squarespace.com',
    'shopify.com',
    'paypal.com',
    'stripe.com',
    'mailchimp.com',
    'constantcontact.com',
    'salesforce.com',
    'hubspot.com',
    
    # Cloud Storage & File Sharing
    'dropbox.com',
    'box.com',
    'icloud.com',
    'drive.google.com',
    'docs.google.com',
    'wetransfer.com',
    'sendspace.com',
    'mediafire.com',
    '4shared.com',
    
    # Time & Network Services
    'time.nist.gov',
    'pool.ntp.org',
    'time.windows.com',
    'time.google.com',
    'time.cloudflare.com',
    'ntp.org',
    'timeanddate.com',
    
    # DNS Services
    '1.1.1.1',
    '8.8.8.8',
    '8.8.4.4',
    'quad9.net',
    'opendns.com',
    'dns.google',
    'cloudflare-dns.com',
    
    # Operating System Updates
    'apple.com',
    'icloud.com',
    'mzstatic.com',
    'ubuntu.com',
    'canonical.com',
    'redhat.com',
    'centos.org',
    'debian.org',
    'fedoraproject.org',
    
    # Development & Package Managers
    'npmjs.org',
    'npmjs.com',
    'yarnpkg.com',
    'nuget.org',
    'pypi.org',
    'rubygems.org',
    'packagist.org',
    'maven.org',
    'gradle.org',
    'docker.com',
    'docker.io',
    'hub.docker.com',
    
    # Enterprise/Corporate Common
    'corp.local',
    'internal',
    'intranet',
    'local',
    'domain.local',
    'ad.local',
    'company.local',
    
    # Banking & Financial (Common ones - adjust for your region)
    'bankofamerica.com',
    'chase.com',
    'wellsfargo.com',
    'citibank.com',
    'usbank.com',
    'capitalone.com',
    'americanexpress.com',
    'visa.com',
    'mastercard.com',
    
    # Government & Public Services (adjust for your country)
    'gov',
    'irs.gov',
    'usps.com',
    'usps.gov',
    'fedex.com',
    'ups.com',
    'dhl.com',
    
    # Educational Institutions
    'edu',
    'ac.uk',
    'mit.edu',
    'stanford.edu',
    'harvard.edu',
    'coursera.org',
    'edx.org',
    'khanacademy.org',
    
    # Legitimate Ad Networks (consider removing if you want to flag all ads)
    'doubleclick.net',
    'googlesyndication.com',
    'googleadservices.com',
    'facebook.com',
    'adsystem.amazon.com',
    
    # Additional Legitimate Services
    'zoom.us',
    'zoomgov.com',
    'webex.com',
    'gotomeeting.com',
    'teamviewer.com',
    'anydesk.com',
    'logmein.com',
    'slack.com',
    'atlassian.com',
    'jira.com',
    'confluence.com',
    'trello.com',
    'asana.com',
    'notion.so',
    'airtable.com'
    
    # Add organization-specific domains here
    # 'yourcompany.com',
    # 'partner-domain.com'
)

$foundHits = @()
$totalProcessed = 0
$skippedBenign = 0

Write-Host "Starting network log analysis..." -ForegroundColor Cyan

foreach ($logFile in $networkLogs) {
    if (Test-Path $logFile) {
        Write-Host "Processing: $logFile" -ForegroundColor Yellow
        $lines    = Get-Content $logFile
        $fileHits = @()
        
        foreach ($line in $lines) {
            $totalProcessed++
            $lower    = $line.ToLower()
            $isBenign = $false
            
            # Check against whitelist
            foreach ($w in $domainwhitelist) {
                if ($lower -match [regex]::Escape($w)) {
                    $isBenign = $true
                    $skippedBenign++
                    break
                }
            }
            
            # Skip if it's just an IP address without domain
            if ($lower -match '^\s*\d+\.\d+\.\d+\.\d+\s*$') {
                $isBenign = $true
            }
            
            # Skip localhost and private IP ranges
            if ($lower -match 'localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.' -or
                $lower -match '169\.254\.|224\.|225\.|226\.|227\.|228\.|229\.|23[0-9]\.|24[0-9]\.|25[0-5]\.') {
                $isBenign = $true
            }
            
            if (-not $isBenign -and $line.Trim() -ne '') {
                $fileHits += $line
            }
        }
        
        if ($fileHits.Count -gt 0) {
            $foundHits += "`n=== SUSPICIOUS ENTRIES FROM: $logFile ===`n$($fileHits -join "`n")"
            Write-Host "Found $($fileHits.Count) suspicious entries in $($logFile | Split-Path -Leaf)" -ForegroundColor Red
        } else {
            Write-Host "No suspicious entries found in $($logFile | Split-Path -Leaf)" -ForegroundColor Green
        }
    } else {
        Write-Host "Log file not found: $logFile" -ForegroundColor Magenta
    }
}

# Generate summary report
$summary = @"
NETWORK DOMAIN ANALYSIS SUMMARY
===============================
Total entries processed: $totalProcessed
Benign entries skipped: $skippedBenign
Suspicious entries found: $($foundHits.Count)
Analysis completed: $(Get-Date)

SUSPICIOUS ENTRIES:
$($foundHits -join "`n")
"@

if ($foundHits.Count -gt 0) {
    $summary | Out-File -FilePath $domainHits -Encoding UTF8
    Write-Host "`nSuspicious domain entries saved to: $domainHits" -ForegroundColor Red
    Write-Host "ALERT: Found $($foundHits.Count) potentially suspicious network entries!" -ForegroundColor Red -BackgroundColor Yellow
} else {
    "NETWORK DOMAIN ANALYSIS - No suspicious domains found.`nAnalysis completed: $(Get-Date)" | Out-File -FilePath $domainHits
    Write-Host "`nNo suspicious domains found in network logs." -ForegroundColor Green
}

Write-Host "`nAnalysis complete. Processed $totalProcessed total entries." -ForegroundColor Cyan

# === 7. Detect Suspicious Scheduled Tasks ===
$taskDir     = Join-Path $Parsed 'ScheduledTasks'
$taskLog     = Join-Path $IR 'ScheduledTasks\tasks_detailed.txt'
$taskHitsOut = Join-Path $taskDir 'Suspicious_Tasks.txt'
New-Item -ItemType Directory -Path $taskDir -Force | Out-Null

# Comprehensive whitelist of benign task actions (paths or executables)
$whitelistActions = @(
    # Windows System Tasks
    'C:\Windows\System32\svchost.exe',
    'C:\Windows\System32\taskeng.exe',
    'C:\Windows\System32\taskhostw.exe',
    'C:\Windows\System32\taskhost.exe',
    'C:\Windows\System32\rundll32.exe',
    'C:\Windows\System32\dllhost.exe',
    'C:\Windows\System32\conhost.exe',
    'C:\Windows\System32\wbem\wmiprvse.exe',
    'C:\Windows\System32\msiexec.exe',
    'C:\Windows\System32\regsvr32.exe',
    'C:\Windows\System32\sc.exe',
    'C:\Windows\System32\net.exe',
    'C:\Windows\System32\netsh.exe',
    'C:\Windows\System32\bcdedit.exe',
    'C:\Windows\System32\diskpart.exe',
    'C:\Windows\System32\defrag.exe',
    'C:\Windows\System32\cleanmgr.exe',
    'C:\Windows\System32\wbem\wmic.exe',
    'C:\Windows\System32\powershell.exe',
    'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe',
    'C:\Windows\System32\cmd.exe',
    'C:\Windows\SysWOW64\cmd.exe',
    'C:\Windows\System32\cscript.exe',
    'C:\Windows\SysWOW64\cscript.exe',
    'C:\Windows\System32\wscript.exe',
    'C:\Windows\SysWOW64\wscript.exe',
    
    # Windows Update & Maintenance
    'C:\Windows\System32\UsoClient.exe',
    'C:\Windows\System32\wuauclt.exe',
    'C:\Windows\servicing\TrustedInstaller.exe',
    'C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_*\TiWorker.exe',
    'C:\Windows\System32\CompatTelRunner.exe',
    'C:\Windows\System32\DisableDynamicUpdate.exe',
    'C:\Windows\System32\MRT.exe',
    'C:\Windows\System32\SIHClient.exe',
    'C:\Windows\System32\usocoreworker.exe',
    'C:\Windows\System32\WindowsUpdateElevatedInstaller.exe',
    
    # Windows Defender
    'C:\Program Files\Windows Defender\MpCmdRun.exe',
    'C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe',
    'C:\Program Files\Windows Defender\MsMpEng.exe',
    'C:\Program Files\Windows Defender\NisSrv.exe',
    'C:\Windows\System32\SecurityHealthSystray.exe',
    'C:\Windows\System32\smartscreen.exe',
    
    # Microsoft Office
    'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE',
    'C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE',
    'C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE',
    'C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE',
    'C:\Program Files\Microsoft Office\root\Office16\OfficeClickToRun.exe',
    'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe',
    'C:\Program Files (x86)\Microsoft Office\root\Office16\*',
    'C:\Program Files\Microsoft Office\root\VFS\ProgramFilesCommonX86\Microsoft Shared\Office16\*',
    
    # Common Applications
    'C:\Program Files\Google\Chrome\Application\chrome.exe',
    'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
    'C:\Program Files\Mozilla Firefox\firefox.exe',
    'C:\Program Files (x86)\Mozilla Firefox\firefox.exe',
    'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    'C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe',
    'C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe',
    'C:\Program Files\7-Zip\7z.exe',
    'C:\Program Files (x86)\7-Zip\7z.exe',
    'C:\Program Files\WinRAR\WinRAR.exe',
    'C:\Program Files (x86)\WinRAR\WinRAR.exe',
    'C:\Program Files\Notepad++\notepad++.exe',
    'C:\Program Files (x86)\Notepad++\notepad++.exe',
    
    # Antivirus Software (Common Vendors)
    'C:\Program Files\Symantec\*',
    'C:\Program Files (x86)\Symantec\*',
    'C:\Program Files\Norton\*',
    'C:\Program Files (x86)\Norton\*',
    'C:\Program Files\McAfee\*',
    'C:\Program Files (x86)\McAfee\*',
    'C:\Program Files\Kaspersky Lab\*',
    'C:\Program Files (x86)\Kaspersky Lab\*',
    'C:\Program Files\Bitdefender\*',
    'C:\Program Files (x86)\Bitdefender\*',
    'C:\Program Files\AVAST Software\*',
    'C:\Program Files (x86)\AVAST Software\*',
    'C:\Program Files\AVG\*',
    'C:\Program Files (x86)\AVG\*',
    'C:\Program Files\ESET\*',
    'C:\Program Files (x86)\ESET\*',
    'C:\Program Files\Trend Micro\*',
    'C:\Program Files (x86)\Trend Micro\*',
    'C:\Program Files\Sophos\*',
    'C:\Program Files (x86)\Sophos\*',
    'C:\Program Files\Malwarebytes\*',
    'C:\Program Files (x86)\Malwarebytes\*',
    
    # System Utilities
    'C:\Windows\System32\shutdown.exe',
    'C:\Windows\System32\gpupdate.exe',
    'C:\Windows\System32\vssadmin.exe',
    'C:\Windows\System32\backup.exe',
    'C:\Windows\System32\wbadmin.exe',
    'C:\Windows\System32\xcopy.exe',
    'C:\Windows\System32\robocopy.exe',
    'C:\Windows\System32\expand.exe',
    'C:\Windows\System32\compact.exe',
    'C:\Windows\System32\cipher.exe',
    'C:\Windows\System32\sfc.exe',
    'C:\Windows\System32\dism.exe',
    'C:\Windows\System32\chkdsk.exe',
    'C:\Windows\System32\fsutil.exe',
    'C:\Windows\System32\systeminfo.exe',
    'C:\Windows\System32\msinfo32.exe',
    'C:\Windows\System32\eventvwr.exe',
    'C:\Windows\System32\perfmon.exe',
    'C:\Windows\System32\resmon.exe',
    'C:\Windows\System32\tasklist.exe',
    'C:\Windows\System32\taskkill.exe',
    
    # Hardware & Drivers
    'C:\Windows\System32\PnPUnattend.exe',
    'C:\Windows\System32\DeviceSetupManager.exe',
    'C:\Windows\System32\drvinst.exe',
    'C:\Windows\System32\InfDefaultInstall.exe',
    'C:\Windows\System32\DeviceProperties.exe',
    
    # Windows Store & Modern Apps
    'C:\Windows\System32\wsreset.exe',
    'C:\Windows\ImmersiveControlPanel\SystemSettings.exe',
    'C:\Windows\SystemApps\*',
    'C:\Program Files\WindowsApps\*'
)

# Suspicious indicators for deeper analysis
$suspiciousIndicators = @{
    'SuspiciousLocations' = @(
        'C:\Users\*\AppData\Roaming\*',
        'C:\Users\*\AppData\Local\Temp\*',
        'C:\Windows\Temp\*',
        'C:\Temp\*',
        'C:\ProgramData\*',
        'C:\Users\Public\*',
        'C:\$Recycle.Bin\*',
        'C:\Recovery\*',
        'C:\Intel\*',
        'C:\AMD\*',
        'C:\PerfLogs\*'
    )
    
    'SuspiciousExtensions' = @(
        '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr', '.pif', '.com'
    )
    
    'SuspiciousArguments' = @(
        '-enc', '-encoded', '-w hidden', '-windowstyle hidden', '-nop', '-noprofile',
        '-ep bypass', '-executionpolicy bypass', 'iex', 'invoke-expression',
        'downloadstring', 'webclient', 'net.webclient', 'bitsadmin', 'certutil',
        'powershell.exe -', 'cmd.exe /c', 'wscript.exe', 'cscript.exe',
        'regsvr32 /s', 'rundll32.exe', 'mshta.exe', 'odbcconf.exe',
        'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'msbuild.exe'
    )
    
    'SuspiciousKeywords' = @(
        'mimikatz', 'metasploit', 'meterpreter', 'cobalt', 'beacon',
        'empire', 'covenant', 'shellcode', 'payload', 'backdoor',
        'keylogger', 'stealer', 'ransomware', 'crypter', 'trojan',
        'dropper', 'loader', 'injector', 'hollowing', 'persistence'
    )
    
    'NetworkCommands' = @(
        'telnet', 'ftp', 'tftp', 'ssh', 'scp', 'nc.exe', 'netcat',
        'curl', 'wget', 'invoke-webrequest', 'start-bitstransfer'
    )
    
    'SystemModification' = @(
        'net user', 'net localgroup', 'net group', 'whoami /priv',
        'reg add', 'reg delete', 'reg query', 'schtasks /create',
        'at.exe', 'sc create', 'sc config', 'wevtutil cl',
        'fsutil behavior', 'bcdedit', 'vssadmin delete'
    )
}

# Common legitimate task name patterns (case-insensitive regex)
$legitimateTaskPatterns = @(
    '^Microsoft\\',
    '^Windows\\',
    '^Adobe\\',
    '^Google\\',
    '^Mozilla\\',
    '^Office\\',
    '^OneDrive\\',
    '^McAfee\\',
    '^Norton\\',
    '^Symantec\\',
    '^Kaspersky\\',
    '^Bitdefender\\',
    '^AVAST\\',
    '^AVG\\',
    '^ESET\\',
    '^TrendMicro\\',
    '^Sophos\\',
    '^Malwarebytes\\'
)

function Test-SuspiciousTask {
    param([string]$TaskLine)
    
    $suspiciousScore = 0
    $reasons = @()
    
    # Parse task line (assuming format: TaskName | State | LastRunTime | NextRunTime | Author | Actions)
    $parts = $TaskLine -split '\|'
    if ($parts.Count -lt 6) { return @{Score=0; Reasons=@()} }
    
    $taskName = $parts[0].Trim()
    $author = $parts[4].Trim()
    $action = $parts[5].Trim()
    
    # Check if task name follows legitimate patterns
    $isLegitimatePattern = $false
    foreach ($pattern in $legitimateTaskPatterns) {
        if ($taskName -match $pattern) {
            $isLegitimatePattern = $true
            break
        }
    }
    
    if (-not $isLegitimatePattern) {
        $suspiciousScore += 2
        $reasons += "Non-standard task name pattern"
    }
    
    # Check author
    if ($author -notmatch '^(Microsoft|SYSTEM|Administrators|NT AUTHORITY)' -and $author -ne '') {
        $suspiciousScore += 3
        $reasons += "Suspicious author: $author"
    }
    
    # Check for suspicious locations
    foreach ($location in $suspiciousIndicators.SuspiciousLocations) {
        if ($action -like $location) {
            $suspiciousScore += 4
            $reasons += "Suspicious location: $location"
            break
        }
    }
    
    # Check for suspicious file extensions
    foreach ($ext in $suspiciousIndicators.SuspiciousExtensions) {
        if ($action -like "*$ext*") {
            $suspiciousScore += 3
            $reasons += "Suspicious file extension: $ext"
        }
    }
    
    # Check for suspicious arguments/commands
    foreach ($arg in $suspiciousIndicators.SuspiciousArguments) {
        if ($action -like "*$arg*") {
            $suspiciousScore += 5
            $reasons += "Suspicious argument: $arg"
        }
    }
    
    # Check for malicious keywords
    foreach ($keyword in $suspiciousIndicators.SuspiciousKeywords) {
        if ($action -like "*$keyword*") {
            $suspiciousScore += 8
            $reasons += "Malicious keyword detected: $keyword"
        }
    }
    
    # Check for network commands
    foreach ($netCmd in $suspiciousIndicators.NetworkCommands) {
        if ($action -like "*$netCmd*") {
            $suspiciousScore += 4
            $reasons += "Network command: $netCmd"
        }
    }
    
    # Check for system modification commands
    foreach ($sysCmd in $suspiciousIndicators.SystemModification) {
        if ($action -like "*$sysCmd*") {
            $suspiciousScore += 6
            $reasons += "System modification command: $sysCmd"
        }
    }
    
    # Check for base64 encoding (common in malware)
    if ($action -match '[A-Za-z0-9+/]{20,}={0,2}') {
        $suspiciousScore += 7
        $reasons += "Possible base64 encoded content"
    }
    
    # Check for very long command lines (often used to obfuscate)
    if ($action.Length -gt 500) {
        $suspiciousScore += 3
        $reasons += "Unusually long command line"
    }
    
    # Check for multiple chained commands
    if (($action -split '[&|;]').Count -gt 3) {
        $suspiciousScore += 4
        $reasons += "Multiple chained commands"
    }
    
    return @{
        Score = $suspiciousScore
        Reasons = $reasons
    }
}

$suspiciousTasks = @()
$analyzedTasks = 0
$whitelistedTasks = 0

Write-Host "Starting scheduled task analysis..." -ForegroundColor Cyan

if (Test-Path $taskLog) {
    $lines = Get-Content $taskLog
    
    foreach ($line in $lines) {
        # Skip header or empty lines
        if ($line -match '^\s*TaskName' -or $line -match '^\s*$' -or $line -match '^-+$') {
            continue
        }
        
        $analyzedTasks++
        
        # Parse the line to extract action
        $parts = $line -split '\|'
        if ($parts.Count -lt 6) { continue }
        
        $action = $parts[5].Trim()
        
        # Check whitelist first
        $isWhitelisted = $false
        foreach ($whitelistItem in $whitelistActions) {
            if ($action -like $whitelistItem -or $action -eq $whitelistItem) {
                $isWhitelisted = $true
                $whitelistedTasks++
                break
            }
        }
        
        if (-not $isWhitelisted) {
            # Perform detailed suspicious analysis
            $analysis = Test-SuspiciousTask -TaskLine $line
            
            if ($analysis.Score -gt 0) {
                $taskInfo = @{
                    Line = $line
                    Score = $analysis.Score
                    Reasons = $analysis.Reasons
                    Severity = switch ($analysis.Score) {
                        {$_ -ge 15} { "CRITICAL" }
                        {$_ -ge 10} { "HIGH" }
                        {$_ -ge 5}  { "MEDIUM" }
                        default     { "LOW" }
                    }
                }
                $suspiciousTasks += $taskInfo
            }
        }
    }
    
    # Sort by suspicion score (highest first)
    $suspiciousTasks = $suspiciousTasks | Sort-Object Score -Descending
    
    # Generate detailed report
    $report = @"
SCHEDULED TASK SECURITY ANALYSIS REPORT
=======================================
Analysis Date: $(Get-Date)
Total Tasks Analyzed: $analyzedTasks
Whitelisted Tasks: $whitelistedTasks
Suspicious Tasks Found: $($suspiciousTasks.Count)

THREAT LEVEL SUMMARY:
$(($suspiciousTasks | Group-Object Severity | ForEach-Object { "- $($_.Name): $($_.Count)" }) -join "`n")

DETAILED FINDINGS:
==================
"@
    
    if ($suspiciousTasks.Count -gt 0) {
        foreach ($task in $suspiciousTasks) {
            $report += @"

[$($task.Severity) - Score: $($task.Score)]
Task Details: $($task.Line)
Suspicious Indicators:
$(($task.Reasons | ForEach-Object { "  - $_" }) -join "`n")
$("-" * 80)
"@
        }
        
        $report | Out-File -FilePath $taskHitsOut -Encoding UTF8
        
        $criticalCount = ($suspiciousTasks | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $highCount = ($suspiciousTasks | Where-Object { $_.Severity -eq "HIGH" }).Count
        
        if ($criticalCount -gt 0) {
            Write-Host "🚨 CRITICAL ALERT: Found $criticalCount critical suspicious tasks!" -ForegroundColor Red -BackgroundColor Yellow
        }
        if ($highCount -gt 0) {
            Write-Host "⚠️  HIGH ALERT: Found $highCount high-risk suspicious tasks!" -ForegroundColor Red
        }
        
        Write-Host "Suspicious scheduled tasks report saved to: $taskHitsOut" -ForegroundColor Yellow
        Write-Host "Total suspicious tasks found: $($suspiciousTasks.Count)" -ForegroundColor Red
        
    } else {
        $report += "`nNo suspicious scheduled tasks detected. All tasks appear legitimate."
        $report | Out-File -FilePath $taskHitsOut -Encoding UTF8
        Write-Host "✅ No suspicious scheduled tasks detected." -ForegroundColor Green
    }
    
} else {
    $errorMsg = "❌ Scheduled task log file not found: $taskLog"
    $errorMsg | Out-File -FilePath $taskHitsOut -Encoding UTF8
    Write-Host $errorMsg -ForegroundColor Red
}

Write-Host "Analysis complete. Processed $analyzedTasks tasks total." -ForegroundColor Cyan

# === 9. Search APT-Hunter TimeSketch CSV for Critical Indicators ===
$aptHunterReport = Get-ChildItem -Path (Join-Path $Parsed 'APT_Hunter') -Filter 'APT_Hunter_TimeSketch.csv' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
$aptFindingOut   = Join-Path (Join-Path $Parsed 'APT_Hunter') 'APT_Hunter_Detections.txt'

if ($aptHunterReport -and (Test-Path $aptHunterReport.FullName)) {
    $csv      = Import-Csv $aptHunterReport.FullName
    $findings = @()

    # 1. Suspicious regsvr32.exe usage
    $regsvrHits = $csv | Where-Object { $_.PSObject.Properties.Value -match 'regsvr32\.exe' }
    if ($regsvrHits) {
        $findings += "`n=== Detected Suspicious PowerShell via regsvr32.exe ==="
        $findings += $regsvrHits | Out-String -Width 4096
    }

    if ($findings) {
        $findings | Out-File -FilePath $aptFindingOut -Encoding UTF8
        Write-Host "APT-Hunter detections written to: $aptFindingOut"
    } else {
        "No APT-Hunter IOC matches found." | Out-File -FilePath $aptFindingOut
        Write-Host "No critical indicators in APT-Hunter CSV."
    }
} else {
    Write-Host "APT-Hunter TimeSketch report not found for analysis."
}

# === 10. ShimCache Output Scan for Temp-folder Executables ===
$shimCSV        = Join-Path (Join-Path $Parsed 'Shimcache') 'output.csv'
$shimFindingOut = Join-Path (Join-Path $Parsed 'Shimcache') 'Shimcache_Findings.txt'

if (Test-Path $shimCSV) {
    $csv     = Import-Csv $shimCSV
    # Pattern matches any .exe under C:\Users\<any user>\AppData\Local\Temp
    $tempExePattern = 'C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\[^\\]+\.exe'

    $matches = $csv | Where-Object {
        # concatenate all fields into one string and test
        ($_.PSObject.Properties.Value -join ' ') -match $tempExePattern
    }

    if ($matches) {
        # write each matching record as CSV for easier review
        $matches | Export-Csv -NoTypeInformation -Path $shimFindingOut
        Write-Host "Temp-folder executables found in ShimCache; details in: $shimFindingOut"
    } else {
        "No Temp-folder executables found in ShimCache." | Out-File -FilePath $shimFindingOut
        Write-Host "No matches in ShimCache for Temp-folder executables."
    }
} else {
    Write-Host "ShimCache output CSV not found: $shimCSV"
}


# === 11. SOFTWARE hive: enumerate installed programs ===
$softwareHive = Join-Path $IR 'Registry\SOFTWARE.hiv'
$swMount      = 'HKLM\IR_SOFTWARE'
if (Test-Path $softwareHive) {
    reg.exe load $swMount $softwareHive | Out-Null
    $instProgs = Get-ItemProperty -Path "$swMount\Microsoft\Windows\CurrentVersion\Uninstall\*" |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    $csvOut = Join-Path $Parsed 'Registry\InstalledPrograms.csv'
    New-Item -ItemType Directory -Path (Split-Path $csvOut) -Force | Out-Null
    $instProgs | Export-Csv $csvOut -NoTypeInformation
    reg.exe unload $swMount | Out-Null
    Write-Host "Installed‐program inventory exported to: $csvOut"
} else {
    Write-Host "SOFTWARE hive not found at $softwareHive"
}

# === 12. SAM hive: list local user accounts ===
$samHive  = Join-Path $IR 'Registry\SAM.hiv'
$samMount = 'HKLM\IR_SAM'
if (Test-Path $samHive) {
    reg.exe load $samMount $samHive | Out-Null
    $localUsers = Get-ItemProperty -Path "$samMount\SAM\Domains\Account\Users\Names\*" |
        Select-Object PSChildName
    $samCsv = Join-Path $Parsed 'Registry\LocalUsers.csv'
    New-Item -ItemType Directory -Path (Split-Path $samCsv) -Force | Out-Null
    $localUsers | Export-Csv $samCsv -NoTypeInformation
    reg.exe unload $samMount | Out-Null
    Write-Host "Local user list exported to: $samCsv"
} else {
    Write-Host "SAM hive not found at $samHive"
}
# === 14. Certificates: dump all .pfx details ===
$certOut = Join-Path $Parsed 'Certificates\pfx_dump.txt'
New-Item -ItemType Directory -Path (Split-Path $certOut) -Force | Out-Null
Get-ChildItem -Path $IR -Filter *.pfx -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    certutil -dump $_.FullName | Out-File -FilePath $certOut -Append
}
Write-Host "All .pfx certificates dumped to: $certOut"

# === 15. Enhanced EDR/AV logs: comprehensive keyword scan ===
$edrOut = Join-Path $Parsed 'AV_EDR\EDR_Findings.txt'
$edrSummary = Join-Path $Parsed 'AV_EDR\EDR_Summary.txt'
New-Item -ItemType Directory -Path (Split-Path $edrOut) -Force | Out-Null

# Enhanced detection keywords organized by category
$detectionPatterns = @{
    'Malware Detection' = @(
        'malware', 'virus', 'trojan', 'worm', 'rootkit', 'backdoor', 'spyware', 'adware',
        'ransomware', 'cryptolocker', 'wannacry', 'keylogger', 'botnet', 'payload',
        'dropper', 'downloader', 'loader', 'packer', 'obfuscated', 'encoded'
    )
    'Threat Actions' = @(
        'detected', 'blocked', 'quarantined', 'removed', 'cleaned', 'isolated',
        'terminated', 'killed', 'suspended', 'prevented', 'stopped', 'denied',
        'contained', 'remediated', 'deleted', 'moved'
    )
    'Advanced Threats' = @(
        'apt', 'zero.day', 'exploit', 'vulnerability', 'cve-', 'fileless',
        'living.off.the.land', 'lolbas', 'powershell.empire', 'cobalt.strike',
        'metasploit', 'mimikatz', 'credential.dump', 'pass.the.hash', 'lateral.movement'
    )
    'Behavioral Indicators' = @(
        'suspicious', 'anomalous', 'unusual', 'unauthorized', 'privilege.escalation',
        'process.injection', 'dll.injection', 'process.hollowing', 'reflective.loading',
        'memory.scraping', 'network.beacon', 'command.and.control', 'c2', 'exfiltration'
    )
    'File Operations' = @(
        'file.modification', 'registry.change', 'startup.modification', 'service.creation',
        'scheduled.task', 'persistence', 'autorun', 'hijack', 'masquerading',
        'timestamp.manipulation', 'file.deletion', 'shadow.copy'
    )
    'Network Activity' = @(
        'outbound.connection', 'dns.request', 'domain.generation', 'dga',
        'tor.traffic', 'proxy.detected', 'tunnel', 'encryption.detected',
        'data.transfer', 'upload.detected', 'download.blocked'
    )
}

# File extensions to analyze
$logExtensions = @('*.log', '*.txt', '*.json', '*.xml', '*.csv', '*.evt', '*.evtx')

Write-Host "Starting enhanced EDR/AV log analysis..." -ForegroundColor Green

# Collect all relevant log files from AV_EDR folder only
$edrLogs = Get-ChildItem -Path (Join-Path $IR 'AV_EDR') -Include $logExtensions -Recurse -ErrorAction SilentlyContinue

Write-Host "Found $($edrLogs.Count) log files to analyze" -ForegroundColor Yellow

# Initialize counters for summary
$detectionCounts = @{}
$totalMatches = 0
$processedFiles = 0

# Process each log file
foreach ($f in $edrLogs) {
    Write-Progress -Activity "Analyzing EDR/AV Logs" -Status "Processing $($f.Name)" -PercentComplete (($processedFiles / $edrLogs.Count) * 100)
    
    try {
        # Create combined regex pattern for efficient searching
        $allPatterns = ($detectionPatterns.Values | ForEach-Object { $_ }) -join '|'
        $matches = Select-String -Path $f.FullName -Pattern $allPatterns -AllMatches -ErrorAction SilentlyContinue
        
        if ($matches) {
            "=" * 80 | Out-File -Append $edrOut
            "FILE: $($f.FullName)" | Out-File -Append $edrOut
            "SIZE: $([math]::Round($f.Length/1KB, 2)) KB" | Out-File -Append $edrOut
            "MODIFIED: $($f.LastWriteTime)" | Out-File -Append $edrOut
            "=" * 80 | Out-File -Append $edrOut
            
            foreach ($match in $matches) {
                # Categorize the match
                $category = "Unknown"
                $matchedKeyword = ""
                
                foreach ($cat in $detectionPatterns.Keys) {
                    foreach ($keyword in $detectionPatterns[$cat]) {
                        if ($match.Line -match $keyword) {
                            $category = $cat
                            $matchedKeyword = $keyword
                            break
                        }
                    }
                    if ($category -ne "Unknown") { break }
                }
                
                # Update counters
                if (-not $detectionCounts.ContainsKey($category)) {
                    $detectionCounts[$category] = 0
                }
                $detectionCounts[$category]++
                $totalMatches++
                
                # Output formatted result
                $output = @(
                    "[CATEGORY: $category]"
                    "[KEYWORD: $matchedKeyword]"
                    "[LINE: $($match.LineNumber)]"
                    "[CONTENT: $($match.Line.Trim())]"
                    ""
                ) -join "`n"
                
                $output | Out-File -Append $edrOut
            }
            
            "`n" | Out-File -Append $edrOut
        }
    }
    catch {
        Write-Warning "Error processing file $($f.FullName): $($_.Exception.Message)"
        "ERROR processing file $($f.FullName): $($_.Exception.Message)" | Out-File -Append $edrOut
    }
    
    $processedFiles++
}

# Generate summary report
$summaryContent = @"
EDR/AV LOG ANALYSIS SUMMARY
Generated: $(Get-Date)
Files Analyzed: $($edrLogs.Count)
Total Matches Found: $totalMatches

DETECTION BREAKDOWN BY CATEGORY:
$("-" * 40)
"@

foreach ($cat in $detectionCounts.Keys | Sort-Object) {
    $summaryContent += "`n$cat : $($detectionCounts[$cat]) matches"
}

$summaryContent += @"

`n
TOP SECURITY VENDORS DETECTED:
$("-" * 40)
"@

# Identify security vendors from file paths
$vendors = @()
$edrLogs | ForEach-Object {
    $path = $_.FullName.ToLower()
    switch -Regex ($path) {
        'defender|windows.*defender|msmpeng' { $vendors += 'Windows Defender' }
        'malwarebytes' { $vendors += 'Malwarebytes' }
        'kaspersky' { $vendors += 'Kaspersky' }
        'mcafee' { $vendors += 'McAfee' }
        'symantec|norton' { $vendors += 'Symantec/Norton' }
        'trend.*micro' { $vendors += 'Trend Micro' }
        'crowdstrike' { $vendors += 'CrowdStrike' }
        'sentinelone' { $vendors += 'SentinelOne' }
        'carbon.*black' { $vendors += 'Carbon Black' }
        'cylance' { $vendors += 'Cylance' }
        'avast' { $vendors += 'Avast' }
        'avg' { $vendors += 'AVG' }
        'bitdefender' { $vendors += 'Bitdefender' }
        'eset' { $vendors += 'ESET' }
        'sophos' { $vendors += 'Sophos' }
    }
}

$uniqueVendors = $vendors | Sort-Object -Unique
foreach ($vendor in $uniqueVendors) {
    $summaryContent += "`n$vendor"
}

if ($totalMatches -eq 0) {
    $summaryContent += "`n`nNO SECURITY EVENTS DETECTED - This could indicate:"
    $summaryContent += "`n- No threats were present during the analyzed timeframe"
    $summaryContent += "`n- Security software was not actively logging"
    $summaryContent += "`n- Log files may have been cleared or rotated"
    $summaryContent += "`n- Different log locations may need to be analyzed"
}

$summaryContent | Out-File $edrSummary

Write-Host "`nEDR keyword scan complete!" -ForegroundColor Green
Write-Host "Detailed results: $edrOut" -ForegroundColor Cyan
Write-Host "Summary report: $edrSummary" -ForegroundColor Cyan
Write-Host "Total matches found: $totalMatches" -ForegroundColor Yellow

# Display summary on console
if ($totalMatches -gt 0) {
    Write-Host "`nTop Detection Categories:" -ForegroundColor Magenta
    $detectionCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object {
        Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor White
    }
}

Write-Progress -Activity "Analyzing EDR/AV Logs" -Completed

Write-Host "`nAll processing complete."
