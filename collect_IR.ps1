# Auto-elevate if not running as admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Set up paths
$base = "C:\IR"
$log = "$base\collection_log.txt"
$debug = "$base\debug_output.txt"
$mountPath = "C:\shadowcopy_mount"

# Create directories
$folders = @("Prefetch", "Amcache", "Registry", "EventLogs", "ScheduledTasks", "CrowdStrike", "AvastLogs", "Network", "USNJournal")
foreach ($f in $folders) { New-Item -ItemType Directory -Path "$base\$f" -Force | Out-Null }

"Artifact Collection Log - $(Get-Date)" | Set-Content $log
"--- DEBUG OUTPUT ---`n" | Set-Content $debug

# Create shadow copy
try {
    ([WMICLASS]"Win32_ShadowCopy").Create("C:\", "ClientAccessible") | Out-Null
    Start-Sleep -Seconds 2
    $shadow = Get-CimInstance Win32_ShadowCopy | Sort-Object InstallDate -Descending | Select-Object -First 1
    $shadowPath = $shadow.DeviceObject
    if (-not $shadowPath) {
        "[FAIL] Shadow copy not created" | Tee-Object -FilePath $log -Append | Tee-Object -FilePath $debug -Append
        exit
    }
    "Mounted shadow: $shadowPath" | Tee-Object -FilePath $debug -Append | Tee-Object -FilePath $log -Append
} catch {
    "[ERROR] Shadow creation failed: $_" | Tee-Object -FilePath $debug -Append | Tee-Object -FilePath $log -Append
    exit
}

# Mount the shadow copy
cmd /c mklink /d $mountPath $shadowPath | Out-Null

# Utility function
function Try-Copy($source, $dest, $desc) {
    try {
        Copy-Item -Path $source -Destination $dest -Recurse -Force -ErrorAction Stop
        "[OK] $desc" | Tee-Object -FilePath $log -Append
    } catch {
        "[FAIL] $desc -- $_" | Tee-Object -FilePath $log -Append
    }
}

# Utility function for registry exports
function Try-RegExport($regPath, $outputFile, $desc) {
    try {
        reg export $regPath $outputFile /y 2>$null
        if ($LASTEXITCODE -eq 0) {
            "[OK] $desc registry exported" | Tee-Object -FilePath $log -Append
        } else {
            "[FAIL] $desc registry export failed (Exit Code: $LASTEXITCODE)" | Tee-Object -FilePath $log -Append
        }
    } catch {
        "[FAIL] $desc registry export error: $_" | Tee-Object -FilePath $log -Append
    }
}

# Basic artifact collection
Try-Copy "$mountPath\Windows\Prefetch\*.pf" "$base\Prefetch" "Prefetch"
Try-Copy "$mountPath\Windows\AppCompat\Programs\Amcache.hve" "$base\Amcache" "Amcache"
Try-Copy "$mountPath\Windows\System32\config\SYSTEM"       "$base\Registry\SYSTEM.hiv"       "Registry SYSTEM (ShimCache source)"
Try-Copy "$mountPath\Windows\System32\config\SOFTWARE"     "$base\Registry\SOFTWARE.hiv"     "Registry SOFTWARE"
Try-Copy "$mountPath\Windows\System32\config\SAM"          "$base\Registry\SAM.hiv"          "Registry SAM"
Try-Copy "$mountPath\Windows\System32\config\SECURITY"     "$base\Registry\SECURITY.hiv"     "Registry SECURITY"
Try-Copy "$mountPath\Windows\System32\winevt\Logs\*.evtx" "$base\EventLogs" "Event Logs"

# Enhanced AV/EDR Collection Module
# Create AV/EDR folder structure
$avFolders = @(
    "CrowdStrike", "Avast", "Symantec", "McAfee", "Trend", "Kaspersky", 
    "Bitdefender", "ESET", "Sophos", "Malwarebytes", "WindowsDefender",
    "CarbonBlack", "SentinelOne", "Cylance", "Palo_Alto", "FireEye",
    "Fortinet", "Check_Point", "Webroot", "AVG", "Avira", "F-Secure",
    "G_Data", "Comodo", "Vipre", "TrendMicro_Apex", "Cisco_AMP", "Generic_Security"
)
foreach ($folder in $avFolders) { 
    New-Item -ItemType Directory -Path "$base\AV_EDR\$folder" -Force | Out-Null 
}

# 1. CrowdStrike Falcon (Enhanced)
try {
    $csLocations = @(
        "$mountPath\Windows\Temp\*crowdstrike*",
        "$mountPath\ProgramData\CrowdStrike\*",
        "$mountPath\Windows\System32\drivers\CrowdStrike\*",
        "$mountPath\Program Files\CrowdStrike\*",
        "$mountPath\Windows\CSAgent\*"
    )
    foreach ($location in $csLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\CrowdStrike" "CrowdStrike from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CSAgent" "$base\AV_EDR\CrowdStrike\CSAgent_registry.reg" "CrowdStrike CSAgent"
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\CrowdStrike" "$base\AV_EDR\CrowdStrike\CrowdStrike_registry.reg" "CrowdStrike"
    "[OK] CrowdStrike Enhanced Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] CrowdStrike Enhanced -- $_" | Tee-Object -FilePath $log -Append
}

# 2. Carbon Black (VMware)
try {
    $cbLocations = @(
        "$mountPath\Program Files\Confer\*",
        "$mountPath\Program Files (x86)\Confer\*",
        "$mountPath\ProgramData\Confer\*",
        "$mountPath\Program Files\CarbonBlack\*",
        "$mountPath\Windows\CarbonBlack\*"
    )
    foreach ($location in $cbLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\CarbonBlack" "Carbon Black from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\CarbonBlack" "$base\AV_EDR\CarbonBlack\CarbonBlack_registry.reg" "Carbon Black"
    "[OK] Carbon Black Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Carbon Black -- $_" | Tee-Object -FilePath $log -Append
}

# 3. SentinelOne
try {
    $s1Locations = @(
        "$mountPath\Program Files\SentinelOne\*",
        "$mountPath\ProgramData\Sentinel\*",
        "$mountPath\Windows\System32\config\systemprofile\AppData\Local\Sentinel\*"
    )
    foreach ($location in $s1Locations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\SentinelOne" "SentinelOne from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\SentinelOne" "$base\AV_EDR\SentinelOne\SentinelOne_registry.reg" "SentinelOne"
    "[OK] SentinelOne Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] SentinelOne -- $_" | Tee-Object -FilePath $log -Append
}

# 4. Cylance (BlackBerry)
try {
    $cylanceLocations = @(
        "$mountPath\Program Files\Cylance\*",
        "$mountPath\ProgramData\Cylance\*",
        "$mountPath\Windows\System32\drivers\Cylance\*"
    )
    foreach ($location in $cylanceLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Cylance" "Cylance from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\Cylance" "$base\AV_EDR\Cylance\Cylance_registry.reg" "Cylance"
    "[OK] Cylance Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Cylance -- $_" | Tee-Object -FilePath $log -Append
}

# 5. Palo Alto Traps/Cortex XDR
try {
    $paLocations = @(
        "$mountPath\Program Files\Palo Alto Networks\*",
        "$mountPath\ProgramData\Cyvera\*",
        "$mountPath\ProgramData\Palo Alto Networks\*"
    )
    foreach ($location in $paLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Palo_Alto" "Palo Alto from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\Palo Alto Networks" "$base\AV_EDR\Palo_Alto\PaloAlto_registry.reg" "Palo Alto"
    "[OK] Palo Alto Traps/Cortex Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Palo Alto -- $_" | Tee-Object -FilePath $log -Append
}

# 6. FireEye HX
try {
    $fireeyeLocations = @(
        "$mountPath\Program Files\FireEye\*",
        "$mountPath\Windows\System32\drivers\FireEye\*",
        "$mountPath\ProgramData\FireEye\*"
    )
    foreach ($location in $fireeyeLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\FireEye" "FireEye from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\FireEye" "$base\AV_EDR\FireEye\FireEye_registry.reg" "FireEye"
    "[OK] FireEye Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] FireEye -- $_" | Tee-Object -FilePath $log -Append
}

# 7. Cisco AMP
try {
    $ciscoLocations = @(
        "$mountPath\Program Files\Cisco\AMP\*",
        "$mountPath\Program Files (x86)\Cisco\AMP\*",
        "$mountPath\ProgramData\Cisco\AMP\*"
    )
    foreach ($location in $ciscoLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Cisco_AMP" "Cisco AMP from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\Cisco" "$base\AV_EDR\Cisco_AMP\Cisco_registry.reg" "Cisco"
    "[OK] Cisco AMP Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Cisco AMP -- $_" | Tee-Object -FilePath $log -Append
}

# ═══════════════════════ MAJOR ANTIVIRUS SOLUTIONS ═══════════════════════

# 8. Symantec/Norton (Enhanced)
try {
    $symantecLocations = @(
        "$mountPath\Program Files\Symantec\*",
        "$mountPath\Program Files (x86)\Symantec\*",
        "$mountPath\Program Files\Norton\*",
        "$mountPath\Program Files (x86)\Norton\*",
        "$mountPath\ProgramData\Symantec\*",
        "$mountPath\ProgramData\Norton\*",
        "$mountPath\Users\All Users\Symantec\*"
    )
    foreach ($location in $symantecLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Symantec" "Symantec from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\Symantec" "$base\AV_EDR\Symantec\Symantec_registry.reg" "Symantec"
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\Norton" "$base\AV_EDR\Symantec\Norton_registry.reg" "Norton"
    "[OK] Symantec/Norton Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Symantec/Norton -- $_" | Tee-Object -FilePath $log -Append
}

# 9. McAfee (Enhanced)
try {
    $mcafeeLocations = @(
        "$mountPath\Program Files\McAfee\*",
        "$mountPath\Program Files (x86)\McAfee\*",
        "$mountPath\Program Files\Common Files\McAfee\*",
        "$mountPath\ProgramData\McAfee\*",
        "$mountPath\Users\All Users\McAfee\*"
    )
    foreach ($location in $mcafeeLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\McAfee" "McAfee from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\McAfee" "$base\AV_EDR\McAfee\McAfee_registry.reg" "McAfee"
    "[OK] McAfee Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] McAfee -- $_" | Tee-Object -FilePath $log -Append
}

# 10. Trend Micro (Enhanced)
try {
    $trendLocations = @(
        "$mountPath\Program Files\Trend Micro\*",
        "$mountPath\Program Files (x86)\Trend Micro\*",
        "$mountPath\ProgramData\Trend Micro\*",
        "$mountPath\Windows\System32\drivers\tmcomm.sys",
        "$mountPath\Windows\System32\drivers\tmactmon.sys"
    )
    foreach ($location in $trendLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Trend" "Trend Micro from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\TrendMicro" "$base\AV_EDR\Trend\TrendMicro_registry.reg" "Trend Micro"
    "[OK] Trend Micro Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Trend Micro -- $_" | Tee-Object -FilePath $log -Append
}

# 11. Kaspersky
try {
    $kasperskyLocations = @(
        "$mountPath\Program Files\Kaspersky Lab\*",
        "$mountPath\Program Files (x86)\Kaspersky Lab\*",
        "$mountPath\ProgramData\Kaspersky Lab\*",
        "$mountPath\Users\All Users\Kaspersky Lab\*"
    )
    foreach ($location in $kasperskyLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Kaspersky" "Kaspersky from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\KasperskyLab" "$base\AV_EDR\Kaspersky\Kaspersky_registry.reg" "Kaspersky"
    "[OK] Kaspersky Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Kaspersky -- $_" | Tee-Object -FilePath $log -Append
}

# 12. Bitdefender
try {
    $bitdefenderLocations = @(
        "$mountPath\Program Files\Bitdefender\*",
        "$mountPath\Program Files (x86)\Bitdefender\*",
        "$mountPath\ProgramData\Bitdefender\*"
    )
    foreach ($location in $bitdefenderLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Bitdefender" "Bitdefender from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\Bitdefender" "$base\AV_EDR\Bitdefender\Bitdefender_registry.reg" "Bitdefender"
    "[OK] Bitdefender Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Bitdefender -- $_" | Tee-Object -FilePath $log -Append
}

# 13. ESET
try {
    $esetLocations = @(
        "$mountPath\Program Files\ESET\*",
        "$mountPath\Program Files (x86)\ESET\*",
        "$mountPath\ProgramData\ESET\*"
    )
    foreach ($location in $esetLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\ESET" "ESET from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\ESET" "$base\AV_EDR\ESET\ESET_registry.reg" "ESET"
    "[OK] ESET Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] ESET -- $_" | Tee-Object -FilePath $log -Append
}

# 14. Sophos
# try {
#     $sophosLocations = @(
#         "$mountPath\Program Files\Sophos\*",
#         "$mountPath\Program Files (x86)\Sophos\*",
#         "$mountPath\ProgramData\Sophos\*"
#     )
#     foreach ($location in $sophosLocations) {
#         if (Test-Path $location -ErrorAction SilentlyContinue) {
#             Try-Copy $location "$base\AV_EDR\Sophos" "Sophos from $location"
#         }
#     }
#     Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\Sophos" "$base\AV_EDR\Sophos\Sophos_registry.reg" "Sophos"
#     "[OK] Sophos Collection" | Tee-Object -FilePath $log -Append
# } catch {
#     "[FAIL] Sophos -- $_" | Tee-Object -FilePath $log -Append
# }

# 15. Malwarebytes
try {
    $mbamLocations = @(
        "$mountPath\Program Files\Malwarebytes\*",
        "$mountPath\Program Files (x86)\Malwarebytes\*",
        "$mountPath\ProgramData\Malwarebytes\*"
    )
    foreach ($location in $mbamLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Malwarebytes" "Malwarebytes from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\Malwarebytes" "$base\AV_EDR\Malwarebytes\Malwarebytes_registry.reg" "Malwarebytes"
    "[OK] Malwarebytes Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Malwarebytes -- $_" | Tee-Object -FilePath $log -Append
}

# 16. Windows Defender
try {
    $defenderLocations = @(
        "$mountPath\ProgramData\Microsoft\Windows Defender\*",
        "$mountPath\Program Files\Windows Defender\*",
        "$mountPath\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows Defender\*"
    )
    foreach ($location in $defenderLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\WindowsDefender" "Windows Defender from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" "$base\AV_EDR\WindowsDefender\WindowsDefender_registry.reg" "Windows Defender"
    "[OK] Windows Defender Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Windows Defender -- $_" | Tee-Object -FilePath $log -Append
}

# 17. Fortinet FortiClient
try {
    $fortinetLocations = @(
        "$mountPath\Program Files\Fortinet\*",
        "$mountPath\Program Files (x86)\Fortinet\*",
        "$mountPath\ProgramData\Fortinet\*"
    )
    foreach ($location in $fortinetLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Fortinet" "Fortinet from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet" "$base\AV_EDR\Fortinet\Fortinet_registry.reg" "Fortinet"
    "[OK] Fortinet Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Fortinet -- $_" | Tee-Object -FilePath $log -Append
}

# 18. Check Point
try {
    $checkpointLocations = @(
        "$mountPath\Program Files\CheckPoint\*",
        "$mountPath\Program Files (x86)\CheckPoint\*",
        "$mountPath\ProgramData\CheckPoint\*"
    )
    foreach ($location in $checkpointLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Check_Point" "Check Point from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\CheckPoint" "$base\AV_EDR\Check_Point\CheckPoint_registry.reg" "Check Point"
    "[OK] Check Point Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Check Point -- $_" | Tee-Object -FilePath $log -Append
}

# 19. Webroot
try {
    $webrootLocations = @(
        "$mountPath\Program Files\Webroot\*",
        "$mountPath\Program Files (x86)\Webroot\*",
        "$mountPath\ProgramData\WRData\*",
        "$mountPath\ProgramData\WRCore\*"
    )
    foreach ($location in $webrootLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Webroot" "Webroot from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\WRData" "$base\AV_EDR\Webroot\Webroot_registry.reg" "Webroot"
    "[OK] Webroot Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Webroot -- $_" | Tee-Object -FilePath $log -Append
}

# 20. AVG
try {
    $avgLocations = @(
        "$mountPath\Program Files\AVG\*",
        "$mountPath\Program Files (x86)\AVG\*",
        "$mountPath\ProgramData\AVG\*"
    )
    foreach ($location in $avgLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\AVG" "AVG from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\AVG" "$base\AV_EDR\AVG\AVG_registry.reg" "AVG"
    "[OK] AVG Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] AVG -- $_" | Tee-Object -FilePath $log -Append
}

# 21. Avira
try {
    $aviraLocations = @(
        "$mountPath\Program Files\Avira\*",
        "$mountPath\Program Files (x86)\Avira\*",
        "$mountPath\ProgramData\Avira\*"
    )
    foreach ($location in $aviraLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Avira" "Avira from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\Avira" "$base\AV_EDR\Avira\Avira_registry.reg" "Avira"
    "[OK] Avira Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Avira -- $_" | Tee-Object -FilePath $log -Append
}

# 22. F-Secure
try {
    $fsecureLocations = @(
        "$mountPath\Program Files\F-Secure\*",
        "$mountPath\Program Files (x86)\F-Secure\*",
        "$mountPath\ProgramData\F-Secure\*"
    )
    foreach ($location in $fsecureLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\F-Secure" "F-Secure from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\Data Fellows" "$base\AV_EDR\F-Secure\FSecure_registry.reg" "F-Secure"
    "[OK] F-Secure Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] F-Secure -- $_" | Tee-Object -FilePath $log -Append
}

# 23. G Data
try {
    $gdataLocations = @(
        "$mountPath\Program Files\G Data\*",
        "$mountPath\Program Files (x86)\G Data\*",
        "$mountPath\ProgramData\G Data\*"
    )
    foreach ($location in $gdataLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\G_Data" "G Data from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\G Data" "$base\AV_EDR\G_Data\GData_registry.reg" "G Data"
    "[OK] G Data Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] G Data -- $_" | Tee-Object -FilePath $log -Append
}

# 24. Comodo
try {
    $comodoLocations = @(
        "$mountPath\Program Files\COMODO\*",
        "$mountPath\Program Files (x86)\COMODO\*",
        "$mountPath\ProgramData\COMODO\*"
    )
    foreach ($location in $comodoLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Comodo" "Comodo from $location"
        }
    }
    Try-RegExport "HKEY_LOCAL_MACHINE\SOFTWARE\COMODO" "$base\AV_EDR\Comodo\Comodo_registry.reg" "Comodo"
    "[OK] Comodo Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Comodo -- $_" | Tee-Object -FilePath $log -Append
}

# 25. VIPRE
try {
    $vipreLocations = @(
        "$mountPath\Program Files\VIPRE\*",
        "$mountPath\Program Files (x86)\VIPRE\*",
        "$mountPath\ProgramData\VIPRE\*"
    )
    foreach ($location in $vipreLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Vipre" "VIPRE from $location"
        }
    }
    reg export "HKEY_LOCAL_MACHINE\SOFTWARE\VIPRE" "$base\AV_EDR\Vipre\VIPRE_registry.reg" /y 2>$null
    "[OK] VIPRE Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] VIPRE -- $_" | Tee-Object -FilePath $log -Append
}

# ═══════════════════════ SPECIALIZED TOOLS ═══════════════════════

# Enhanced Avast Collection
try {
    $avastLocations = @(
        "$mountPath\ProgramData\AVAST Software\Avast\log\*",
        "$mountPath\Program Files\AVAST Software\*",
        "$mountPath\Program Files (x86)\AVAST Software\*",
        "$mountPath\ProgramData\AVAST Software\*"
    )
    foreach ($location in $avastLocations) {
        if (Test-Path $location -ErrorAction SilentlyContinue) {
            Try-Copy $location "$base\AV_EDR\Avast" "Avast from $location"
        }
    }
    reg export "HKEY_LOCAL_MACHINE\SOFTWARE\AVAST Software" "$base\AV_EDR\Avast\Avast_registry.reg" /y 2>$null
    "[OK] Avast Enhanced Collection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Avast Enhanced -- $_" | Tee-Object -FilePath $log -Append
}

# Generic Security Software Detection
try {
    $genericPaths = @(
        "$mountPath\Program Files\*Security*\*",
        "$mountPath\Program Files\*Antivirus*\*",
        "$mountPath\Program Files\*Anti-Virus*\*",
        "$mountPath\Program Files\*Endpoint*\*",
        "$mountPath\Program Files\*Protection*\*",
        "$mountPath\Program Files (x86)\*Security*\*",
        "$mountPath\Program Files (x86)\*Antivirus*\*",
        "$mountPath\Program Files (x86)\*Anti-Virus*\*",
        "$mountPath\Program Files (x86)\*Endpoint*\*",
        "$mountPath\Program Files (x86)\*Protection*\*"
    )
    $genericFolder = "$base\AV_EDR\Generic_Security"
    New-Item -ItemType Directory -Path $genericFolder -Force | Out-Null
    foreach ($path in $genericPaths) {
        $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            $safeName = ($item.Name -replace '[^\w\-_\.]', '_')
            Try-Copy $item.FullName "$genericFolder\$safeName" "Generic security software: $($item.Name)"
        }
    }
    "[OK] Generic Security Software Detection" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Generic Security Detection -- $_" | Tee-Object -FilePath $log -Append
}

# Scheduled Tasks Summary
try {
    Get-ScheduledTask | Format-Table TaskName, TaskPath, State, Actions -AutoSize | Out-File "$base\ScheduledTasks\tasks_summary.txt" -Encoding UTF8
    "[OK] Scheduled Tasks (summary)" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Scheduled Tasks summary -- $_" | Tee-Object -FilePath $log -Append
}

# Scheduled Tasks Detailed
try {
    $tasks = Get-ScheduledTask
    $allDetails = foreach ($task in $tasks) {
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            TaskName    = "$($task.TaskPath)$($task.TaskName)"
            State       = $info.State
            LastRun     = $info.LastRunTime
            NextRun     = $info.NextRunTime
            LastResult  = $info.LastTaskResult
            Author      = $task.Principal.UserId
            Action      = ($task.Actions | ForEach-Object { $_.Execute }) -join "; "
        }
    }
    $allDetails | Format-Table -AutoSize | Out-String | Out-File "$base\ScheduledTasks\tasks_detailed.txt" -Encoding UTF8
    "[OK] Scheduled Tasks (detailed)" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Scheduled Tasks (detailed) -- $_" | Tee-Object -FilePath $log -Append
}

# Network info
try {
    arp -a | Out-File "$base\Network\arp.txt"
    ipconfig /displaydns | Out-File "$base\Network\dns_cache.txt"
    netstat -ano | Out-File "$base\Network\netstat.txt"
    "[OK] Network info" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Network info -- $_" | Tee-Object -FilePath $log -Append
}

# USN Journal Collection
# $usnOut = "$base\USNJournal\usn_output.txt"
# New-Item -ItemType Directory -Path "$base\USNJournal" -Force | Out-Null
# try {
#     fsutil usn readjournal C: > $usnOut 2>&1
#     "[OK] USN Journal collected" | Tee-Object -FilePath $log -Append
# } catch {
#     "[FAIL] USN Journal -- $_" | Tee-Object -FilePath $log -Append
# }

# ─── Additional Artifact Collection ──────────────────────────────────────────

# 1. Alternate Data Streams (ADS)
$adsOut = Join-Path $base "ADS"
New-Item -Path $adsOut -ItemType Directory -Force | Out-Null
& streams.exe -s "$mountPath\*.*" > "$adsOut\ads_list.txt"

# 2. Recycle Bin metadata
Try-Copy "$mountPath\$Recycle.Bin\*"              "$base\RecycleBin"     "Recycle Bin contents"

# 3. Windows Search DB
Try-Copy "$mountPath\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" `
         "$base\SearchDB"                         "Windows Search DB"

# 4. LNK files & Jump Lists
$users = Get-ChildItem "$mountPath\Users" -Directory | Where Name -notin 'Public','Default*'
foreach ($u in $users) {
  $home = $u.FullName
  Try-Copy "$home\AppData\Roaming\Microsoft\Windows\Recent\*.lnk"                   "$base\LNK"           "LNKs for $($u.Name)"
  Try-Copy "$home\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*"  "$base\JumpLists\AutoDest"    "AutoDest for $($u.Name)"
  Try-Copy "$home\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*"     "$base\JumpLists\CustomDest"  "CustomDest for $($u.Name)"
}

# 5. pagefile & hibernation file
Try-Copy "$mountPath\pagefile.sys"               "$base\Pagefile"       "pagefile.sys"
Try-Copy "$mountPath\hiberfil.sys"               "$base\Hiberfile"      "hiberfil.sys"

# 6. DPAPI & Credential Manager vaults
foreach ($u in $users) {
  $home = $u.FullName
  $pp = "$home\AppData\Roaming\Microsoft\Protect\*"
  Try-Copy $pp                                               "$base\DPAPI"     "DPAPI keys for $($u.Name)"
  Try-Copy "$home\AppData\Roaming\Microsoft\Vault\*"         "$base\Vault"     "Credential Vault for $($u.Name)"
}

# 7. Cached domain secrets (NL$KM)
Try-Copy "$mountPath\Windows\System32\config\NL$KM"         "$base\NLKM"       "NL$KM"

# 8. Certificate stores (text export)
New-Item "$base\Certificates" -ItemType Directory -Force | Out-Null
certutil -store My         > "$base\Certificates\Local_My.txt"
certutil -user -store My   > "$base\Certificates\User_My.txt"

# 9. BITS jobs
bitsadmin /listallusers    > "$base\BITS\bits_jobs.txt"

# 10. ShellBags (registry exports)
New-Item "$base\ShellBags" -ItemType Directory -Force | Out-Null
foreach ($u in $users) {
  reg load HKU\TempHive "$u.FullName\NTUSER.DAT"
  reg export HKU\TempHive\Software\Microsoft\Windows\Shell\BagMRU `
             "$base\ShellBags\BagMRU_$($u.Name).reg"
  reg export HKU\TempHive\Software\Microsoft\Windows\Shell\Bags `
             "$base\ShellBags\Bags_$($u.Name).reg"
  reg unload HKU\TempHive
}

# 11. Routing table, WLAN & Firewall
route print                                                 > "$base\Network\routing_table.txt"
netsh wlan show profiles key=clear                           > "$base\Wireless\wlan_profiles.txt"
Try-Copy "$mountPath\Windows\System32\LogFiles\Firewall\*"   "$base\FirewallLogs" "Firewall logs"

# 12. Browser artifacts
New-Item "$base\Browser" -ItemType Directory -Force | Out-Null
Try-Copy "$mountPath\Users\*\AppData\Local\Google\Chrome\User Data\Default\History" `
         "$base\Browser\Chrome"                              "Chrome History"
# …repeat for Cookies, Cache, and for Firefox & Edge paths…

# 13. Cloud-sync logs
Try-Copy "$mountPath\Users\*\AppData\Local\Google\Drive\*"           "$base\GoogleDrive" "Google Drive"
Try-Copy "$mountPath\Users\*\OneDrive\*"                             "$base\OneDrive\Sync"
Try-Copy "$mountPath\Users\*\AppData\Local\Microsoft\OneDrive\logs\*" "$base\OneDrive\Logs"

# 14. WMI Repository & MOF files
Try-Copy "$mountPath\Windows\System32\wbem\Repository\OBJECTS.DATA"  "$base\WMI\Repository"
Try-Copy "$mountPath\Windows\System32\wbem\*.mof"                    "$base\WMI\MOF"

# 15. PowerShell history
Try-Copy "$mountPath\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*" `
         "$base\PowerShell"                                        "PSReadLine history"

# 16. SRUM DB & Timeline
Try-Copy "$mountPath\Windows\System32\sru\SRUDB.dat"                "$base\SRUM"        "SRUM DB"
Try-Copy "$mountPath\Users\*\AppData\Local\ConnectedDevicesPlatform\*" `
         "$base\Timeline"                                         "Windows Timeline"

# 17. Thumbcache & IconCache
Try-Copy "$mountPath\Users\*\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db" `
         "$base\Thumbcache"                                       "Thumbnail caches"
Try-Copy "$mountPath\Users\*\AppData\Local\IconCache.db"           "$base\IconCache"  "IconCache"

# 18. Crash dumps & WER
Try-Copy "$mountPath\Windows\Minidump\*.dmp"                        "$base\CrashDumps" "Minidumps"
Try-Copy "$mountPath\Users\*\AppData\Local\CrashDumps\*"           "$base\CrashDumps" "User CrashDumps"
Try-Copy "$mountPath\Users\*\AppData\Local\Microsoft\Windows\WER\*" `
         "$base\WER"                                               "WER reports"

# ───────────────────────────────────────────────────────────────────────────────

# Cleanup mount
try {
    Remove-Item -Path $mountPath -Force -ErrorAction Stop
    "[OK] Shadow copy mount cleaned up" | Tee-Object -FilePath $log -Append
} catch {
    "[FAIL] Shadow copy cleanup -- $_" | Tee-Object -FilePath $log -Append
}

 
# ──────────────── Run the analysis script ────────────────
$analysisScript = Join-Path $PSScriptRoot 'analyse_artifacts.ps1'
if (Test-Path $analysisScript) {
    $scriptDir   = Split-Path -Parent $analysisScript
    $toolsPath   = Join-Path $scriptDir 'Tools'
    $parsedPath  = Join-Path $scriptDir 'Logs_Parsed_Output'

    Write-Host "`n🧩 Running analysis script:`n  Path: $analysisScript`n  -IR     $base`n  -Tools  $toolsPath`n  -Parsed $parsedPath`n"
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File  "`"$analysisScript`"" `
            -IR    "`"$base`"" `
            -Tools "`"$toolsPath`"" `
            -Parsed "`"$parsedPath`""
        Write-Host "`n✅ analyse_artifacts.ps1 completed successfully.`n"
    } catch {
        Write-Host "`n❌ analyse_artifacts.ps1 failed: $_`n"
    }
} else {
    Write-Host "`n⚠️  Could not find analyse_artifacts.ps1 at $analysisScript`n"
}
