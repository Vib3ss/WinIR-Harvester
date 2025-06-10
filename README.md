# WinIR-Harvester

**WinIR-Harvester** is a comprehensive, script-based incident response toolkit for Windows endpoints that automates forensic artifact collection and analysis. Designed for investigating compromised systems, particularly those affected by Remote Access Trojans (RATs) and other malware threats.

It automates two critical phases of your incident response workflow:

| Phase | Script | Purpose |
|-------|--------|---------|
| **Collection** | `collect_IR.ps1` | Safely extracts comprehensive forensic artifacts from a live system using VSS snapshots |
| **Analysis**   | `analyse_artifacts.ps1` | Parses & correlates artifacts to reconstruct infection timelines and surface IoCs |

> ⚠️ **Run on copies, not originals.** The collection script automatically creates and works from VSS shadow copies to preserve evidence integrity.

---

## 🚀 Features

### Advanced Collection Capabilities
* **Automated shadow copy creation & cleanup** (no third-party drivers required)
* **Comprehensive artifact extraction** including:
  - **System artifacts**: Prefetch files, Amcache, Registry hives (SYSTEM, SOFTWARE, SAM, SECURITY)
  - **Event logs**: All Windows Event logs (EVTX format)
  - **Memory artifacts**: Pagefile.sys, Hiberfil.sys, crash dumps
  - **Network artifacts**: ARP cache, DNS cache, routing tables, WLAN profiles, firewall logs
  - **User artifacts**: Browser history, PowerShell history, LNK files, Jump Lists
  - **Filesystem artifacts**: USN Journal, Recycle Bin, Alternate Data Streams (ADS)
  - **Security artifacts**: DPAPI keys, credential vaults, certificates, SRUM database
  - **Cloud sync artifacts**: OneDrive, Google Drive logs and data
  - **Persistence artifacts**: Scheduled tasks, services, startup programs
  - **Additional forensics**: Thumbcache, IconCache, Windows Timeline, WER reports

### Extensive AV/EDR Log Collection
* **25+ security solutions supported**, including:
  - **Enterprise EDR**: CrowdStrike Falcon, Carbon Black, SentinelOne, Cylance, Palo Alto Cortex
  - **Major AV vendors**: Symantec, McAfee, Trend Micro, Kaspersky, Bitdefender, ESET
  - **Specialized tools**: Sophos, Malwarebytes, Windows Defender, Fortinet, Check Point
  - **Generic detection**: Automatically discovers unknown security software

### Analysis Capabilities
* **Timeline reconstruction** from multiple artifact sources
* **IoC hunting** across collected artifacts
* **Persistence mechanism detection** (Registry Run keys, Scheduled Tasks, Services)
* **Network activity correlation** from multiple log sources
* **Best-of-breed open-source tooling** integration:
  - PECmd (Prefetch analysis)
  - AmcacheParser (Program execution tracking)
  - Chainsaw (Event log analysis)
  - APT-Hunter (Threat hunting)

---

## 📋 Prerequisites

### Required Third-Party Tools

Download and place the following tools in the `.\Tools\` directory:

| Tool | Version | Purpose | Download Link |
|------|---------|---------|---------------|
| **PECmd.exe** | Latest | Prefetch analysis | [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md) |
| **AmcacheParser.exe** | Latest | Amcache parsing | [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md) |
| **chainsaw.exe** | v2.0+ | Event log hunting | [Chainsaw Releases](https://github.com/WithSecureLabs/chainsaw/releases) |
| **APT-Hunter.exe** | Latest | Event log hunting | [APT-Hunter Releases](https://github.com/ahmedkhlief/APT-Hunter) |

### System Requirements
- **Administrator privileges** (script auto-elevates)
- **PowerShell 5.0+** 
- **Sufficient disk space** (~20% free space on target drive for VSS)
- **VSS service running** (automatically checked)

---

## 📁 Directory Structure
```
Acquirelyzer/
├── collect_IR.ps1              # Main collection script
├── analyse_artifacts.ps1       # Analysis and correlation script
├── Tools/                      # Third-party forensic tools
│   ├── PECmd.exe
│   ├── AmcacheParser.exe
│   ├── APT-Hunter.exe
│   └── chainsaw.exe
└── Output/                     # Default output directory
    └── C:\IR\                  # Actual collection output path
```

---

## 🚀 Quick Start

### Basic Usage
```powershell
# Collection phase - extract artifacts from target system
.\collect_IR.ps1

# The script will:
# 1. Auto-elevate to Administrator if needed
# 2. Create a VSS shadow copy of C:\ drive
# 3. Extract all artifacts to C:\IR\
# 4. Automatically run analyse_artifacts.ps1 if present
# 5. Clean up the shadow copy mount
```

### Advanced Usage
```powershell
# Manual analysis (if needed)
.\analyse_artifacts.ps1 -IR "C:\IR" -Tools ".\Tools" -Parsed ".\Logs_Parsed_Output"
```

---

## 📊 Collection Output Structure

The script creates a comprehensive artifact collection in `C:\IR\` with the following structure:

```
C:\IR/
├── AV_EDR/                     # Security software logs (25+ vendors)
│   ├── CrowdStrike/
│   ├── CarbonBlack/
│   ├── SentinelOne/
│   ├── WindowsDefender/
│   └── [20+ other vendors]/
├── Prefetch/                   # Windows Prefetch files (.pf)
├── Amcache/                    # Amcache.hve registry hive
├── Registry/                   # Core registry hives
│   ├── SYSTEM.hiv
│   ├── SOFTWARE.hiv
│   ├── SAM.hiv
│   └── SECURITY.hiv
├── EventLogs/                  # Windows Event logs (.evtx)
├── ScheduledTasks/             # Task scheduler information
├── Network/                    # Network configuration & logs
│   ├── arp.txt
│   ├── dns_cache.txt
│   ├── netstat.txt
│   └── routing_table.txt
├── Browser/                    # Browser artifacts
│   └── Chrome/
├── PowerShell/                 # PowerShell execution history
├── LNK/                        # Link files
├── JumpLists/                  # Jump list artifacts
│   ├── AutoDest/
│   └── CustomDest/
├── DPAPI/                      # DPAPI master keys
├── Certificates/               # Certificate stores
├── SRUM/                       # System Resource Usage Monitor
├── Timeline/                   # Windows Timeline database
├── CrashDumps/                 # System crash dumps
├── WER/                        # Windows Error Reporting
├── Pagefile/                   # pagefile.sys
├── Hiberfile/                  # hiberfil.sys
├── RecycleBin/                 # Recycle bin contents
├── OneDrive/                   # OneDrive sync artifacts
├── GoogleDrive/                # Google Drive artifacts
├── WMI/                        # WMI repository & MOF files
├── FirewallLogs/               # Windows Firewall logs
├── Wireless/                   # WLAN profiles
├── Thumbcache/                 # Thumbnail caches
├── IconCache/                  # Icon cache
├── ADS/                        # Alternate Data Streams
├── collection_log.txt          # Detailed collection log
└── debug_output.txt            # Debug information
```

---

## 🔍 Detection Capabilities

### Malware Persistence Detection
- **Registry Run keys** (HKLM/HKCU Software\Microsoft\Windows\CurrentVersion\Run)
- **Scheduled Tasks** (detailed enumeration with execution history)
- **Windows Services** (service registry analysis)
- **Startup folders** and autostart locations
- **WMI persistence** (MOF files and repository)

### Execution Artifacts
- **Prefetch analysis** (program execution evidence)
- **Amcache parsing** (comprehensive program installation/execution tracking)
- **ShimCache** (Application Compatibility Cache)
- **BAM/DAM** (Background Activity Moderator)
- **SRUM database** (System Resource Usage Monitor)

### Network Activity
- **DNS cache** (recent DNS resolutions)
- **ARP cache** (recent network communications)
- **Network connections** (active and recent)
- **Firewall logs** (blocked/allowed connections)
- **WLAN profiles** (wireless network history)

### File System Artifacts
- **USN Journal** (file system change log)
- **Link files** (LNK files showing recently accessed files)
- **Jump Lists** (application-specific recent files)
- **Alternate Data Streams** (hidden file content)
- **Recycle Bin** (deleted file metadata)

### User Activity
- **Browser history** (Chrome, Firefox, Edge)
- **PowerShell history** (command execution history)
- **Windows Timeline** (cross-device activity)
- **Thumbcache** (thumbnail evidence of viewed images)

---

## 🛠️ Advanced Features

### Automatic Shadow Copy Management
- **Safe artifact extraction** without modifying the live system
- **Automated cleanup** of shadow copies after collection
- **Error handling** for insufficient disk space or VSS failures

### Comprehensive Registry Analysis
- **Live registry exports** for persistence analysis
- **Offline registry hive collection** for detailed analysis
- **ShellBags** (folder access history)
- **DPAPI master keys** for decryption capabilities

### Multi-Vendor Security Software Support
- **Automatic detection** of installed security solutions
- **Comprehensive log collection** from 25+ vendors
- **Registry configuration backup** for each detected solution
- **Generic detection** for unknown security software

---

## 🚨 Common Issues & Solutions

### Collection Issues

**Issue**: "Access Denied" errors during collection  
**Solution**: Ensure script is running as Administrator (it auto-elevates)

**Issue**: VSS creation fails  
**Solution**: 
- Check available disk space (need ~20% free space)
- Ensure Volume Shadow Copy service is running: `net start vss`
- Verify no other backup operations are in progress

**Issue**: Third-party tools not found  
**Solution**: Verify all required tools are in `.\Tools\` directory with correct filenames

**Issue**: PowerShell execution policy errors  
**Solution**: Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

### Analysis Issues

**Issue**: Analysis script fails to run automatically  
**Solution**: Ensure `analyse_artifacts.ps1` is in the same directory as `collect_IR.ps1`

**Issue**: Parsing tools crash or fail  
**Solution**: 
- Verify tool versions are compatible
- Check for corrupted artifact files
- Review debug output in `debug_output.txt`

---

## 📝 Logging & Output

### Collection Logging
- **collection_log.txt**: Detailed log of all collection activities
- **debug_output.txt**: Debug information and error details
- **Console output**: Real-time progress and status updates

### Analysis Output
- **Parsed artifacts**: Structured output from analysis tools
- **Timeline reconstruction**: Chronological view of system activity
- **IoC reports**: Identified indicators of compromise
- **Summary reports**: High-level findings and recommendations

---

## 🙏 Acknowledgments

- **Eric Zimmerman** for the excellent forensic tools suite (KAPE, PECmd, AmcacheParser)
- **WithSecure Labs** for Chainsaw event log analysis tool
- **Ahmed Khlief** for APT-Hunter threat hunting capabilities

---

## 🤝 Contributing

Contributions are welcome! Please consider:
- Additional security software detection capabilities
- New artifact collection modules
- Analysis and correlation improvements
- Bug fixes and performance optimizations

---
