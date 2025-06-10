# Acquirelyzer

**Acquirelyzer** is a lean, script-based incident-response toolkit for Windows endpoints that were (or may be) compromised by the **Nemesis** Remote-Access Trojan or other malware threats.

It automates two high-leverage phases of your incident response workflow:

| Phase | Script | Purpose |
|-------|--------|---------|
| **Collection** | `collect_IR.ps1` | Safely extracts forensic artefacts from a live or mounted disk snapshot (using VSS). |
| **Analysis**   | `analyse_artifacts.ps1` | Parses & correlates artefacts to reconstruct an infection timeline, discover persistence, and surface IoCs. |

> ⚠️ **Run on copies, not originals.** Always work on a mounted shadow copy or disk image to preserve evidence integrity.

---

## 🚀 Features

### Collection Capabilities
* **Shadow copy creation & clean un-mount** (no third-party drivers required)
* **Comprehensive artefact extraction** including:
  - Prefetch files (`*.pf`)
  - Amcache registry hive
  - ShimCache (Application Compatibility Cache)
  - Windows Event logs (EVTX)
  - EDR/AV logs
  - USN Journal entries
  - ShellBags registry data
  - BITS (Background Intelligent Transfer Service) jobs
  - Memory dumps (pagefile.sys, hiberfil.sys)
  - Cloud sync logs (OneDrive, Google Drive)
  - Browser history and downloads
  - Scheduled tasks
  - Services registry data

### Analysis Capabilities
* **Timeline reconstruction** from multiple artifact sources
* **IOC hunting** 
* **Persistence mechanism detection** (Registry Run keys, Scheduled Tasks, Services)
* **Network activity correlation** from multiple log sources
* **Best-of-breed open-source tooling** integration:
  - PECmd (Prefetch analysis)
  - AmcacheParser (Program execution tracking)
  - Chainsaw (Event log analysis)
  - APT-Hunter (Threat hunting)
  - And more...

---

## 📋 Prerequisites

### Required Third-Party Tools

Download and place the following tools in the `.\Tools\` directory:

| Tool | Version | Purpose | Download Link |
|------|---------|---------|---------------|
| **PECmd.exe** | Latest | Prefetch analysis | [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md) |
| **AmcacheParser.exe** | Latest | Amcache parsing | [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md) |
| **chainsaw.exe** | v2.0+ | Event log hunting | [Chainsaw Releases](https://github.com/WithSecureLabs/chainsaw/releases) |
| **APT-Hunter.exe** | Latest| Event log hunting | [APT-Hunter Releases]([https://github.com/WithSecureLabs/chainsaw/releases](https://github.com/ahmedkhlief/APT-Hunter)) |

---

### Directory Structure
```
Acquirelyzer/
├── collect_IR.ps1           # Main collection script
├── analyse_artifacts.ps1    # Analysis and correlation script
├── Tools/                   # Third-party forensic tools
│   ├── PECmd.exe
│   ├── AmcacheParser.exe
│   ├── APT-Hunter.exe
│   └── Chainsaw/
│     ├── chainsaw.exe
└── Output/                 # Default output directory
```

---

## 🚀 Quick Start

### Basic Usage
```powershell
# Collection phase - extract artifacts from target system
.\collect_IR.ps1
```
---
## 🔍 Detection Capabilities

### Generic Malware Detection
- Suspicious process execution patterns
- Unusual network connections
- Registry modifications
- File system changes
- Service installations
- Scheduled task creation

---
### Collection Output
```
Output/
├── Artifacts/
│   ├── Prefetch/           # .pf files
│   ├── Registry/           # Registry hives
│   ├── EventLogs/          # .evtx files
│   ├── Memory/             # Memory dumps
│   └── Filesystem/         # File listings, USN journal
├── Logs/
     └── collection.log      # Detailed collection log
```
### Common Issues

**Issue**: "Access Denied" errors during collection
**Solution**: Ensure you're running as Administrator and the target drive is accessible

**Issue**: VSS creation fails
**Solution**: Check available disk space (need ~20% free) and ensure VSS service is running

**Issue**: Third-party tools not found
**Solution**: Verify all required tools are in the `.\Tools\` directory with correct filenames

**Issue**: PowerShell execution policy errors
**Solution**: Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

---

## 🙏 Acknowledgments

- **Eric Zimmerman** for the excellent forensic tools suite
- **WithSecure Labs** for Chainsaw
- **ahmedkhlief** for APT-Hunter

---

