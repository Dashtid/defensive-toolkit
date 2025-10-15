# Digital Forensics & Memory Analysis

Comprehensive digital forensics toolkit for collecting, analyzing, and preserving evidence during security incidents and investigations.

## Overview

This forensics toolkit provides automated tools for:
- **Memory Analysis**: Malware hunting in memory dumps using Volatility 3
- **Disk Forensics**: MFT parsing, file carving, and disk image analysis
- **Artifact Collection**: Registry, browser history, and persistence mechanism extraction
- **Timeline Generation**: Creating and analyzing forensic timelines from multiple sources

All tools follow forensic best practices including evidence preservation, chain of custody, and proper documentation.

## Quick Start

### Memory Analysis

```bash
# Analyze memory dump with Volatility 3 (quick triage)
python memory/volatility-auto-analyze.py memory.dmp --quick --output analysis/

# Full comprehensive analysis
python memory/volatility-auto-analyze.py memory.dmp --output analysis/

# Hunt for malware in memory dump
python memory/hunt-malware.py memory.dmp --output malware_findings/

# With IOC file
python memory/hunt-malware.py memory.dmp --iocs threat_intel.txt --output findings/
```

### Disk Forensics

```bash
# Parse Windows MFT (Master File Table)
python disk/extract-mft.py --mft $MFT --output mft_analysis/

# Generate timeline from MFT
python disk/extract-mft.py --mft $MFT --timeline timeline.csv --output analysis/

# File carving from disk image
python disk/carve-files.py --image disk.dd --output carved_files/

# Carve specific file types
python disk/carve-files.py --image disk.dd --types jpg,pdf,doc --output evidence/
```

### Artifact Collection

```powershell
# Extract Windows registry artifacts
.\artifacts\registry\extract-registry-artifacts.ps1 -OutputDir evidence\registry

# Hunt for persistence mechanisms
.\artifacts\persistence\hunt-persistence.ps1 -OutputDir evidence\persistence

# Deep scan for persistence
.\artifacts\persistence\hunt-persistence.ps1 -OutputDir evidence\persistence -DeepScan
```

```bash
# Extract browser history (Chrome, Edge, Firefox)
python artifacts/browser/extract-browser-history.py --user-profile C:\Users\John --output browser_evidence/

# Extract specific browser
python artifacts/browser/extract-browser-history.py --user-profile C:\Users\John --browser chrome --output evidence/
```

### Timeline Generation

```bash
# Generate timeline with plaso/log2timeline
python timeline/generate-timeline.py --source /evidence --output timeline.csv

# Merge multiple timeline files
python timeline/generate-timeline.py --merge file1.csv file2.csv file3.json --output merged_timeline.csv

# Analyze timeline for patterns
python timeline/analyze-timeline.py --timeline timeline.csv --output analysis/ --detect-anomalies

# Custom analysis parameters
python timeline/analyze-timeline.py --timeline timeline.csv --output analysis/ \
    --spike-window 30 \
    --gap-threshold 180 \
    --correlation-window 600
```

## Directory Structure

```
forensics/
├── memory/                     # Memory analysis tools
│   ├── volatility-auto-analyze.py   # Automated Volatility 3 analysis
│   └── hunt-malware.py               # Memory-based malware hunting
├── disk/                       # Disk forensics tools
│   ├── extract-mft.py                # MFT parser and analyzer
│   └── carve-files.py                # File carving automation
├── artifacts/                  # Artifact collectors
│   ├── registry/                     # Windows registry extraction
│   │   └── extract-registry-artifacts.ps1
│   ├── browser/                      # Browser history extraction
│   │   └── extract-browser-history.py
│   └── persistence/                  # Persistence mechanism hunting
│       └── hunt-persistence.ps1
├── timeline/                   # Timeline tools
│   ├── generate-timeline.py         # Timeline generation
│   └── analyze-timeline.py          # Timeline analysis
└── tools/                      # Helper scripts and utilities
```

## Tool Documentation

### Memory Analysis

#### volatility-auto-analyze.py

Automates Volatility 3 memory analysis with three modes:

**Quick Mode** (5-10 minutes):
- System information
- Process list and tree
- Network connections
- Command lines

**Full Mode** (30-60 minutes):
- All quick mode plugins
- DLL and driver analysis
- Registry analysis
- File system scanning
- Malware detection (malfind, ldrmodules)
- Timeline generation

**Malware Hunt Mode**:
- Focused malware detection
- Process analysis (pslist, psscan)
- DLL analysis
- Network artifact extraction
- Service enumeration
- Automated indicator analysis

**Requirements**:
- Volatility 3 (pip install volatility3)
- Python 3.8+

**Output**:
- Individual plugin outputs (TXT format)
- Summary report (JSON + TXT)
- Suspicious findings with severity ratings

#### hunt-malware.py

Automated malware hunting in memory dumps using heuristics and IOCs.

**Detection Methods**:
1. **Suspicious Processes**: Known malware indicators (cmd.exe, powershell.exe with unusual parents)
2. **Code Injection**: Detects injected code via malfind
3. **Network Connections**: Suspicious ports and IOC matching
4. **Hidden Processes**: Compares pslist vs psscan for unlinked processes
5. **Suspicious DLLs**: Unlinked DLLs and IOC matching
6. **Persistence Mechanisms**: Registry run keys in suspicious locations

**IOC Format** (text file, one per line):
```
malware.exe
badprocess.dll
192.168.1.100
malicious-domain.com
```

**Output**:
- JSON report with findings grouped by severity
- Detailed finding descriptions
- Evidence references

### Disk Forensics

#### extract-mft.py

Parses Windows NTFS Master File Table for forensic analysis.

**Capabilities**:
- Extracts all file metadata (timestamps, size, attributes)
- Identifies suspicious files (executables in temp locations, hidden files)
- Generates timeline of file activity
- Groups findings by severity

**Suspicious File Indicators**:
- Executables in: temp, appdata, programdata, public folders
- Hidden executables
- Recently created executables

**Requirements**:
- analyzeMFT (pip install analyzeMFT)
- Python 3.8+

#### carve-files.py

Automated file carving from disk images using bulk_extractor and foremost.

**Tools Supported**:
- bulk_extractor: Comprehensive data extraction
- foremost: Targeted file type carving

**File Types**: jpg, png, gif, pdf, doc, docx, xls, xlsx, zip, rar, exe, dll

**Requirements**:
- bulk_extractor (apt install bulk-extractor)
- foremost (apt install foremost)

**Output**:
- Carved files organized by tool and type
- Statistics (file count, types, sizes)
- JSON report with file inventory

### Artifact Collection

#### extract-registry-artifacts.ps1

Extracts forensic artifacts from Windows Registry.

**Artifacts Collected**:
- UserAssist (program execution tracking)
- RecentDocs (recently opened files)
- USB device history
- Network connection history
- Autorun locations (Run, RunOnce keys)
- Installed software inventory
- System and network configuration

**Modes**:
- Live system (default)
- Offline registry hives (with -Offline flag)

**Output**:
- JSON files for each artifact type
- Extraction report with statistics

#### hunt-persistence.ps1

Hunts for malware persistence mechanisms on Windows systems.

**Detection Areas**:
1. **Registry Run Keys**: All variants including WOW6432Node
2. **Scheduled Tasks**: Suspicious executables and arguments
3. **Services**: Unusual paths and unsigned binaries
4. **WMI Event Subscriptions**: Event filters and consumers
5. **Startup Folders**: User and system-wide
6. **IFEO Debuggers**: Image File Execution Options hijacking
7. **AppInit DLLs**: DLL injection via AppInit
8. **Winlogon Helpers**: Shell, Userinit, Notify modifications

**Severity Levels**:
- High: Active threats (WMI subscriptions, IFEO debuggers)
- Medium: Unusual but potentially legitimate (startup folders)
- Low: Informational findings

**Output**:
- JSON report with all findings
- CSV for easy analysis
- Colored console output

#### extract-browser-history.py

Extracts forensic artifacts from web browsers.

**Browsers Supported**:
- Google Chrome
- Microsoft Edge
- Mozilla Firefox

**Artifacts Extracted**:
- Browsing history (URLs, titles, visit counts, timestamps)
- Download history (files, sources, timestamps)
- Cookies (domains, paths, expiration)
- Autofill data (where available)

**Requirements**:
- Python 3.8+
- sqlite3 (built-in)

**Output**:
- JSON files per browser
- Summary report
- Timestamps in ISO format

### Timeline Analysis

#### generate-timeline.py

Generates forensic timelines from multiple sources using plaso/log2timeline.

**Modes**:
1. **Generate with plaso**: Process evidence source with log2timeline
2. **Export plaso file**: Convert existing plaso database to CSV
3. **Merge timelines**: Combine multiple timeline files (CSV/JSON)

**Supported Formats**:
- Input: plaso, CSV, JSON
- Output: CSV (l2tcsv format)

**Timeline Sources**:
- Windows Event Logs (EVTX)
- Registry hives
- File system metadata
- Browser history
- Custom sources

**Requirements**:
- plaso/log2timeline (pip install plaso) - optional
- Python 3.8+

#### analyze-timeline.py

Analyzes forensic timelines for suspicious patterns and anomalies.

**Analysis Techniques**:
1. **Activity Spikes**: Statistical detection of unusual event volumes
2. **Timeline Gaps**: Identifies suspicious gaps (potential log deletion)
3. **Event Correlation**: Finds related events within time windows
4. **Off-Hours Activity**: Detects activity outside work hours
5. **Temporal Patterns**: Hourly/daily/weekly distribution analysis

**Suspicious Patterns Detected**:
- powershell + network activity
- download + execution sequences
- credential access + network activity
- file_creation + process_creation
- registry_modification + persistence

**Configuration**:
- `--spike-window`: Activity spike detection window (minutes, default: 60)
- `--gap-threshold`: Minimum gap to report (minutes, default: 120)
- `--correlation-window`: Event correlation window (seconds, default: 300)

**Output**:
- Findings grouped by severity (critical/high/medium)
- Temporal pattern analysis (JSON)
- Detailed finding descriptions

## Integration with Incident Response

These forensics tools integrate with the incident response playbooks:

### Ransomware Response

**Phase 2 - Evidence Collection**:
```powershell
# Memory analysis
.\DumpIt.exe /O memory.raw
python forensics\memory\hunt-malware.py memory.raw --output analysis\memory

# Registry artifacts
.\forensics\artifacts\registry\extract-registry-artifacts.ps1 -OutputDir evidence\registry

# Persistence hunting
.\forensics\artifacts\persistence\hunt-persistence.ps1 -OutputDir evidence\persistence
```

**Phase 2 - Timeline Development**:
```bash
# Generate comprehensive timeline
python forensics\timeline\generate-timeline.py --source evidence --output timeline.csv

# Analyze for suspicious patterns
python forensics\timeline\analyze-timeline.py --timeline timeline.csv --output analysis --detect-anomalies
```

### Malware Infection Response

**Phase 2 - Preserve Evidence**:
```powershell
# Memory dump and analysis
.\DumpIt.exe /O memory.raw
python forensics\memory\hunt-malware.py memory.raw --output memory_analysis

# Persistence hunting
.\forensics\artifacts\persistence\hunt-persistence.ps1 -OutputDir evidence\persistence

# Registry artifacts
.\forensics\artifacts\registry\extract-registry-artifacts.ps1 -OutputDir evidence\registry
```

**Phase 3 - Investigation**:
```bash
# Browser history (if web-based infection)
python forensics\artifacts\browser\extract-browser-history.py --user-profile C:\Users\target_user --output browser_evidence
```

See `../incident-response/playbooks/` for complete integration examples.

## Best Practices

### Evidence Preservation

1. **Always work on copies**, never on original evidence
2. **Document chain of custody** for all evidence collected
3. **Use write-blockers** when imaging disks
4. **Hash evidence** before and after analysis (MD5, SHA-256)
5. **Maintain detailed logs** of all actions taken

### Analysis Workflow

```
1. Acquire Evidence
   ├─ Memory dump (volatile data first)
   ├─ Disk image
   └─ Live system artifacts

2. Preserve Evidence
   ├─ Hash all evidence files
   ├─ Create working copies
   └─ Document acquisition

3. Analyze Evidence
   ├─ Memory analysis (malware, processes, network)
   ├─ Disk analysis (MFT, deleted files, carved data)
   ├─ Artifact extraction (registry, browser, persistence)
   └─ Timeline generation and correlation

4. Document Findings
   ├─ Detailed technical report
   ├─ Timeline of events
   ├─ IOCs identified
   └─ Recommendations

5. Present Results
   ├─ Executive summary
   ├─ Technical details
   └─ Evidence references
```

### Legal and Compliance Considerations

- **Admissibility**: Follow forensically sound procedures
- **Privacy**: Handle personal data appropriately
- **Retention**: Maintain evidence per legal requirements
- **Documentation**: Detailed notes for court testimony

## Performance Considerations

### Memory Analysis
- **Quick mode**: 5-10 minutes (small dumps < 4GB)
- **Full mode**: 30-60 minutes (depends on dump size)
- **Malware hunt**: 10-20 minutes

### Disk Forensics
- **MFT parsing**: 2-10 minutes (depends on filesystem size)
- **File carving**: 30 minutes to several hours (depends on image size)

### Timeline Generation
- **plaso processing**: 1-4 hours (depends on evidence size)
- **Timeline analysis**: 5-15 minutes (depends on timeline size)

### Resource Requirements

**Minimum**:
- CPU: 4 cores
- RAM: 8GB
- Disk: 100GB free space

**Recommended**:
- CPU: 8+ cores
- RAM: 16-32GB
- Disk: 500GB+ SSD

## Troubleshooting

### Volatility 3 Issues

**Problem**: Plugin not found
```bash
# List available plugins
vol -f memory.dmp windows.info.Info
```

**Problem**: Symbol file errors
```bash
# Download symbols
python -m volatility3.framework.automagic.symbol_cache
```

### plaso/log2timeline Issues

**Problem**: Slow processing
```bash
# Use targeted parsers instead of all
log2timeline.py --parsers "evtx,prefetch,mft" timeline.plaso evidence/
```

**Problem**: Out of memory
```bash
# Process in chunks or use storage-based processing
log2timeline.py --storage-file timeline.plaso --single-process evidence/
```

### Permission Issues (Windows)

```powershell
# Run PowerShell scripts as Administrator
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\script.ps1
```

## Additional Resources

### Documentation
- Volatility 3 Documentation: https://volatility3.readthedocs.io/
- plaso Documentation: https://plaso.readthedocs.io/
- SANS Digital Forensics: https://www.sans.org/digital-forensics/

### Training
- SANS FOR500: Windows Forensics
- SANS FOR508: Advanced Incident Response
- SANS FOR572: Advanced Network Forensics

### Tools
- Eric Zimmerman's Tools: https://ericzimmerman.github.io/
- KAPE (Kroll Artifact Parser and Extractor): https://www.kroll.com/kape
- RegRipper: https://github.com/keydet89/RegRipper3.0

## Contributing

When contributing forensics tools:
1. Follow forensic best practices
2. Document evidence handling procedures
3. Include comprehensive help text
4. Add error handling and logging
5. Test with sample evidence
6. Update this README with new tools

## Security Notice

These tools are designed for **defensive security** and **legitimate forensic investigations** only:

**Authorized Use**:
- Incident response during active security incidents
- Forensic investigations with proper authorization
- Security research on owned/authorized systems
- Training and education in controlled environments

**Prohibited Use**:
- Unauthorized access to systems or data
- Analysis of systems without proper authorization
- Evidence tampering or destruction
- Violation of privacy laws or regulations

Always obtain proper authorization before conducting any forensic analysis.

---

**Last Updated**: 2025-10-15
**Maintainer**: Defensive Toolkit
**License**: MIT
