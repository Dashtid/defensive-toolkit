# Defensive Toolkit - API Reference

Auto-generated API documentation from Python docstrings.

**Last Updated**: 2025-10-18

---

## Automation

### automation\actions\analysis.py

---

### automation\actions\containment.py

Containment Actions for Security Automation
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Automated containment actions for incident response:
    - Host isolation
    - IP blocking
    - File quarantine
    - Process termination

**Functions:**

#### `isolate_host(hostname: str, method: str, dry_run: bool) -> bool`

Isolate host from network

Args:
    hostname: Target hostname or IP
    method: Isolation method (firewall, vlan, edr)
    dry_run: Simulation mode

Returns:
    bool: True if successful

#### `block_ip(ip_address: str, direction: str, duration: Optional[int], dry_run: bool) -> bool`

Block IP address at firewall

Args:
    ip_address: IP to block
    direction: inbound, outbound, or both
    duration: Block duration in seconds (None = permanent)
    dry_run: Simulation mode

Returns:
    bool: True if successful

#### `quarantine_file(file_path: str, quarantine_dir: str, dry_run: bool) -> bool`

Quarantine suspicious file

Args:
    file_path: Path to suspicious file
    quarantine_dir: Quarantine directory
    dry_run: Simulation mode

Returns:
    bool: True if successful

#### `terminate_process(process_name: str, pid: int, dry_run: bool) -> bool`

Terminate suspicious process

Args:
    process_name: Process name to terminate
    pid: Process ID
    dry_run: Simulation mode

Returns:
    bool: True if successful

#### `disable_user_account(username: str, dry_run: bool) -> bool`

Disable compromised user account

Args:
    username: Username to disable
    dry_run: Simulation mode

Returns:
    bool: True if successful

---

### automation\actions\enrichment.py

Enrichment Actions for Security Automation
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Automated threat intelligence enrichment actions

**Functions:**

#### `enrich_ioc(ioc: str, ioc_type: str, sources: list) -> Dict`

Enrich IOC with threat intelligence

Args:
    ioc: Indicator of compromise
    ioc_type: Type (ip, domain, hash, url)
    sources: TI sources to query

Returns:
    dict: Enrichment data

#### `lookup_domain(domain: str) -> Dict`

DNS/WHOIS lookup

#### `geolocate_ip(ip: str) -> Dict`

Geolocate IP address

---

### automation\actions\notification.py

Notification Actions for Security Automation

**Functions:**

#### `send_email(to: str, subject: str, body: str, smtp_server: str, dry_run: bool) -> bool`

Send email notification

#### `send_slack(webhook_url: str, message: str, dry_run: bool) -> bool`

Send Slack notification

#### `send_webhook(url: str, payload: dict, dry_run: bool) -> bool`

Send webhook notification

---

### automation\integrations\email-connector.py

---

### automation\integrations\siem-connector.py

---

### automation\integrations\ticket-connector.py

---

### automation\integrations\toolkit-connector.py

---

### automation\playbooks\playbook-engine.py

Security Automation Playbook Engine
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    YAML-based playbook execution engine for security automation.
    Supports sequential/parallel tasks, conditional logic, error handling.

Requirements:
    - PyYAML (pip install pyyaml)
    - Python 3.8+

Usage:
    python playbook-engine.py --playbook phishing-response.yaml
    python playbook-engine.py --playbook malware-containment.yaml --dry-run
    python playbook-engine.py --playbook alert-enrichment.yaml --variables vars.json

**Classes:**

#### `PlaybookEngine`

Execute security automation playbooks

**Methods:**

- `__init__(self, dry_run: bool)`

- `load_playbook(self, playbook_file: Path) -> Dict`
  - Load YAML playbook

- `execute_playbook(self, playbook: Dict) -> bool`
  - Execute playbook

- `execute_task(self, task: Dict) -> bool`
  - Execute single task

- `execute_external_action(self, action: str, parameters: Dict) -> bool`
  - Execute external action by importing module

- `save_execution_log(self, output_file: Path)`
  - Save execution log

**Functions:**

#### `main()`

#### `load_playbook(self, playbook_file: Path) -> Dict`

Load YAML playbook

#### `execute_playbook(self, playbook: Dict) -> bool`

Execute playbook

#### `execute_task(self, task: Dict) -> bool`

Execute single task

#### `execute_external_action(self, action: str, parameters: Dict) -> bool`

Execute external action by importing module

#### `save_execution_log(self, output_file: Path)`

Save execution log

#### `replace_var(match)`

---

## Compliance

### compliance\frameworks\cis-checker.py

CIS Controls v8 Compliance Checker
Validates system configuration against CIS Controls v8 safeguards
Supports Windows and Linux systems

**Classes:**

#### `CISChecker`

CIS Controls v8 compliance checker

**Methods:**

- `__init__(self, output_format: str)`

- `check_control_1_inventory(self) -> Dict`
  - CIS Control 1: Inventory and Control of Enterprise Assets

- `check_control_2_software_inventory(self) -> Dict`
  - CIS Control 2: Inventory and Control of Software Assets

- `check_control_3_data_protection(self) -> Dict`
  - CIS Control 3: Data Protection

- `check_control_4_secure_configuration(self) -> Dict`
  - CIS Control 4: Secure Configuration of Enterprise Assets and Software

- `check_control_5_account_management(self) -> Dict`
  - CIS Control 5: Account Management

- `check_control_6_access_control(self) -> Dict`
  - CIS Control 6: Access Control Management

- `check_control_10_malware_defenses(self) -> Dict`
  - CIS Control 10: Malware Defenses

- `run_all_checks(self, controls: Optional[List[int]]) -> Dict`
  - Run all or specified CIS Control checks

- `generate_report(self, output_file: Optional[Path])`
  - Generate compliance report in specified format

**Functions:**

#### `main()`

#### `check_control_1_inventory(self) -> Dict`

CIS Control 1: Inventory and Control of Enterprise Assets
Actively manage all enterprise assets connected to the infrastructure

#### `check_control_2_software_inventory(self) -> Dict`

CIS Control 2: Inventory and Control of Software Assets
Actively manage all software on the network

#### `check_control_3_data_protection(self) -> Dict`

CIS Control 3: Data Protection
Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data

#### `check_control_4_secure_configuration(self) -> Dict`

CIS Control 4: Secure Configuration of Enterprise Assets and Software
Establish and maintain secure configurations for all assets

#### `check_control_5_account_management(self) -> Dict`

CIS Control 5: Account Management
Use processes and tools to assign and manage authorization to credentials

#### `check_control_6_access_control(self) -> Dict`

CIS Control 6: Access Control Management
Use processes and tools to create, assign, manage, and revoke access credentials

#### `check_control_10_malware_defenses(self) -> Dict`

CIS Control 10: Malware Defenses
Prevent or control installation, spread, and execution of malicious applications

#### `run_all_checks(self, controls: Optional[List[int]]) -> Dict`

Run all or specified CIS Control checks

#### `generate_report(self, output_file: Optional[Path])`

Generate compliance report in specified format

---

### compliance\frameworks\framework-mapper.py

Multi-Framework Compliance Mapper
Maps controls between CIS, NIST 800-53, ISO 27001, PCI-DSS, and SOC2
Helps organizations understand control overlap and compliance synergies

**Classes:**

#### `FrameworkMapper`

Multi-framework compliance mapper

**Methods:**

- `__init__(self)`

- `map_control(self, control_id: str) -> Optional[Dict]`
  - Map a specific control to other frameworks

- `find_overlaps(self, frameworks: List[str]) -> Dict`
  - Find control overlaps between multiple frameworks

- `generate_coverage_matrix(self, target_framework: str) -> Dict`
  - Generate a coverage matrix showing which controls in target framework

- `recommend_implementation_order(self, target_frameworks: List[str]) -> List[Dict]`
  - Recommend which controls to implement first for maximum multi-framework coverage

- `export_mapping(self, output_format: str, output_file: Optional[Path]) -> str`
  - Export complete mapping database

**Functions:**

#### `main()`

#### `map_control(self, control_id: str) -> Optional[Dict]`

Map a specific control to other frameworks

Args:
    control_id: Control identifier (e.g., 'CIS-1', 'NIST-AC', 'ISO-A.9.2')

Returns:
    Dictionary with control details and mappings

#### `find_overlaps(self, frameworks: List[str]) -> Dict`

Find control overlaps between multiple frameworks

Args:
    frameworks: List of framework names (e.g., ['CIS', 'NIST-800-53', 'PCI-DSS'])

Returns:
    Dictionary showing overlapping controls

#### `generate_coverage_matrix(self, target_framework: str) -> Dict`

Generate a coverage matrix showing which controls in target framework
are covered by implementing controls from other frameworks

Args:
    target_framework: Framework to analyze (e.g., 'PCI-DSS', 'ISO-27001')

Returns:
    Coverage matrix dictionary

#### `recommend_implementation_order(self, target_frameworks: List[str]) -> List[Dict]`

Recommend which controls to implement first for maximum multi-framework coverage

Args:
    target_frameworks: List of frameworks to achieve compliance with

Returns:
    Ordered list of controls by coverage value

#### `export_mapping(self, output_format: str, output_file: Optional[Path]) -> str`

Export complete mapping database

---

### compliance\frameworks\nist-checker.py

NIST 800-53 Rev 5 Compliance Checker
Validates system configuration against NIST 800-53 security controls
Focuses on technical controls that can be automated

**Classes:**

#### `NISTChecker`

NIST 800-53 Rev 5 compliance checker

**Methods:**

- `__init__(self, output_format: str, impact_level: str)`

- `check_ac_access_control(self) -> Dict`
  - AC - Access Control Family

- `check_au_audit_accountability(self) -> Dict`
  - AU - Audit and Accountability Family

- `check_cm_configuration_management(self) -> Dict`
  - CM - Configuration Management Family

- `check_ia_identification_authentication(self) -> Dict`
  - IA - Identification and Authentication Family

- `check_sc_system_communications_protection(self) -> Dict`
  - SC - System and Communications Protection Family

- `check_si_system_information_integrity(self) -> Dict`
  - SI - System and Information Integrity Family

- `run_all_checks(self, families: Optional[List[str]]) -> Dict`
  - Run all or specified NIST 800-53 control family checks

- `generate_report(self, output_file: Optional[Path])`
  - Generate compliance report in specified format

**Functions:**

#### `main()`

#### `check_ac_access_control(self) -> Dict`

AC - Access Control Family
Limit system access to authorized users and processes

#### `check_au_audit_accountability(self) -> Dict`

AU - Audit and Accountability Family
Create, protect, and retain audit records

#### `check_cm_configuration_management(self) -> Dict`

CM - Configuration Management Family
Establish and maintain baseline configurations

#### `check_ia_identification_authentication(self) -> Dict`

IA - Identification and Authentication Family
Identify and authenticate users and processes

#### `check_sc_system_communications_protection(self) -> Dict`

SC - System and Communications Protection Family
Monitor, control, and protect communications

#### `check_si_system_information_integrity(self) -> Dict`

SI - System and Information Integrity Family
Identify, report, and correct flaws in a timely manner

#### `run_all_checks(self, families: Optional[List[str]]) -> Dict`

Run all or specified NIST 800-53 control family checks

#### `generate_report(self, output_file: Optional[Path])`

Generate compliance report in specified format

---

### compliance\policy\config-drift.py

Configuration Drift Detector
Detects changes from baseline system configuration
Monitors configuration files, services, users, and system settings

**Classes:**

#### `DriftDetector`

Configuration drift detection engine

**Methods:**

- `__init__(self, baseline_file: Path)`

- `create_baseline(self, config_files: List[Path], output_file: Path)`
  - Create new baseline configuration snapshot

- `detect_drift(self) -> Dict`
  - Detect configuration drift from baseline

- `generate_diff(self, file_path: Path, baseline_content: str) -> str`
  - Generate diff between baseline and current file

- `generate_report(self, output_format: str, output_file: Optional[Path]) -> str`
  - Generate drift detection report

**Functions:**

#### `main()`

#### `create_baseline(self, config_files: List[Path], output_file: Path)`

Create new baseline configuration snapshot

#### `detect_drift(self) -> Dict`

Detect configuration drift from baseline

#### `generate_diff(self, file_path: Path, baseline_content: str) -> str`

Generate diff between baseline and current file

#### `generate_report(self, output_format: str, output_file: Optional[Path]) -> str`

Generate drift detection report

---

### compliance\policy\policy-checker.py

Security Policy Checker
Validates system configuration against defined security policies
Supports YAML policy definitions with automated checks

**Classes:**

#### `PolicyChecker`

Security policy validation engine

**Methods:**

- `__init__(self, policy_file: Path)`

- `check_all_policies(self) -> Dict`
  - Execute all policy checks

- `generate_report(self, output_format: str, output_file: Optional[Path]) -> str`
  - Generate policy compliance report

**Functions:**

#### `main()`

#### `check_all_policies(self) -> Dict`

Execute all policy checks

#### `generate_report(self, output_format: str, output_file: Optional[Path]) -> str`

Generate policy compliance report

---

### compliance\reporting\dashboard.py

Compliance Dashboard Generator
Creates real-time compliance status dashboard
Combines CIS, NIST, and policy check results

**Functions:**

#### `generate_html_dashboard(compliance_data: Dict, output_file: Path)`

Generate HTML compliance dashboard

#### `load_compliance_results(result_files: List[Path]) -> Dict`

Load and aggregate compliance results from multiple sources

#### `main()`

---

## Forensics

### forensics\disk\carve-files.py

File Carving Automation Script
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Automates file carving from disk images using bulk_extractor and foremost.
    Useful for recovering deleted files and extracting evidence.

Requirements:
    - bulk_extractor (apt install bulk-extractor)
    - foremost (apt install foremost)
    - Python 3.8+

Usage:
    python carve-files.py --image disk.img --output carved/
    python carve-files.py --image disk.dd --tool foremost
    python carve-files.py --image disk.img --types jpg,png,pdf,doc

**Classes:**

#### `FileCarver`

Automate file carving from disk images

**Methods:**

- `__init__(self, image_file: Path, output_dir: Path)`

- `check_tool(self, tool_name: str) -> bool`
  - Check if carving tool is installed

- `run_bulk_extractor(self) -> bool`
  - Run bulk_extractor for comprehensive data extraction

- `run_foremost(self, file_types: Optional[List[str]]) -> bool`
  - Run foremost for file carving

- `analyze_carved_files(self) -> None`
  - Analyze carved files and generate statistics

- `generate_report(self) -> None`
  - Generate carving report

**Functions:**

#### `main()`

#### `check_tool(self, tool_name: str) -> bool`

Check if carving tool is installed

Args:
    tool_name: Name of tool (bulk_extractor, foremost)

Returns:
    bool: True if tool is available

#### `run_bulk_extractor(self) -> bool`

Run bulk_extractor for comprehensive data extraction

Returns:
    bool: True if successful

#### `run_foremost(self, file_types: Optional[List[str]]) -> bool`

Run foremost for file carving

Args:
    file_types: List of file types to carve (e.g., ['jpg', 'pdf'])

Returns:
    bool: True if successful

#### `analyze_carved_files(self) -> None`

Analyze carved files and generate statistics

#### `generate_report(self) -> None`

Generate carving report

---

### forensics\disk\extract-mft.py

MFT (Master File Table) Parser and Analyzer
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Parses Windows NTFS Master File Table (MFT) to extract file metadata,
    identify suspicious files, and generate timelines.

Requirements:
    - analyzeMFT (pip install analyzeMFT)
    - Python 3.8+

Usage:
    python extract-mft.py --mft $MFT --output analysis/
    python extract-mft.py --mft $MFT --suspicious-only
    python extract-mft.py --mft $MFT --timeline timeline.csv

**Classes:**

#### `MFTAnalyzer`

Parse and analyze Windows MFT

**Methods:**

- `__init__(self, mft_file: Path, output_dir: Path)`

- `parse_mft(self) -> Optional[Path]`
  - Parse MFT using analyzeMFT

- `analyze_suspicious_files(self, parsed_csv: Path) -> None`
  - Analyze parsed MFT for suspicious files

- `generate_timeline(self, parsed_csv: Path, output_file: Path) -> None`
  - Generate timeline from parsed MFT

- `generate_report(self) -> None`
  - Generate analysis report

**Functions:**

#### `main()`

#### `parse_mft(self) -> Optional[Path]`

Parse MFT using analyzeMFT

Returns:
    Path to parsed CSV file

#### `analyze_suspicious_files(self, parsed_csv: Path) -> None`

Analyze parsed MFT for suspicious files

Args:
    parsed_csv: Path to parsed MFT CSV

#### `generate_timeline(self, parsed_csv: Path, output_file: Path) -> None`

Generate timeline from parsed MFT

Args:
    parsed_csv: Path to parsed MFT CSV
    output_file: Output timeline file

#### `generate_report(self) -> None`

Generate analysis report

---

### forensics\memory\hunt-malware.py

Memory-Based Malware Hunting
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Automated malware hunting in memory dumps using Volatility 3 and heuristics.
    Identifies suspicious processes, injections, and malicious indicators.

Requirements:
    - Volatility 3
    - Python 3.8+

Usage:
    python hunt-malware.py memory.dmp
    python hunt-malware.py memory.dmp --iocs iocs.txt

**Classes:**

#### `MalwareHunter`

Hunt for malware in memory dumps

**Methods:**

- `__init__(self, memory_dump: Path, ioc_file: Path)`

- `check_suspicious_processes(self) -> None`
  - Check for suspicious process characteristics

- `check_code_injection(self) -> None`
  - Check for code injection indicators

- `check_network_connections(self) -> None`
  - Check for suspicious network connections

- `check_hidden_processes(self) -> None`
  - Check for hidden/unlinked processes

- `check_suspicious_dlls(self) -> None`
  - Check for suspicious DLL loading

- `check_persistence_mechanisms(self) -> None`
  - Check for persistence mechanisms

- `generate_report(self, output_file: Path) -> None`
  - Generate hunting report

- `hunt(self) -> None`
  - Run all hunting checks

**Functions:**

#### `main()`

#### `check_suspicious_processes(self) -> None`

Check for suspicious process characteristics

#### `check_code_injection(self) -> None`

Check for code injection indicators

#### `check_network_connections(self) -> None`

Check for suspicious network connections

#### `check_hidden_processes(self) -> None`

Check for hidden/unlinked processes

#### `check_suspicious_dlls(self) -> None`

Check for suspicious DLL loading

#### `check_persistence_mechanisms(self) -> None`

Check for persistence mechanisms

#### `generate_report(self, output_file: Path) -> None`

Generate hunting report

#### `hunt(self) -> None`

Run all hunting checks

---

### forensics\memory\volatility-auto-analyze.py

Volatility 3 Automated Memory Analysis
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Automates common Volatility 3 memory analysis tasks including:
    - Process listing and analysis
    - Network connections
    - DLL/driver analysis
    - Malware detection indicators
    - Timeline generation

Requirements:
    - Volatility 3 (pip install volatility3)
    - Python 3.8+

Usage:
    python volatility-auto-analyze.py memory.dmp --output report/
    python volatility-auto-analyze.py memory.dmp --quick
    python volatility-auto-analyze.py memory.dmp --malware-hunt

**Classes:**

#### `VolatilityAnalyzer`

Automated Volatility 3 memory analysis

**Methods:**

- `__init__(self, memory_dump: Path, output_dir: Path)`
  - Initialize analyzer

- `run_plugin(self, plugin: str, output_file: Optional[str], extra_args: List[str]) -> Dict`
  - Run Volatility 3 plugin

- `quick_analysis(self) -> None`
  - Run quick triage analysis

- `full_analysis(self) -> None`
  - Run comprehensive analysis

- `malware_hunt(self) -> None`
  - Focus on malware-specific analysis

- `generate_report(self) -> None`
  - Generate analysis summary report

**Functions:**

#### `check_volatility() -> bool`

Check if Volatility 3 is installed

#### `main()`

#### `run_plugin(self, plugin: str, output_file: Optional[str], extra_args: List[str]) -> Dict`

Run Volatility 3 plugin

Args:
    plugin: Plugin name
    output_file: Optional output filename
    extra_args: Additional arguments for plugin

Returns:
    dict: Plugin execution results

#### `quick_analysis(self) -> None`

Run quick triage analysis

#### `full_analysis(self) -> None`

Run comprehensive analysis

#### `malware_hunt(self) -> None`

Focus on malware-specific analysis

#### `generate_report(self) -> None`

Generate analysis summary report

---

### forensics\timeline\analyze-timeline.py

Timeline Analysis and Pattern Detection
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Analyzes forensic timelines to identify:
    - Suspicious temporal patterns
    - Activity spikes and anomalies
    - Event correlations
    - Attack progression indicators
    - Timeline gaps (anti-forensics)

Requirements:
    - pandas (pip install pandas)
    - Python 3.8+

Usage:
    python analyze-timeline.py --timeline timeline.csv --output analysis/
    python analyze-timeline.py --timeline timeline.csv --detect-anomalies
    python analyze-timeline.py --timeline timeline.csv --correlation-window 300

**Classes:**

#### `TimelineAnalyzer`

Analyze forensic timelines for patterns and anomalies

**Methods:**

- `__init__(self, timeline_file: Path, output_dir: Path)`

- `load_timeline(self) -> bool`
  - Load timeline from CSV file

- `detect_activity_spikes(self, window_minutes: int) -> None`
  - Detect unusual activity spikes

- `detect_timeline_gaps(self, gap_threshold_minutes: int) -> None`
  - Detect suspicious gaps in timeline (potential anti-forensics)

- `correlate_events(self, window_seconds: int) -> None`
  - Find correlated events within time window

- `detect_off_hours_activity(self, work_start_hour: int, work_end_hour: int) -> None`
  - Detect activity outside normal work hours

- `analyze_temporal_patterns(self) -> None`
  - Analyze temporal patterns in timeline

- `generate_report(self) -> None`
  - Generate analysis report

**Functions:**

#### `main()`

#### `load_timeline(self) -> bool`

Load timeline from CSV file

Returns:
    bool: True if successful

#### `detect_activity_spikes(self, window_minutes: int) -> None`

Detect unusual activity spikes

Args:
    window_minutes: Time window for spike detection (minutes)

#### `detect_timeline_gaps(self, gap_threshold_minutes: int) -> None`

Detect suspicious gaps in timeline (potential anti-forensics)

Args:
    gap_threshold_minutes: Minimum gap to report (minutes)

#### `correlate_events(self, window_seconds: int) -> None`

Find correlated events within time window

Args:
    window_seconds: Correlation window (seconds)

#### `detect_off_hours_activity(self, work_start_hour: int, work_end_hour: int) -> None`

Detect activity outside normal work hours

Args:
    work_start_hour: Work day start hour (0-23)
    work_end_hour: Work day end hour (0-23)

#### `analyze_temporal_patterns(self) -> None`

Analyze temporal patterns in timeline

#### `generate_report(self) -> None`

Generate analysis report

---

### forensics\timeline\generate-timeline.py

Timeline Generation and Analysis
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Generates forensic timelines from multiple sources and formats:
    - Windows Event Logs (EVTX)
    - MFT records
    - Registry artifacts
    - Browser history
    - File system metadata
    Uses log2timeline/plaso format when available

Requirements:
    - plaso/log2timeline (optional, for comprehensive timeline generation)
    - Python 3.8+

Usage:
    python generate-timeline.py --source /evidence --output timeline.csv
    python generate-timeline.py --plaso-dump evidence.plaso --output timeline.csv
    python generate-timeline.py --merge file1.csv file2.csv --output merged.csv

**Classes:**

#### `TimelineGenerator`

Generate forensic timelines from multiple sources

**Methods:**

- `__init__(self, output_file: Path)`

- `check_plaso(self) -> bool`
  - Check if plaso/log2timeline is available

- `generate_with_plaso(self, source_path: Path, plaso_file: Path) -> bool`
  - Generate timeline using log2timeline

- `export_plaso_timeline(self, plaso_file: Path) -> bool`
  - Export plaso database to CSV timeline

- `parse_json_timeline(self, json_file: Path) -> None`
  - Parse JSON timeline entries

- `parse_csv_timeline(self, csv_file: Path) -> None`
  - Parse CSV timeline entries

- `merge_timelines(self, timeline_files: List[Path]) -> None`
  - Merge multiple timeline files

- `sort_timeline(self) -> None`
  - Sort timeline entries by timestamp

- `write_timeline(self) -> None`
  - Write timeline to output file

- `analyze_timeline(self) -> Dict`
  - Analyze timeline for patterns

- `generate_report(self, analysis: Dict) -> None`
  - Generate timeline analysis report

**Functions:**

#### `main()`

#### `check_plaso(self) -> bool`

Check if plaso/log2timeline is available

#### `generate_with_plaso(self, source_path: Path, plaso_file: Path) -> bool`

Generate timeline using log2timeline

Args:
    source_path: Evidence source directory/file
    plaso_file: Output plaso database file

Returns:
    bool: True if successful

#### `export_plaso_timeline(self, plaso_file: Path) -> bool`

Export plaso database to CSV timeline

Args:
    plaso_file: Plaso database file

Returns:
    bool: True if successful

#### `parse_json_timeline(self, json_file: Path) -> None`

Parse JSON timeline entries

Args:
    json_file: JSON file with timeline entries

#### `parse_csv_timeline(self, csv_file: Path) -> None`

Parse CSV timeline entries

Args:
    csv_file: CSV file with timeline entries

#### `merge_timelines(self, timeline_files: List[Path]) -> None`

Merge multiple timeline files

Args:
    timeline_files: List of timeline files to merge

#### `sort_timeline(self) -> None`

Sort timeline entries by timestamp

#### `write_timeline(self) -> None`

Write timeline to output file

#### `analyze_timeline(self) -> Dict`

Analyze timeline for patterns

Returns:
    dict: Analysis results

#### `generate_report(self, analysis: Dict) -> None`

Generate timeline analysis report

Args:
    analysis: Analysis results

---

### forensics\artifacts\browser\extract-browser-history.py

Browser History and Artifact Extraction
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Extracts forensic artifacts from web browsers including:
    - Browsing history
    - Download history
    - Cookies
    - Autofill data
    - Bookmarks
    Supports: Chrome, Edge, Firefox, Safari

Requirements:
    - Python 3.8+
    - sqlite3 (built-in)

Usage:
    python extract-browser-history.py --user-profile C:\Users\John --output browser_artifacts/
    python extract-browser-history.py --browser chrome --output artifacts/
    python extract-browser-history.py --offline E:\evidence\Users\John --output analysis/

**Classes:**

#### `BrowserForensics`

Extract forensic artifacts from web browsers

**Methods:**

- `__init__(self, user_profile: Path, output_dir: Path)`

- `chrome_timestamp_to_datetime(self, chrome_timestamp: int) -> str`
  - Convert Chrome timestamp to readable datetime

- `firefox_timestamp_to_datetime(self, firefox_timestamp: int) -> str`
  - Convert Firefox timestamp to readable datetime

- `extract_chrome_history(self) -> bool`
  - Extract Chrome browsing history

- `extract_edge_history(self) -> bool`
  - Extract Edge browsing history

- `extract_firefox_history(self) -> bool`
  - Extract Firefox browsing history

- `extract_chrome_cookies(self) -> bool`
  - Extract Chrome cookies

- `generate_report(self) -> None`
  - Generate extraction report

**Functions:**

#### `main()`

#### `chrome_timestamp_to_datetime(self, chrome_timestamp: int) -> str`

Convert Chrome timestamp to readable datetime

Args:
    chrome_timestamp: Chrome timestamp (microseconds since 1601-01-01)

Returns:
    ISO format datetime string

#### `firefox_timestamp_to_datetime(self, firefox_timestamp: int) -> str`

Convert Firefox timestamp to readable datetime

Args:
    firefox_timestamp: Firefox timestamp (microseconds since epoch)

Returns:
    ISO format datetime string

#### `extract_chrome_history(self) -> bool`

Extract Chrome browsing history

Returns:
    bool: True if successful

#### `extract_edge_history(self) -> bool`

Extract Edge browsing history

Returns:
    bool: True if successful

#### `extract_firefox_history(self) -> bool`

Extract Firefox browsing history

Returns:
    bool: True if successful

#### `extract_chrome_cookies(self) -> bool`

Extract Chrome cookies

Returns:
    bool: True if successful

#### `generate_report(self) -> None`

Generate extraction report

---

## Log Analysis

### log-analysis\analysis\anomaly-detector.py

Log Anomaly Detector
Statistical anomaly detection in log files
Detects unusual patterns, frequency spikes, and baseline deviations

**Classes:**

#### `AnomalyDetector`

Statistical anomaly detection for logs

**Methods:**

- `__init__(self, baseline_file: Optional[Path], threshold_stddev: float)`
  - Initialize anomaly detector

- `create_baseline(self, log_entries: List[Dict], output_file: Path)`
  - Create baseline statistics from log data

- `detect_anomalies(self, log_entries: List[Dict]) -> List[Dict]`
  - Detect anomalies in log entries

- `generate_report(self, output_format: str, output_file: Optional[Path]) -> str`
  - Generate anomaly detection report

**Functions:**

#### `main()`

#### `create_baseline(self, log_entries: List[Dict], output_file: Path)`

Create baseline statistics from log data

Args:
    log_entries: List of parsed log entries
    output_file: Where to save baseline

#### `detect_anomalies(self, log_entries: List[Dict]) -> List[Dict]`

Detect anomalies in log entries

Args:
    log_entries: List of parsed log entries

Returns:
    List of detected anomalies

#### `generate_report(self, output_format: str, output_file: Optional[Path]) -> str`

Generate anomaly detection report

---

### log-analysis\parsers\log-parser.py

Universal Log Parser
Parses common log formats: Syslog, JSON, Apache/Nginx, Windows Event Log
Extracts structured data from unstructured logs

**Classes:**

#### `LogEntry`

Standardized log entry structure

**Methods:**

- `to_dict(self) -> Dict`
  - Convert to dictionary

#### `LogParser`

Universal log parser for multiple formats

**Methods:**

- `__init__(self, log_format: str)`
  - Initialize parser

- `parse_line(self, line: str) -> Optional[LogEntry]`
  - Parse a single log line

- `parse_file(self, file_path: Path, max_lines: int) -> List[LogEntry]`
  - Parse entire log file

**Functions:**

#### `main()`

#### `to_dict(self) -> Dict`

Convert to dictionary

#### `parse_line(self, line: str) -> Optional[LogEntry]`

Parse a single log line

#### `parse_file(self, file_path: Path, max_lines: int) -> List[LogEntry]`

Parse entire log file

---

## Vulnerability Mgmt

### vulnerability-mgmt\prioritization\risk-scorer.py

Risk-Based Vulnerability Scoring Engine
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Multi-factor risk scoring for vulnerabilities combining:
    - CVSS base score
    - Exploitability (EPSS, KEV catalog)
    - Asset criticality
    - Environmental factors
    - Threat intelligence

Requirements:
    - requests (pip install requests)
    - Python 3.8+

Usage:
    python risk-scorer.py --vulnerabilities vulns.json --output scored_vulns.json
    python risk-scorer.py --vulnerabilities scan_results.json --asset-critical --output prioritized.json
    python risk-scorer.py --vulnerabilities vulns.json --kev-check --output results.json

**Classes:**

#### `RiskScorer`

Risk-based vulnerability scoring engine

**Methods:**

- `__init__(self)`

- `load_kev_catalog(self) -> bool`
  - Load CISA KEV (Known Exploited Vulnerabilities) catalog

- `check_kev(self, cve_id: str) -> bool`
  - Check if CVE is in KEV catalog

- `get_epss_score(self, cve_id: str) -> float`
  - Get EPSS (Exploit Prediction Scoring System) score

- `calculate_risk_score(self, vuln: Dict, asset_criticality: str, environment: str) -> Dict`
  - Calculate multi-factor risk score

- `score_vulnerabilities(self, vulnerabilities: List[Dict], asset_criticality: str, environment: str) -> List[Dict]`
  - Score all vulnerabilities

- `generate_report(self, scored_vulns: List[Dict], output_file: Path) -> None`
  - Generate prioritization report

**Functions:**

#### `main()`

#### `load_kev_catalog(self) -> bool`

Load CISA KEV (Known Exploited Vulnerabilities) catalog

Returns:
    bool: True if loaded successfully

#### `check_kev(self, cve_id: str) -> bool`

Check if CVE is in KEV catalog

Args:
    cve_id: CVE ID (e.g., CVE-2021-44228)

Returns:
    bool: True if in KEV catalog

#### `get_epss_score(self, cve_id: str) -> float`

Get EPSS (Exploit Prediction Scoring System) score

Args:
    cve_id: CVE ID

Returns:
    float: EPSS score (0.0-1.0) or 0.0 if unavailable

#### `calculate_risk_score(self, vuln: Dict, asset_criticality: str, environment: str) -> Dict`

Calculate multi-factor risk score

Args:
    vuln: Vulnerability data
    asset_criticality: Asset criticality (low, medium, high, critical)
    environment: Environment type (production, staging, development)

Returns:
    dict: Risk scoring details

#### `score_vulnerabilities(self, vulnerabilities: List[Dict], asset_criticality: str, environment: str) -> List[Dict]`

Score all vulnerabilities

Args:
    vulnerabilities: List of vulnerabilities
    asset_criticality: Asset criticality level
    environment: Environment type

Returns:
    list: Vulnerabilities with risk scores

#### `generate_report(self, scored_vulns: List[Dict], output_file: Path) -> None`

Generate prioritization report

Args:
    scored_vulns: Scored vulnerabilities
    output_file: Output file path

---

### vulnerability-mgmt\prioritization\threat-intel-enrichment.py

Threat Intelligence Enrichment for Vulnerabilities
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Enriches vulnerability data with threat intelligence from:
    - CISA KEV catalog
    - NVD (National Vulnerability Database)
    - Exploit-DB searches
    - Public exploit availability

Requirements:
    - requests (pip install requests)
    - Python 3.8+

Usage:
    python threat-intel-enrichment.py --vulnerabilities vulns.json --output enriched.json
    python threat-intel-enrichment.py --cve CVE-2021-44228 --output log4j_intel.json

**Classes:**

#### `ThreatIntelEnricher`

Enrich vulnerabilities with threat intelligence

**Methods:**

- `__init__(self)`

- `load_kev(self) -> bool`
  - Load CISA KEV catalog

- `get_kev_details(self, cve_id: str) -> Optional[Dict]`
  - Get KEV catalog details for CVE

- `query_nvd(self, cve_id: str) -> Optional[Dict]`
  - Query NVD for CVE details

- `check_exploits(self, cve_id: str, references: List[str]) -> Dict`
  - Check for public exploits

- `enrich_vulnerability(self, vuln: Dict) -> Dict`
  - Enrich single vulnerability with threat intel

- `enrich_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]`
  - Enrich all vulnerabilities

**Functions:**

#### `main()`

#### `load_kev(self) -> bool`

Load CISA KEV catalog

#### `get_kev_details(self, cve_id: str) -> Optional[Dict]`

Get KEV catalog details for CVE

#### `query_nvd(self, cve_id: str) -> Optional[Dict]`

Query NVD for CVE details

#### `check_exploits(self, cve_id: str, references: List[str]) -> Dict`

Check for public exploits

#### `enrich_vulnerability(self, vuln: Dict) -> Dict`

Enrich single vulnerability with threat intel

#### `enrich_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]`

Enrich all vulnerabilities

---

### vulnerability-mgmt\remediation\patch-tracker.py

---

### vulnerability-mgmt\remediation\ticket-integration.py

---

### vulnerability-mgmt\reporting\compliance-mapper.py

---

### vulnerability-mgmt\reporting\generate-report.py

Vulnerability Report Generator
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Generates comprehensive vulnerability reports in multiple formats:
    - PDF (requires weasyprint)
    - HTML
    - JSON
    - Markdown

Requirements:
    - Python 3.8+
    - weasyprint (optional, for PDF: pip install weasyprint)

Usage:
    python generate-report.py --vulnerabilities scored_vulns.json --output report.html
    python generate-report.py --vulnerabilities scored_vulns.json --format pdf --output report.pdf

**Classes:**

#### `VulnReportGenerator`

Generate vulnerability reports

**Methods:**

- `__init__(self, vulnerabilities: List[Dict], metadata: Dict)`

- `generate_html(self, output_file: Path) -> None`
  - Generate HTML report

- `generate_markdown(self, output_file: Path) -> None`
  - Generate Markdown report

**Functions:**

#### `main()`

#### `generate_html(self, output_file: Path) -> None`

Generate HTML report

#### `generate_markdown(self, output_file: Path) -> None`

Generate Markdown report

---

### vulnerability-mgmt\reporting\metrics-dashboard.py

---

### vulnerability-mgmt\scanners\container-scan.py

Container and Image Vulnerability Scanner
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Scans Docker containers and images for vulnerabilities using Trivy.
    Supports scanning local images, registries, and running containers.

Requirements:
    - Trivy installed (https://aquasecurity.github.io/trivy/)
    - Python 3.8+

Usage:
    python container-scan.py --image nginx:latest --output results/
    python container-scan.py --image myapp:1.0 --severity HIGH,CRITICAL
    python container-scan.py --registry myregistry.azurecr.io/app:latest --output scans/

**Classes:**

#### `ContainerScanner`

Container vulnerability scanner using Trivy

**Methods:**

- `__init__(self, output_dir: Path)`

- `check_trivy(self) -> bool`
  - Check if Trivy is installed

- `scan_image(self, image: str, severity: List[str], scan_type: str) -> Dict`
  - Scan container image for vulnerabilities

- `scan_filesystem(self, path: str) -> Dict`
  - Scan filesystem for vulnerabilities (IaC, secrets, misconfigurations)

- `generate_report(self, results: Dict, output_file: Path) -> None`
  - Generate human-readable report

**Functions:**

#### `main()`

#### `check_trivy(self) -> bool`

Check if Trivy is installed

Returns:
    bool: True if Trivy is available

#### `scan_image(self, image: str, severity: List[str], scan_type: str) -> Dict`

Scan container image for vulnerabilities

Args:
    image: Image name (e.g., nginx:latest)
    severity: List of severities to include (CRITICAL, HIGH, MEDIUM, LOW)
    scan_type: Scan type (all, os, library)

Returns:
    dict: Scan results

#### `scan_filesystem(self, path: str) -> Dict`

Scan filesystem for vulnerabilities (IaC, secrets, misconfigurations)

Args:
    path: Path to scan

Returns:
    dict: Scan results

#### `generate_report(self, results: Dict, output_file: Path) -> None`

Generate human-readable report

Args:
    results: Scan results
    output_file: Output file path

---

### vulnerability-mgmt\scanners\nmap-vuln-scan.py

Nmap NSE Vulnerability Scanner
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Automated Nmap vulnerability scanning using NSE (Nmap Scripting Engine).
    Runs vulnerability detection scripts and formats results for analysis.

Requirements:
    - nmap installed on system
    - python-nmap (pip install python-nmap)
    - Python 3.8+

Usage:
    python nmap-vuln-scan.py --target 192.168.1.100 --output results/
    python nmap-vuln-scan.py --target 10.0.0.0/24 --quick --output scan/
    python nmap-vuln-scan.py --target-file hosts.txt --output scans/

**Classes:**

#### `NmapVulnScanner`

Nmap NSE vulnerability scanner

**Methods:**

- `__init__(self, output_dir: Path)`

- `check_nmap(self) -> bool`
  - Check if nmap is installed

- `scan_vulnerabilities(self, target: str, quick: bool, ports: str) -> Dict`
  - Scan target for vulnerabilities using NSE scripts

- `parse_xml_results(self, xml_file: Path) -> Dict`
  - Parse nmap XML output

- `generate_report(self, results: Dict, output_file: Path) -> None`
  - Generate human-readable report

**Functions:**

#### `main()`

#### `check_nmap(self) -> bool`

Check if nmap is installed

Returns:
    bool: True if nmap is available

#### `scan_vulnerabilities(self, target: str, quick: bool, ports: str) -> Dict`

Scan target for vulnerabilities using NSE scripts

Args:
    target: Target host or network
    quick: Quick scan (fewer scripts)
    ports: Port specification (default: common ports)

Returns:
    dict: Scan results

#### `parse_xml_results(self, xml_file: Path) -> Dict`

Parse nmap XML output

Args:
    xml_file: Path to XML file

Returns:
    dict: Parsed results

#### `generate_report(self, results: Dict, output_file: Path) -> None`

Generate human-readable report

Args:
    results: Scan results
    output_file: Output file path

---

### vulnerability-mgmt\scanners\openvas-scan.py

OpenVAS/GVM Vulnerability Scanner Integration
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Integrates with OpenVAS/GVM (Greenbone Vulnerability Manager) to perform
    automated vulnerability scans. Supports scan templates, authentication,
    and report generation.

Requirements:
    - python-gvm (pip install python-gvm)
    - OpenVAS/GVM server accessible
    - Python 3.8+

Usage:
    python openvas-scan.py --target 192.168.1.0/24 --output scan_results/
    python openvas-scan.py --target example.com --scan-type full --output results/
    python openvas-scan.py --target-file targets.txt --credentials admin:password --output scans/

**Classes:**

#### `OpenVASScanner`

OpenVAS/GVM vulnerability scanner integration

**Methods:**

- `__init__(self, host: str, username: str, password: str)`

- `connect(self) -> bool`
  - Connect to GVM server

- `get_scan_configs(self) -> List[Dict]`
  - Get available scan configurations

- `create_target(self, name: str, hosts: str, port_list_id: str) -> Optional[str]`
  - Create scan target

- `create_task(self, name: str, target_id: str, scan_config_id: str, scanner_id: str) -> Optional[str]`
  - Create scan task

- `start_task(self, task_id: str) -> bool`
  - Start scan task

- `get_task_status(self, task_id: str) -> Dict`
  - Get task status

- `wait_for_task(self, task_id: str, check_interval: int) -> bool`
  - Wait for task to complete

- `get_results(self, task_id: str) -> List[Dict]`
  - Get scan results

- `export_report(self, task_id: str, output_file: Path, format: str) -> bool`
  - Export scan report

- `disconnect(self)`
  - Disconnect from GVM

**Functions:**

#### `main()`

#### `connect(self) -> bool`

Connect to GVM server

Returns:
    bool: True if connected successfully

#### `get_scan_configs(self) -> List[Dict]`

Get available scan configurations

Returns:
    list: Available scan configs

#### `create_target(self, name: str, hosts: str, port_list_id: str) -> Optional[str]`

Create scan target

Args:
    name: Target name
    hosts: Target hosts (IP, range, or hostname)
    port_list_id: Port list UUID (optional)

Returns:
    str: Target UUID

#### `create_task(self, name: str, target_id: str, scan_config_id: str, scanner_id: str) -> Optional[str]`

Create scan task

Args:
    name: Task name
    target_id: Target UUID
    scan_config_id: Scan config UUID
    scanner_id: Scanner UUID (optional)

Returns:
    str: Task UUID

#### `start_task(self, task_id: str) -> bool`

Start scan task

Args:
    task_id: Task UUID

Returns:
    bool: True if started successfully

#### `get_task_status(self, task_id: str) -> Dict`

Get task status

Args:
    task_id: Task UUID

Returns:
    dict: Task status information

#### `wait_for_task(self, task_id: str, check_interval: int) -> bool`

Wait for task to complete

Args:
    task_id: Task UUID
    check_interval: Status check interval (seconds)

Returns:
    bool: True if completed successfully

#### `get_results(self, task_id: str) -> List[Dict]`

Get scan results

Args:
    task_id: Task UUID

Returns:
    list: Vulnerability results

#### `export_report(self, task_id: str, output_file: Path, format: str) -> bool`

Export scan report

Args:
    task_id: Task UUID
    output_file: Output file path
    format: Report format (json, xml, pdf, html)

Returns:
    bool: True if exported successfully

#### `disconnect(self)`

Disconnect from GVM

---

### vulnerability-mgmt\scanners\sbom-generator.py

SBOM (Software Bill of Materials) Generator
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Generates Software Bill of Materials (SBOM) in CycloneDX or SPDX format
    using syft. Complies with CISA 2025 minimum elements for SBOM.

Requirements:
    - syft installed (https://github.com/anchore/syft)
    - Python 3.8+

Usage:
    python sbom-generator.py --image nginx:latest --output sboms/
    python sbom-generator.py --directory /path/to/app --format spdx-json --output sboms/
    python sbom-generator.py --image myapp:1.0 --output sboms/ --analyze

**Classes:**

#### `SBOMGenerator`

SBOM generator using syft

**Methods:**

- `__init__(self, output_dir: Path)`

- `check_syft(self) -> bool`
  - Check if syft is installed

- `generate_sbom(self, target: str, target_type: str, format: str) -> Optional[Path]`
  - Generate SBOM for target

- `analyze_sbom(self, sbom_file: Path) -> Dict`
  - Analyze SBOM contents

- `generate_report(self, analysis: Dict, output_file: Path) -> None`
  - Generate SBOM analysis report

- `validate_cisa_compliance(self, sbom_file: Path) -> Dict`
  - Validate SBOM against CISA 2025 minimum elements

**Functions:**

#### `main()`

#### `check_syft(self) -> bool`

Check if syft is installed

Returns:
    bool: True if syft is available

#### `generate_sbom(self, target: str, target_type: str, format: str) -> Optional[Path]`

Generate SBOM for target

Args:
    target: Target to scan (image name or directory path)
    target_type: Type of target ('image' or 'directory')
    format: Output format (cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tag-value)

Returns:
    Path: Path to generated SBOM file

#### `analyze_sbom(self, sbom_file: Path) -> Dict`

Analyze SBOM contents

Args:
    sbom_file: Path to SBOM file

Returns:
    dict: Analysis results

#### `generate_report(self, analysis: Dict, output_file: Path) -> None`

Generate SBOM analysis report

Args:
    analysis: Analysis results
    output_file: Output file path

#### `validate_cisa_compliance(self, sbom_file: Path) -> Dict`

Validate SBOM against CISA 2025 minimum elements

Args:
    sbom_file: Path to SBOM file

Returns:
    dict: Validation results

---

## Scripts

### scripts\cleanup.py

Deep cleanup script for defensive-toolkit project
Removes temporary files, caches, and organizes project structure

**Functions:**

#### `cleanup_pycache()`

Remove all __pycache__ directories

#### `cleanup_pyc_files()`

Remove .pyc and .pyo files

#### `cleanup_logs()`

Remove .log files

#### `cleanup_os_files()`

Remove OS-specific files

#### `cleanup_pytest_cache()`

Remove pytest cache

#### `cleanup_coverage()`

Remove coverage files

#### `cleanup_temp_files()`

Remove temporary files

#### `main()`

Run all cleanup operations

---

### scripts\generate_docs.py

API Documentation Generator for Defensive Toolkit

Extracts docstrings from Python modules and generates markdown documentation.

Usage:
    python scripts/generate_docs.py
    python scripts/generate_docs.py --module automation
    python scripts/generate_docs.py --output docs/api/

**Classes:**

#### `DocGenerator`

Generates API documentation from Python docstrings

**Methods:**

- `__init__(self, root_dir: Optional[Path], output_dir: Optional[Path])`

- `extract_docstring(self, node: ast.AST) -> Optional[str]`
  - Extract docstring from AST node

- `get_function_signature(self, node: ast.FunctionDef) -> str`
  - Get function signature with arguments

- `parse_module(self, module_path: Path) -> Dict`
  - Parse a Python module and extract documentation

- `scan_category(self, category_path: Path) -> List[Dict]`
  - Scan all Python files in a category

- `generate_module_docs(self, module_info: Dict) -> str`
  - Generate markdown documentation for a module

- `generate_category_docs(self, category_name: str, modules: List[Dict]) -> str`
  - Generate documentation for a category

- `generate_api_reference(self, specific_module: Optional[str]) -> str`
  - Generate complete API reference documentation

- `write_api_reference(self, content: str)`
  - Write API reference to file

**Functions:**

#### `main()`

Main entry point

#### `extract_docstring(self, node: ast.AST) -> Optional[str]`

Extract docstring from AST node

#### `get_function_signature(self, node: ast.FunctionDef) -> str`

Get function signature with arguments

#### `parse_module(self, module_path: Path) -> Dict`

Parse a Python module and extract documentation

#### `scan_category(self, category_path: Path) -> List[Dict]`

Scan all Python files in a category

#### `generate_module_docs(self, module_info: Dict) -> str`

Generate markdown documentation for a module

#### `generate_category_docs(self, category_name: str, modules: List[Dict]) -> str`

Generate documentation for a category

#### `generate_api_reference(self, specific_module: Optional[str]) -> str`

Generate complete API reference documentation

#### `write_api_reference(self, content: str)`

Write API reference to file

---

### scripts\validate_project.py

Project Structure Validator for Defensive Toolkit

Validates project structure, imports, tests, and documentation.

Usage:
    python scripts/validate_project.py
    python scripts/validate_project.py --check-structure
    python scripts/validate_project.py --check-imports
    python scripts/validate_project.py --verbose

**Classes:**

#### `ProjectValidator`

Validates defensive-toolkit project structure and configuration

**Methods:**

- `__init__(self, verbose: bool)`

- `log(self, message: str, level: str)`
  - Log messages based on verbosity

- `validate_directory_structure(self) -> bool`
  - Validate expected directory structure exists

- `validate_init_files(self) -> bool`
  - Validate __init__.py files exist in Python packages

- `validate_required_files(self) -> bool`
  - Validate required configuration and documentation files exist

- `validate_python_syntax(self) -> bool`
  - Validate Python files have correct syntax

- `validate_documentation_structure(self) -> bool`
  - Validate documentation structure

- `validate_test_structure(self) -> bool`
  - Validate test structure

- `validate_all(self) -> bool`
  - Run all validations

**Functions:**

#### `main()`

Main entry point

#### `log(self, message: str, level: str)`

Log messages based on verbosity

#### `validate_directory_structure(self) -> bool`

Validate expected directory structure exists

#### `validate_init_files(self) -> bool`

Validate __init__.py files exist in Python packages

#### `validate_required_files(self) -> bool`

Validate required configuration and documentation files exist

#### `validate_python_syntax(self) -> bool`

Validate Python files have correct syntax

#### `validate_documentation_structure(self) -> bool`

Validate documentation structure

#### `validate_test_structure(self) -> bool`

Validate test structure

#### `validate_all(self) -> bool`

Run all validations

---
