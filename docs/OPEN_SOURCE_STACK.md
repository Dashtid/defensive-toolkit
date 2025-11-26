# Open Source Security Stack

**Defensive Toolkit - 100% Open Source**

## Philosophy

The Defensive Toolkit is built on open-source technologies exclusively. This means:

- **Zero Licensing Costs**: No vendor fees, ever
- **Complete Transparency**: All code can be audited
- **Data Sovereignty**: Full control over your data
- **Community-Driven**: Powered by global security community
- **Vendor Independence**: No lock-in to commercial platforms
- **Self-Hosted**: Deploy anywhere you control

## Complete Open Source Stack

### SIEM & Log Management

| Tool | Purpose | License | Website |
|------|---------|---------|---------|
| **Wazuh** | SIEM, XDR, EDR, Compliance | GPL-2.0 | [wazuh.com](https://wazuh.com/) |
| **Elastic Security** | SIEM, Search, Analytics | SSPL/Elastic License | [elastic.co/security](https://www.elastic.co/security) |
| **OpenSearch** | Search, Analytics, Security | Apache-2.0 | [opensearch.org](https://opensearch.org/) |
| **Graylog** | Log Management, Analysis | SSPL | [graylog.org](https://www.graylog.org/) |

**Recommendation**: Start with **Wazuh** for comprehensive SIEM+XDR capabilities.

### SOAR & Automation

| Tool | Purpose | License | Website |
|------|---------|---------|---------|
| **TheHive** | Incident Response Platform | AGPL-3.0 | [thehive-project.org](https://thehive-project.org/) |
| **Shuffle** | Security Orchestration | AGPL-3.0 | [shuffler.io](https://shuffler.io/) |
| **n8n** | Workflow Automation | Fair Code | [n8n.io](https://n8n.io/) |

**Recommendation**: Use **TheHive** for case management + **Shuffle** for workflow automation.

### Threat Intelligence

| Tool | Purpose | License | Website |
|------|---------|---------|---------|
| **MISP** | Threat Intel Sharing | AGPL-3.0 | [misp-project.org](https://www.misp-project.org/) |
| **OpenCTI** | Threat Intel Platform | Apache-2.0 | [opencti.io](https://www.opencti.io/) |
| **Yeti** | Threat Intel Repository | Apache-2.0 | [yeti-platform.github.io](https://yeti-platform.github.io/) |

**Recommendation**: Use **MISP** for IOC sharing + **OpenCTI** for structured threat intelligence.

### Network Security

| Tool | Purpose | License | Website |
|------|---------|---------|---------|
| **Suricata** | IDS/IPS | GPL-2.0 | [suricata.io](https://suricata.io/) |
| **Zeek** | Network Analysis | BSD | [zeek.org](https://zeek.org/) |
| **ntopng** | Network Monitoring | GPL-3.0 | [ntop.org](https://www.ntop.org/) |

**Recommendation**: Deploy **Suricata** for IDS + **Zeek** for deep packet analysis.

### Vulnerability Management

| Tool | Purpose | License | Website |
|------|---------|---------|---------|
| **OpenVAS** | Vulnerability Scanner | GPL-2.0 | [openvas.org](https://www.openvas.org/) |
| **Trivy** | Container/IaC Scanner | Apache-2.0 | [trivy.dev](https://trivy.dev/) |
| **Clair** | Container Vulnerability DB | Apache-2.0 | [quay.github.io/clair](https://quay.github.io/clair/) |

**Recommendation**: Use **OpenVAS** for infrastructure + **Trivy** for containers.

### Forensics & Incident Response

| Tool | Purpose | License | Website |
|------|---------|---------|---------|
| **Volatility** | Memory Forensics | GPL-2.0 | [volatilityfoundation.org](https://www.volatilityfoundation.org/) |
| **Autopsy** | Digital Forensics | Apache-2.0 | [autopsy.com](https://www.autopsy.com/) |
| **The Sleuth Kit** | Forensic Analysis | GPL-2.0 + more | [sleuthkit.org](https://www.sleuthkit.org/) |

**Recommendation**: **Volatility** for memory + **Autopsy** for disk forensics.

### Visualization & Dashboards

| Tool | Purpose | License | Website |
|------|---------|---------|---------|
| **Grafana** | Metrics Visualization | AGPL-3.0 | [grafana.com](https://grafana.com/) |
| **Kibana** | Data Visualization (Elastic) | SSPL | [elastic.co/kibana](https://www.elastic.co/kibana) |

**Recommendation**: **Grafana** for flexible, beautiful dashboards.

## Recommended Deployment Architecture

###Small/Medium Organizations (< 1000 endpoints)

```
┌─────────────────────────────────────────────────┐
│            Defensive Toolkit API                │
│          (FastAPI - this project)               │
└────────────────┬────────────────────────────────┘
                 │
    ┌────────────┴────────────┬──────────────┐
    │                         │              │
┌───▼────┐              ┌────▼─────┐   ┌────▼────┐
│ Wazuh  │              │ TheHive  │   │  MISP   │
│  SIEM  │              │   SOAR   │   │ ThreatI │
└───┬────┘              └────┬─────┘   └────┬────┘
    │                        │              │
┌───▼──────────────────────┬─▼──────────────▼────┐
│         Endpoints        │    Threat Feeds     │
│  (Wazuh Agents Deployed) │  (IOCs, Rules, TTPs)│
└──────────────────────────┴─────────────────────┘
```

**Components**:
- Wazuh Manager (SIEM)
- TheHive (Incident Response)
- MISP (Threat Intelligence)
- Grafana (Dashboards)

**Cost**: $0 (all open source)
**Hardware**: 3 VMs (8GB RAM each)

### Large Organizations (1000+ endpoints)

```
┌──────────────────────────────────────────────────────┐
│           Defensive Toolkit API (Load Balanced)      │
└─────────────────────┬────────────────────────────────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
    ┌────▼───┐   ┌───▼────┐  ┌───▼─────┐
    │ Wazuh  │   │ Elastic│  │OpenSearch│
    │Cluster │   │ SIEM   │  │Analytics │
    └────┬───┘   └───┬────┘  └────┬────┘
         │           │            │
    ┌────▼───────────▼────────────▼─────┐
    │          Load Balancer             │
    └────┬───────────┬────────────┬──────┘
         │           │            │
    ┌────▼───┐  ┌───▼────┐  ┌───▼─────┐
    │TheHive │  │Shuffle │  │OpenCTI  │
    │Cluster │  │ SOAR   │  │ThreatI  │
    └────────┘  └────────┘  └─────────┘
```

**Components**:
- Wazuh Cluster (3+ nodes)
- Elastic Stack OR OpenSearch
- TheHive Cluster
- Shuffle for automation
- OpenCTI for threat intelligence
- Suricata IDS cluster
- Grafana dashboards

**Cost**: $0 (all open source)
**Hardware**: 10-15 VMs (varies by scale)

## Quick Start Guide

### 1. Deploy Wazuh SIEM

```bash
# Install Wazuh (all-in-one)
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash wazuh-install.sh -a

# Access Wazuh dashboard
# https://your-wazuh-server

# Deploy detection rules
cd monitoring/siem/wazuh
python deploy_rules.py --config wazuh_config.yml
```

### 2. Deploy TheHive

```bash
# Docker Compose installation
git clone https://github.com/TheHive-Project/TheHive
cd TheHive/docker
docker-compose up -d

# Access TheHive
# http://localhost:9000
```

### 3. Deploy MISP

```bash
# Using MISP Docker
git clone https://github.com/MISP/misp-docker
cd misp-docker
docker-compose up -d

# Access MISP
# https://localhost
```

### 4. Integrate with Defensive Toolkit API

```bash
# Start the API
cd defensive-toolkit
python start-api.py

# The API provides unified access to all platforms
```

## Cost Comparison

### Commercial Stack vs Open Source

| Component | Commercial | Open Source | Savings/Year |
|-----------|------------|-------------|--------------|
| SIEM | $100k-500k | $0 (Wazuh) | $100k-500k |
| SOAR | $50k-200k | $0 (TheHive+Shuffle) | $50k-200k |
| Threat Intel | $25k-100k | $0 (MISP+OpenCTI) | $25k-100k |
| Vulnerability Scanning | $20k-50k | $0 (OpenVAS+Trivy) | $20k-50k |
| **TOTAL** | **$195k-850k** | **$0** | **$195k-850k** |

**Additional Savings**:
- No per-agent/per-GB licensing fees
- No forced upgrades
- No vendor lock-in costs
- No audit/compliance fees

## Migration from Commercial Platforms

### From Splunk → Elastic/Wazuh

```bash
# Export Splunk searches
# Convert to Sigma rules (platform-agnostic)
# Deploy to Wazuh or Elastic
sigma convert -t wazuh your-splunk-searches/*.yml
```

### From Sentinel → Wazuh

```bash
# Export KQL queries
# Convert to Sigma
# Deploy to Wazuh
```

### From QRadar → OpenSearch

```bash
# Export QRadar rules
# Convert to Sigma
# Deploy to OpenSearch Security Analytics
```

## Support & Community

### Official Support Channels

- **Wazuh**: [Community Forums](https://groups.google.com/g/wazuh), [Slack](https://wazuh.com/community/join-us-on-slack/)
- **TheHive**: [Discord](https://chat.thehive-project.org/)
- **MISP**: [Gitter](https://gitter.im/MISP/MISP), [GitHub Discussions](https://github.com/MISP/MISP/discussions)
- **Shuffle**: [Discord](https://discord.gg/B2CBzUm)

### Commercial Support (Optional)

If you need enterprise support, many open-source tools offer optional commercial support:

- **Wazuh**: Commercial support available from Wazuh Inc.
- **Elastic**: Elastic Cloud or self-managed with support subscription
- **TheHive**: StrangeBee offers commercial support

**Key Point**: Commercial support is *optional*, not required.

## Advantages of Open Source Security

### Technical Benefits

- **Transparency**: Audit all code for backdoors/vulnerabilities
- **Customization**: Modify to fit your exact needs
- **Integration**: No API limitations or licensing restrictions
- **Performance**: Optimize for your specific environment

### Operational Benefits

- **No Vendor Lock-In**: Switch tools anytime
- **Data Sovereignty**: Your data never leaves your infrastructure
- **Compliance**: Easier to meet data residency requirements
- **Longevity**: Community ensures tools don't disappear

### Financial Benefits

- **Zero Licensing**: No per-user, per-agent, or per-GB fees
- **Predictable Costs**: Only hardware and optional support
- **Budget Flexibility**: Spend savings on staff/training
- **No Surprise Bills**: No forced upgrades or audit fees

## Getting Help

**Defensive Toolkit Issues**:
- GitHub: https://github.com/Dashtid/defensive-toolkit/issues

**Community Support**:
- Each tool has active community forums
- Stack Overflow for technical questions
- Reddit: r/cybersecurity, r/netsec, r/blueteamsec

**Professional Services**:
- Many security consultancies specialize in open-source tools
- No vendor dependency - choose any provider

## Contributing

The open-source security community thrives on contributions:

- Report bugs and suggest features
- Submit detection rules to Sigma project
- Share threat intelligence with MISP community
- Contribute to tool documentation
- Help others in community forums

## License

This project is MIT licensed. All integrated open-source tools retain their respective licenses (GPL, Apache, AGPL, etc.).

---

**Last Updated**: October 22, 2025
**Defensive Toolkit Version**: 1.3.0
