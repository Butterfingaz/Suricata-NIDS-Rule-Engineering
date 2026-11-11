# Suricata-NIDS-Rule-Engineering
Network Intrusion Detection Signature Development & EVE JSON Alert Triage

## 1. Project Overview
This project demonstrates network security monitoring (NSM) and intrusion detection engineering using **Suricata**. A custom network signature was authored to detect anomalous outbound HTTP Command and Control (C2) beaconing based on suspicious User-Agent strings. Additionally, structured Suricata `eve.json` telemetry was triaged to extract actionable Indicators of Compromise (IoCs).

## 2. Custom Suricata Signature (`local.rules`)
The following rule (`SID: 1000001`) inspects established outbound HTTP flows from internal assets (`$HOME_NET`) to external networks (`$EXTERNAL_NET`):

```text
alert http \(HOME_NET any ->\)EXTERNAL_NET any (msg:"CRITICAL: Malicious C2 User-Agent Beaconing Detected"; flow:established,to_server; http.user_agent; content:"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; MaliciousBot)"; classtype:trojan-activity; sid:1000001; rev:1; metadata:mitre_technique_id T1071.001, mitre_tactic "Command and Control";)
```

## 3. Alert Triage & Telemetry Proof

1. <img width="885" height="216" alt="suricata workspace" src="https://github.com/user-attachments/assets/15800a53-dd03-4f6c-9844-5e627384fe5f" />

2. <img width="886" height="467" alt="Suricata signature" src="https://github.com/user-attachments/assets/9b290212-a55e-44bf-b57b-47048c486d01" />

3. <img width="885" height="475" alt="suricata eve_jason" src="https://github.com/user-attachments/assets/9d5a1fa9-2bc3-4f70-83ab-d3aad00dc7c3" />

4. <img width="887" height="344" alt="SOC Analyst Triage Audit" src="https://github.com/user-attachments/assets/89afdad8-0a2f-4473-8d48-b7f1326bfec5" />

5. <img width="894" height="346" alt="cleaning up workspace" src="https://github.com/user-attachments/assets/e1af38a3-f2de-4270-82d9-f37911ca07d5" />


### Key Triage Findings
* **Internal Compromised Host (`src_ip`):** `192.168.1.50`
* **External C2 Destination (`dest_ip`):** `185.220.101.5` (Port `80/TCP`)
* **MITRE ATT&CK Mapping:** `T1071.001` (Application Layer Protocol: Web Protocols)

## 4. Incident Containment Actions
1. **Perimeter Block:** Added destination IP `185.220.101.5` to the enterprise firewall deny list.
2. **Host Isolation:** Quarantined internal endpoint `192.168.1.50` for full memory and process forensics.
