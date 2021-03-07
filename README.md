#
# **Operation Exchange Marauder - An aggregated view for Defenders**
------------
- [Introduction](#Introduction)
- [Advisories, Analysis, and Countermeasures](#Advisories-Analysis-and-Countermeasures)
- [CVE's Exploited](#CVEs-Exploited-by-HAFNIUM)
- [Tools Used in the Attack](#Tools-Used-in-the-Attack)
- [Methodology of Attack](#Methodology-of-Attack)
- [Detection](#Detection-Mechanisms)
	-	CVE Detections
	-	Microsoft defender Queries
	-	Azure Sentinel Detections
	-	Sentinel Queries
	-	Powershell Queries
	-	STIX Object
- [Indicators](#Indicators)
  -	IP addresses
  -	Hashes
  - Paths
  -	Web Shell Names
  -	YARA Rules by Volexity
  -	User Agents
- [Contribution](#Contribution)
------------
## Introduction

In a major revelation on March 2, 2021, Microsoft published a blog detailing the detection of multiple zero-day exploits being used to attack on-premises versions of Microsoft Exchange Server in limited and targeted attacks. Researchers from Volexity and Dubex also contributed to the discovery of this attack chain.

Threat actors used the vulnerabilities to access on-premises Exchange servers which, in turn, enabled them to access email accounts and install additional malware to gain long-term access to victim environments. Microsoft Threat Intelligence Center (MSTIC) attributed the attack campaign with high confidence to HAFNIUM, which is believed to be a state-sponsored group operating out of China, based on observed victimology, tactics, and procedures.

Microsoft has released new security updated to address the vulnerabilities. In this blog, we dive into the indicators of compromise (IOCs), tools used in the attacks, methodology, detection mechanisms, and more.

The affected systems show tendencies of an automated scan and hack, which prompt that the threat actor group Hafnium, likely used an automation script to exploit vulnerable devices at scale. By implanting a web shell, the threat actors were able to create a backdoor on the vulnerable exchange servers, which allowed them further exploitation.

The affected networks seem to be more of small and medium-sized organizations rather than larger enterprises, the reason for which can be that the larger enterprises often use email systems based out of the cloud. In a [press conference](https://thehill.com/policy/cybersecurity/541849-psaki-describes-microsoft-email-breach-as-significant-and-active-threat), White House press secretary Jen Psaki urged that everyone running the vulnerable Exchange servers should immediately patch them.

## Advisories-Analysis-and-Countermeasures
- Cyware Labs : [List of All CVEs and IOCs Used by HAFNIUM to Target Microsoft Exchange Servers](https://cyware.com/blog/list-of-all-cves-and-iocs-used-by-hafnium-to-target-microsoft-exchange-servers-f19e)
- Microsoft: [HAFNIUM targeting Exchange Servers with 0-day exploits](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)
- Volexity: [Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/)
- DHS Emergency Directive 21-02: [Mitigate Microsoft Exchange On-Premises Product Vulnerabilities](https://cyber.dhs.gov/ed/21-02/)
- US-CERT: [Mitigate Microsoft Exchange Server Vulnerabilities](https://us-cert.cisa.gov/ncas/alerts/aa21-062a)
- Wired: [Chinese Hacking Spree Hit an &#39;Astronomical&#39; Number of Victims](https://www.wired.com/story/china-microsoft-exchange-server-hack-victims/)
- AlientVault: [Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities](https://otx.alienvault.com/pulse/603f0fd90aeed325162eeb9b/)

## CVEs-Exploited-by-HAFNIUM

These are the CVE IDs of the vulnerabilities exploited by Hafnium in the Microsoft Exchange Server attack:

- [CVE-2021-26855](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26855)
- [CVE-2021-26857](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26857)
- [CVE-2021-26858](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26858)
- [CVE-2021-27065](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27065)

## Tools-Used-in-the-Attack

- ASP Web shells
- MiniDump
- Procdump
- 7-Zip
- PsExec
- Exchange PowerShell snap-ins
- Nishang
- Powercat

## Methodology-of-Attack

- ASP web shells to initially exploit and perform additional malicious actions
- Procdump to dump the LSASS process memory
- 7-Zip to compress stolen data into ZIP files for exfiltration
- Exchange PowerShell snap-ins to export mailbox data
- Nishang Invoke-PowerShellTcpOneLine reverse shell
- PowerCat from GitHub, then using it to open a connection to a remote server

## Detection-Mechanisms

### CVE Detections
Information regarding the CVE's exploited and detection mechanisms can be found [here](https://github.com/cyware-labs/Operation-Exchange-Marauder/data/CVE_detections.md)

### Microsoft Defender AV Queries
A list of Microsoft Defender AV queries, both specialised for the HAFNIUM attack and generic detection can be found [here](https://github.com/cyware-labs/Operation-Exchange-Marauder/blob/main/data/defender.queries)

### Azure Sentinel Detections

[HAFNIUM Suspicious Exchange Request](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/W3CIISLog/HAFNIUMSuspiciousExchangeRequestPattern.yaml)

[HAFNIUM UM Service writing suspicious file](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/MultipleDataSources/HAFNIUMUmServiceSuspiciousFile.yaml)

[HAFNIUM New UM Service Child Process](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/HAFNIUMNewUMServiceChildProcess.yaml)

[HAFNIUM Suspicious UM Service Errors](https://cyware.com/blog/v)

[HAFNIUM Suspicious File Downloads](https://github.com/Azure/Azure-Sentinel/blob/257ae42ec65d7e9f5d97a8d5d5043bc2005ec065/Detections/htttp_proxy_oab_CL/HAFNIUMSuspiciousFileDownloads.yaml)

### Sentinel Queries

A collection of Sentinel queries, used to detec the behaviours of this attack can be found [here](https://github.com/cyware-labs/Operation-Exchange-Marauder/blob/main/data/sentinel.queries)

## Indicators

### IP Addresses
A list of malicious IP addresses can be found [here](https://github.com/cyware-labs/Operation-Exchange-Marauder/blob/main/data/ip.indicators)

### Web Shell Hashes

A list of hashes that indicate the presence of the ASP web shells used in the attackcan be found [here](https://github.com/cyware-labs/Operation-Exchange-Marauder/blob/main/data/hashes.indicators)

### Web Shell Paths

A list of common paths used by HAFNIUM to download the web shells can be found [here](https://github.com/cyware-labs/Operation-Exchange-Marauder/blob/main/data/web_shells.paths)


### Web Shell Names

A list of names commonly used by the webshells can be found [here](https://github.com/cyware-labs/Operation-Exchange-Marauder/blob/main/data/web_shells.names)

### YARA Rule by Volexity

Security firm Volexity has published a list of YARA rules which assist defenders in analysing the attack which can be found [here](https://github.com/cyware-labs/Operation-Exchange-Marauder/blob/main/data/rules.yara)

### User-Agents

While these cannot be used as indicators, a list of user agents that were used to make the malicious requests can be found [here](https://github.com/cyware-labs/Operation-Exchange-Marauder/blob/main/data/user_agents.indicators)


## Contribution

We are always on the lookout for latest indicators, detection mechanisims and relations. If you note something we have missed or which you would like to add, please raise an issue or create a pull request!
