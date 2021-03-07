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

Microsoft: [HAFNIUM targeting Exchange Servers with 0-day exploits](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)

Volexity: [Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/)

DHS Emergency Directive 21-02: [Mitigate Microsoft Exchange On-Premises Product Vulnerabilities](https://cyber.dhs.gov/ed/21-02/)

US-CERT: [Mitigate Microsoft Exchange Server Vulnerabilities](https://us-cert.cisa.gov/ncas/alerts/aa21-062a)

Wired: [Chinese Hacking Spree Hit an &#39;Astronomical&#39; Number of Victims](https://www.wired.com/story/china-microsoft-exchange-server-hack-victims/)
 
AlientVault: [Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities](https://otx.alienvault.com/pulse/603f0fd90aeed325162eeb9b/)

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

CVE-2021-26855: Exploitation can be detected via the following Exchange HttpProxy logs.

These logs are located in the following directory:

&quot;_%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\HttpProxy&quot;_

Exploitation can be identified by searching for log entries where the AuthenticatedUser is empty and the AnchorMailbox contains the pattern of &quot;ServerInfo~\*/\*&quot;

Here is an example PowerShell command to find these log entries:

_Import-Csv -Path (Get-ChildItem -Recurse -Path &quot;$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy&quot; -Filter &#39;\*.log&#39;).FullName | Where-Object { $\_.AuthenticatedUser -eq &quot; -and $\_.AnchorMailbox -like &#39;ServerInfo~\*/\*&#39; } | select DateTime, AnchorMailbox_

If activity is detected, the logs specific to the application specified in the AnchorMailbox path can be used to help determine what actions were taken.

These logs are located in the &quot;%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging&quot; directory.

CVE-2021-26858: Exploitation can be detected via the Exchange log files:

These logs are located in the following directory:

&quot;_C:\Program Files\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog&quot;_

Files should only be downloaded to the &quot;%PROGRAMFILES%\Microsoft\Exchange Server\V15\ClientAccess\OAB\Temp&quot; directory and in case of exploitation, files are downloaded to other directories (UNC or local paths)

Windows command to search for potential exploitation:

_findstr /snip /c:&quot;Download failed and temporary file&quot; &quot;%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log&quot;_

CVE-2021-26857: Exploitation can be detected via the Windows Application event logs

The exploitation of this deserialization bug will create Application events with the following properties:

- Source: MSExchange Unified Messaging
- EntryType: Error
- Event Message Contains: System.InvalidCastException

Below is a PowerShell command to query the Application Event Log for these log entries:

_Get-EventLog -LogName Application -Source &quot;MSExchange Unified Messaging&quot; -EntryType Error | Where-Object { $\_.Message -like &quot;\*System.InvalidCastException\*&quot; }_

CVE-2021-27065: Exploitation can be detected via the following Exchange log files.

These logs are located in the following directory:

&quot;_C:\Program Files\Microsoft\Exchange Server\V15\Logging\ECP\Server&quot;_

All Set-\&lt;AppName\&gt;VirtualDirectory properties should never contain script and InternalUrl and ExternalUrl should only be valid Uris.

Following is a PowerShell command to search for potential exploitation:

_Select-String -Path &quot;$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log&quot; -Pattern &#39;Set-.+VirtualDirectory&#39;_

### Microsoft Defender AV Queries

- Exploit:Script/Exmann.A!dha
- Behavior:Win32/Exmann.A
- Backdoor:ASP/SecChecker.A

### Generic Microsoft Defender AV Queries

- Backdoor:JS/Webshell (not unique)
- Trojan:JS/Chopper!dha (not unique)
- Behavior:Win32/DumpLsass.A!attk (not unique)
- Backdoor:HTML/TwoFaceVar.B (not unique)

### Azure Sentinel Detections

[HAFNIUM Suspicious Exchange Request](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/W3CIISLog/HAFNIUMSuspiciousExchangeRequestPattern.yaml)

[HAFNIUM UM Service writing suspicious file](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/MultipleDataSources/HAFNIUMUmServiceSuspiciousFile.yaml)

[HAFNIUM New UM Service Child Process](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/HAFNIUMNewUMServiceChildProcess.yaml)

[HAFNIUM Suspicious UM Service Errors](https://cyware.com/blog/v)

[HAFNIUM Suspicious File Downloads](https://github.com/Azure/Azure-Sentinel/blob/257ae42ec65d7e9f5d97a8d5d5043bc2005ec065/Detections/htttp_proxy_oab_CL/HAFNIUMSuspiciousFileDownloads.yaml)

### Sentinel Queries

Nishang Invoke-PowerShellTcpOneLine in Windows Event Logging:

_SecurityEvent | where EventID == 4688 | where Process has\_any (&quot;powershell.exe&quot;, &quot;PowerShell\_ISE.exe&quot;) | where CommandLine has &quot;$client = New-Object System.Net.Sockets.TCPClient&quot;_

Downloads of PowerCat in cmd and Powershell command line logging in Windows Event Logs:

_SecurityEvent | where EventID == 4688 | where Process has\_any (&quot;cmd.exe&quot;, &quot;powershell.exe&quot;, &quot;PowerShell\_ISE.exe&quot;) | where CommandLine has &quot;https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1&quot;_

Exchange PowerShell Snapin being loaded. This can be used to export mailbox data, subsequent command lines should be inspected to verify usage:

_SecurityEvent | where EventID == 4688 | where Process has\_any (&quot;cmd.exe&quot;, &quot;powershell.exe&quot;, &quot;PowerShell\_ISE.exe&quot;) | where isnotempty(CommandLine) | where CommandLine contains &quot;Add-PSSnapin Microsoft.Exchange.Powershell.Snapin&quot; | summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Computer, Account, CommandLine_

## Indicators

### IP Addresses

103.77.192[.]219

104.140.114[.]110

104.250.191[.]110

108.61.246[.]56

149.28.14[.]163

157.230.221[.]198

167.99.168[.]251

185.250.151[.]72

192.81.208[.]169

203.160.69[.]66

211.56.98[.]146

5.254.43[.]18

5.2.69[.]14

80.92.205[.]81

91.192.103[.]43

### Web Shell Hashes

These hashes indicate the presence of the ASP web shells used in the attack

b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0

097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e

2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1

65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5

511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1

4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea

811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d

1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944

### Web Shell Paths

These are the common paths used by Hafnium to download the web shells

In Microsoft Exchange Server installation paths such as:

%PROGRAMFILES%\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\

C:\Exchange\FrontEnd\HttpProxy\owa\auth\

C:\inetpub\wwwroot\aspnet\_client\

C:\inetpub\wwwroot\aspnet\_client\system\_web\

\inetpub\wwwroot\aspnet\_client\ (any .aspx file under this folder or sub folders)

\\&lt;exchange install path\&gt;\FrontEnd\HttpProxy\ecp\auth\ (any file besides TimeoutLogoff.aspx)

\\&lt;exchange install path\&gt;\FrontEnd\HttpProxy\owa\auth\ (any file or modified file that is not part of a standard install)

\\&lt;exchange install path\&gt;\FrontEnd\HttpProxy\owa\auth\Current\\&lt;any aspx file in this folder or subfolders\&gt;

\\&lt;exchange install path\&gt;\FrontEnd\HttpProxy\owa\auth\\&lt;folder with version number\&gt;\\&lt;any aspx file in this folder or subfolders\&gt;

### Web Shell Names

The web shells were commonly named as the following:

web.aspx

help.aspx

document.aspx

errorEE.aspx

errorEEE.aspx

errorEW.aspx

errorFF.aspx

healthcheck.aspx

aspnet\_www.aspx

aspnet\_client.aspx

xx.aspx

shell.aspx

aspnet\_iisstart.aspx

one.aspx

### YARA Rule by Volexity

Rule 1: rule webshell\_aspx\_simpleseesharp : Webshell Unclassified

{

meta:

author = &quot;threatintel@volexity.com&quot;

date = &quot;2021-03-01&quot;

description = &quot;A simple ASPX Webshell that allows an attacker to write further files to disk.&quot;

hash = &quot;893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2&quot;

strings:

$header = &quot;\&lt;%@ Page Language=\&quot;C#\&quot; %\&gt;&quot;

$body = &quot;\&lt;% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine&quot;

condition:

$header at 0 and

$body and

filesize \&lt; 1KB

}

Rule 2: rule webshell\_aspx\_reGeorgTunnel : Webshell Commodity

{

meta:

author = &quot;threatintel@volexity.com&quot;

date = &quot;2021-03-01&quot;

description = &quot;A variation on the reGeorg tunnel webshell&quot;

hash = &quot;406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928&quot;

reference = &quot;https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx&quot;

strings:

$s1 = &quot;System.Net.Sockets&quot;

$s2 = &quot;System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get&quot;

// a bit more experimental

$t1 = &quot;.Split(&#39;|&#39;)&quot;

$t2 = &quot;Request.Headers.Get&quot;

$t3 = &quot;.Substring(&quot;

$t4 = &quot;new Socket(&quot;

$t5 = &quot;IPAddress ip;&quot;

condition:

all of ($s\*) or

all of ($t\*)

}

Rule 3: rule webshell\_aspx\_sportsball : Webshell Unclassified

{

meta:

author = &quot;threatintel@volexity.com&quot;

date = &quot;2021-03-01&quot;

description = &quot;The SPORTSBALL webshell allows attackers to upload files or execute commands on the system.&quot;

hash = &quot;2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a&quot;

strings:

$uniq1 = &quot;HttpCookie newcook = new HttpCookie(\&quot;fqrspt\&quot;, HttpContext.Current.Request.Form&quot;

$uniq2 = &quot;ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE=&quot;

$var1 = &quot;Result.InnerText = string.Empty;&quot;

$var2 = &quot;newcook.Expires = DateTime.Now.AddDays(&quot;

$var3 = &quot;System.Diagnostics.Process process = new System.Diagnostics.Process();&quot;

$var4 = &quot;process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\&quot;&quot;

$var5 = &quot;else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\&quot;&quot;

$var6 = &quot;\&lt;input type=\&quot;submit\&quot; value=\&quot;Upload\&quot; /\&gt;&quot;

condition:

any of ($uniq\*) or

all of ($var\*)

}

### User-Agents

These were the user agents commonly used to make malicious requests:

DuckDuckBot/1.0;+(+http://duckduckgo.com/duckduckbot.html)

facebookexternalhit/1.1+(+http://www.facebook.com/externalhit\_uatext.php)

Mozilla/5.0+(compatible;+Baiduspider/2.0;++http://www.baidu.com/search/spider.html)

Mozilla/5.0+(compatible;+Bingbot/2.0;++http://www.bing.com/bingbot.htm)

Mozilla/5.0+(compatible;+Googlebot/2.1;++http://www.google.com/bot.html

Mozilla/5.0+(compatible;+Konqueror/3.5;+Linux)+KHTML/3.5.5+(like+Gecko)+(Exabot-Thumbnails)

Mozilla/5.0+(compatible;+Yahoo!+Slurp;+http://help.yahoo.com/help/us/ysearch/slurp)

Mozilla/5.0+(compatible;+YandexBot/3.0;++http://yandex.com/bots)

Mozilla/5.0+(X11;+Linux+x86\_64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/51.0.2704.103+Safari/537.36

antSword/v2.1

Googlebot/2.1+(+http://www.googlebot.com/bot.html)

Mozilla/5.0+(compatible;+Baiduspider/2.0;++http://www.baidu.com/search/spider.html)

ExchangeServicesClient/0.0.0.0

python-requests/2.19.1

python-requests/2.25.1

## Contribution

We are always on the lookout for latest indicators, detection mechanisims and relations. If you note something we have missed or which you would like to add, please raise an issue or create a pull request!
