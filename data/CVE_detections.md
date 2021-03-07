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

