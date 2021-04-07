# Trend Micro Vision One (XDR) Search Queries by examples
## Most Works in Search App or Search API (but search API does not have General, you will have to use the specific data lake (search method) and use their field names

Before you begin, please read our search syntax online help here : https://docs.trendmicro.com/en-us/enterprise/trend-micro-xdr-online-help/apps/search-app/search-grammar-and-s.aspx

## Example 1 : Searching for PowerShell with not empty command line on a specific endpoint
Search method : General

endpointHostName: your-endpoint-name AND (objectFilePath: powershell.exe AND NOT objectCmd:"")

Explanation : you hunt for powershell command, this is why you look for command line that is not empty.

## Example 2 : Searching for multiple values and partial on IP to simulate /24
Search method : EndPoint Activity Data

endpointIp: (192.168.10.41 OR 192.168.1.)

Explanation, this take advantage of partial search 1. and it simulate /24

## Example 3 : PowerShell accessing the Web
Search method : General

NOT request:"" AND processFilePath:powershell

Explanation : You are looking a web request that is not empty and process file is powershell. Again you take advantage of partial search.

## Example 4 : Searching for a MITRE ATT&CK Technique or Sub Techniques
Search method : General but could be other methods as well

tags:T1105

Explanation : just enter the technique or sub-technique number after tags. Tags field is filled with MITRE filters and XDR SAE filters

## Example 5: Searching for Scripting Usage with MITRE Techniques
Search method : General

tags:(T1059 OR T1064)

Explanation : instead of looking for powershell, windows scripting host and others, just take advange of XDR MITRE filters. in this case these 2 techniques involve scripting. This is TTP base hunting made easy.

## Example 6 : Query for exploits (CVE's)
Search method : Detections

ruleName:CVE-2019-0708

ruleName:CVE-2

Explanation: the first one will search for a specific CVE number, the second one will look for any CVE since year 2000. Both use partial search. Both network and file based exploits with generate detections and the CVE number is in the ruleName field.


## Example 7: Hunting for Autorun with MITRE Techniques
Search method : General

tags:(T1547 OR T1060)

Explanation : We take advantage of XDR MITRE tagging to look for 2 techniques that cover persistence using autorun

## Example 8 : Hunting using MITRE CAR Analytics : CAR-2020-11-006: Local Permission Group Discovery
Reference : https://car.mitre.org/analytics/CAR-2020-11-006/

Search method : General

processName:net.exe AND CLICommand:(user OR localgroup OR group OR ADPrincipalGroupMembership)

Explanation : You want to hunt on this MITRE analytics and you just read their query example and convert into search API syntax. Since it use the net.exe tool, you look for processName:net.exe and command line with CLICommand equal some of the commands that were enumerated in MITRE Analytics. we take advantage of partial search.

## Exemple 9 : Hunting for MS Office process that calls cmd.exe
Search method : Endpoint activity data

objectFilePath:cmd.exe AND parentFilePath:(winword.exe OR excel.exe OR powerpnt.exe OR onenote.exe OR outlook.exe OR Msaccess.exe)

Explanation : parent call object. So parentFilePath is creating objectFilePath. In this case MS Office calling cmd.exe which is common when Office documents are used to attack.

## Example 10 : Hunting for Virtual machines that access the internet or create outbound connections
Search method : Endpoint Activity Data

processFilePath:(vmware-hostd.exe OR vmnat.exe OR VirtualBoxVM.exe OR VBoxSVC.exe OR VBoxSDS.exe) AND (eventSubId: 204 OR NOT request:"")

Explanation : look for VMware or VirualBox process on Windows nad then look for Outbound connection (eventSubid 204) or web request is not empty

## Example 11 : Hunting for malicious use of Certutil.exe
Search method : General

objectCmd:certutil AND filterRiskLevel:high

Explanation : you could also have look for tags field with these filters XSAE.F1505 or XSAE.F1032 but we picked the command line and we ask for filterRisk Level :high to remove noise.

## Example 12 : Finding Logon events 
Search method : General

winEventId:4624

EndpointName:your-endpoint-name AND winEventId:4624

logonUser:davidg AND winEventId:4624

Explanation : in some cases we gather Windows Event logs that do not duplicate our Activity Data. Logon event 4624 is such an example. in the first one you would get all logon events in your entire deployment (oups!). In the second you would get all the logon events on your your-endpoint-name and in the 3rd example you get all logon events for davidg on any machine which is nice if you know that davidg is potentially compromised.

## Example 13: Searching for activity data with winEventId field not empty
Search method : General or Endpoint Activity Data

eventId:"10"

Explanation : eventId 10 is TELEMETRY_WINDOWS_EVENT. this is easier and faster than checking for winEventId NOT empty.

## Example 14: Searching for a URL in all data lakes. Or see if a Spear Phishing email with a URL was also detected by Network or EndPoint
Search method : General

URL:ca75-1.winshipway.com

URL:"https://ca75-1.winshipway.com"

URL:"https://*.winshipway.com"

Explanation : searching for specific might not return hits so I got more hits searching without prefix and suffix. 2nd example will search for the exact URL and the 3rd one will use wild card. You can specify Wild card almost anywhere.

## Example 15 : Searching if the legitimate tool was installed.  
Search method: General

FileFullPath:rclone.exe OR URL:(downloads.rclone.org OR "https://github.com/rclone/*")

Explanation: rclone is a legitimate tool to backup files in multiple cloud storage services (or local network systems) and could be use to exfiltrate data. Modify to cover the Mac or Linux versions. process is rclone.exe on windows so we look for FileFullPath (but we only give exe name using partial search) or we look for download of the installation package. You can use similar techniques to hunt for other tools or software.

## Example 16: Hunting for connections outside your network with EndPoint Activity Data
Search Method : EndPoint Activity Data

eventId: 3 AND NOT (dst:10. OR dst:192. OR dst:224.0.0. OR dst:"::1" OR dst:127.0.0.1 OR dst:"::" OR dst:0.0.0.0 )

Explanation : eventId 3 is TELEMETRY_CONNECTION and we exclude internal destinations on 10, 192, 224, 127, 0... addresses

## Example 17 : Hunting for C2, 3rd party Firewall or Threat Intelligence tell you to search for a C2 call back to 44.233.47.30 on port 443
Search method : General or EndPoint Activity Data 

dst:"44.233.47.30" AND dpt:443

Explanation : Exact search on destination (dst field) and on destination port (dpt field). If you get a hit, you then get the endpoint names, process, users impacted.

## Example 18 : Searching a hash
Search Method : General, Email, EndPoint and Network Activity

file_sha1:"5e7677272b112b90777900f5dd8bad5bd8152002"

Explanation : No partial search on a one way hash for obvious reasons. FileMD5, FileSHA2, FileSHA1 field names in General.file_sha1 in the above example could be in email or Network. Network also have a file_sha256 field.

## Example 19 : Search for email attachment extensions. Office files for examples
Search method : Email Activity Data

file_extension:("docx" OR "xlsx OR "pptx")

Explanation : if a threat come through email attachment of a certain type, just hunt for these file extensions. the example above should include more extensions, just complete it if you need to search for Office files.

## Example 20 : Hunt for new registry entry under run key
Search method : General

objectRegistryKeyHandle:"hklm\\software\\microsoft\\windows\\currentversion\\run*" AND eventSubId:402

Explanation: look for new registry values under the run key. eventSubId 402 is TELEMETRY_REGISTRY_SET 

# The next examples where used to hunt for the HAFNIUM campaign targeting Microsoft Exchange servers

Reference :  https://success.trendmicro.com/solution/000285882

Note: with all searches in this section you can narrow your searches by specifying your exchange servers like this :
You query AND endpointHostName:myExchangeServer
or 
You query AND endpointHostName:(myExchangeServer1 OR server2 OR server3)

## Example 21: HAFNIUM :  Looking for child processes of c:\windows\system32\inetsrv\w3wp.exe  (any or cmd.exe in particular)
Search Method : EndPoint Activity Data

processFilePath:"c:\\windows\\system32\\inetsrv\\w3wp.exe" AND objectFilePath:*

processFilePath:"c:\\windows\\system32\\inetsrv\\w3wp.exe" AND objectFilePath:cmd.exe

Explanation : the 1st query look for the exact process that get compromised which will new processes (in this case any *). The 2nd query is similar but it look specifically for cmd.exe which has been reported in intelligence reports. 

## Example 22: HAFNIUM : Files written to the system by w3wp.exe or UMWorkerProcess.exe
Search Method : EndPoint Activity Data

parentFilePath:(w3wp.exe OR UMWorkerProcess.exe) AND eventSubId: 101

Note : eventSubId 101 is file creation

## Example 23: HAFNIUM :ASPX files created by the SYSTEM user 
Search Method : EndPoint Activity Data

logonUser:(SYSTEM OR Administrator) AND objectFilePath:*.aspx    

## Example 24: HAFNIUM :New, unexpected compiled ASPX files in aspnet_client ASP.NET Files directory
Search Method : EndPoint Activity Data

objectFilePath:("*\inetpub\wwwroot\aspnet_client\*" AND \*aspx) AND eventSubId: 101


## Example 25: HAFNIUM : another vendor reported that the threat actor used the following command:
net group "Exchange Organization administrators" administrator /del /domain.

Search Method: General

ProcessName:net.exe AND CLICommand:((localgroup OR group) AND (Exchange AND /del))


## Example 26: HAFNIUM : 7zip files were used during exfiltration
So you can look for 7zip usage on your Exchange server

Search Method : EndPoint Activity Data

processCmd:7z AND endpointHostName:myExchangeServer

Note you could be more generic by hunting for the Mitre technique tags: MITREV8.T1560 Archive Collected Data

## Example 27 : HAFNIUM : Look for Trend Micro Cloud One - Workload Security and Deep Security IPS rules detections 
Rule 1010854 - Microsoft Exchange Server Remote Code Execution Vulnerability (CVE-2021-26855)

Search method : Detections

ruleName:CVE-2021-26855

Note: this is like example #6

## Example 28 : HAFNIUM : Search for the malware name used in this campaign
Currently known malicious web shells are being detected as Backdoor.ASP.SECCHECHECKER.A and malicious tools as HackTool.PS1.PowerCat.A

Search method : Detections

malName:(Backdoor.ASP.SECCHECHECKER.A OR HackTool.PS1.PowerCat.A)

Other detections to look for :  Backdoor.ASP.CHOPPER.ASPGIG, Trojan.ASP.SECCHECKER.A, Backdoor.ASP.WEBSHELL.UWMANM, Trojan.PS1.BOXTER.A



## END OF HAFNIUM CAMPAIGN EXAMPLE

