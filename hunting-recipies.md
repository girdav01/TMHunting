# Trend Micro XDR/Vision One Search Queries by examples
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

ProcessName:net.exe AND CLICommand:(user OR localgroup OR group OR ADPrincipalGroupMembership)

Explanation : You want to hunt on this MITRE analytics and you just read their query example and convert into search API syntax. Since it use the net.exe tool, you look for ProcessName:net.exe and command lime with CLICommand equal some of the commands that were enumerated in MITRE Analytics. we take advantage of partial search.

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


