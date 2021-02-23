# Trend Micro XDR/Vision One Search Queries by examples
## Most Works in Search App or Search API (but search API does not have General, you will have to use the specific data lake (search method) and use their field names

Before you begin, please read our search syntax online help here : https://docs.trendmicro.com/en-us/enterprise/trend-micro-xdr-online-help/apps/search-app/search-grammar-and-s.aspx

## Example 1 : Searching for PowerShell with not empty command line on a specific endpoint
Search method : General

endpointHostName: your-endpoint-name AND (objectFilePath: powershell.exe AND NOT objectCmd:"")

Explanation : you hunt for powershell command, this is why you look for not empty.

## Example 2 : Searching for multiple values and partial on IP to simulate /24
Search method : EndPoint Activity Data

endpointIp: (192.168.10.41 OR 192.168.1.)

Explanation, this take advantage of partial search 1. and it simulate /24

## Example 3 : PowerShell accessing the Web
Search method : General

NOT request:"" AND processFilePath:powershell

Explanation : You are looking a web request that is not empty and process file is powershell. Again you take advantage of partial search.


