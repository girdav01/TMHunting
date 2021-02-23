# Trend Micro XDR/Vision One Search Queries by examples
## Works in Search App or Search API

Before you begin, please read our search syntax online help here : https://docs.trendmicro.com/en-us/enterprise/trend-micro-xdr-online-help/apps/search-app/search-grammar-and-s.aspx

##Example 1 : Searching for PowerShell with not empty command line on a specific endpoint
Search method : General
endpointHostName: your-endpoint-name AND (objectFilePath: powershell.exe AND NOT objectCmd:"")

##Example 2 : Searching for multiple values and partial on IP to simulate /24
Search method : EndPoint Activity Data
endpointIp: (192.168.10.41 OR 192.168.1.)


