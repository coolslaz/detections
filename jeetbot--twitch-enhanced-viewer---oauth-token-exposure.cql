// JeetBot / Twitch Enhanced Viewer - OAuth Token Exposure
// Source: Socket Threat Research / The Hacker News - September 2026
// Severity: high
// Tags: JeetBot, Twitch, OAuth token theft, browser extension, credential exposure
#event_simpleName = NetworkConnectIP4
| @timestamp > now()-30d
| (RemoteUrl = /^(enhanced\.jeetbot\.cc|enhanced-1\.jeetbot\.cc|ext-03\.jeetbot\.cc|ext-styles\.jeetbot\.cc|morphilina\.me|proxy\.morphilina\.me|drisnya\.online|img\.drisnya\.online|thebeholder-proxy\.deno\.dev|proxy\.thebeholder\.deno\.net|alexue4\.dev)$/ OR RemoteAddressIP4 = /^(152\.53\.177\.186|132\.243\.113\.25|80\.74\.26\.162)$/ OR (RemoteUrl = /^(jeetbot\.cc|api\.jeetbot\.cc)$/ AND (RemoteUrl = "*&auth=*" OR RemoteUrl = "*set-token*" OR RemoteUrl = "*/api/v1/proxies*" OR RemoteUrl = "*/api/v1/forced-proxy*")))
| case {
  RemoteUrl = "*&auth=*" | DetectionReason := "Possible Twitch OAuth token forwarded in URL" ;
  RemoteUrl = "*set-token*" | DetectionReason := "Historical OAuth token collection endpoint" ;
  RemoteUrl = "*/api/v1/proxies*" | DetectionReason := "JeetBot proxy configuration request" ;
  RemoteUrl = "*/api/v1/forced-proxy*" | DetectionReason := "JeetBot forced proxy configuration request" ;
  RemoteUrl = /^(enhanced\.jeetbot\.cc|enhanced-1\.jeetbot\.cc|ext-03\.jeetbot\.cc|ext-styles\.jeetbot\.cc|morphilina\.me|proxy\.morphilina\.me|drisnya\.online|img\.drisnya\.online|thebeholder-proxy\.deno\.dev|proxy\.thebeholder\.deno\.net|alexue4\.dev)$/ | DetectionReason := "Connection to JeetBot extension proxy/dev infrastructure" ;
  RemoteAddressIP4 = /^(152\.53\.177\.186|132\.243\.113\.25|80\.74\.26\.162)$/ | DetectionReason := "Connection to known JeetBot IP infrastructure" ;
  * | DetectionReason := "Connection to JeetBot-associated domain"
}
| table([@timestamp, ComputerName, aid, UserName, RemoteUrl, RemoteAddressIP4, RemotePort, Protocol, DetectionReason])
| sort(field=@timestamp, order=desc)