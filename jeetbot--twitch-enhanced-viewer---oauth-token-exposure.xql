// Title: JeetBot / Twitch Enhanced Viewer - OAuth Token Exposure
// Description: Detects network connections to JeetBot/Twitch Enhanced Viewer malicious browser extension infrastructure exfiltrating Twitch OAuth tokens.
// Tags: JeetBot, Twitch, OAuth, credential exposure
// MITRE: T1566.002, T1598
// Severity: High
config timeframe = 30d
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| filter (dns_query_name in ("enhanced.jeetbot.cc", "enhanced-1.jeetbot.cc", "ext-03.jeetbot.cc", "ext-styles.jeetbot.cc", "morphilina.me", "proxy.morphilina.me", "drisnya.online", "img.drisnya.online", "thebeholder-proxy.deno.dev", "proxy.thebeholder.deno.net", "alexue4.dev") or action_remote_ip in ("152.53.177.186", "132.243.113.25", "80.74.26.162") or (dns_query_name in ("jeetbot.cc", "api.jeetbot.cc") and (action_network_http_url contains "&auth=" or action_network_http_url contains "set-token" or action_network_http_url contains "/api/v1/proxies" or action_network_http_url contains "/api/v1/forced-proxy")))
| alter DetectionReason = if(action_network_http_url contains "&auth=", "Possible Twitch OAuth token forwarded in URL", if(action_network_http_url contains "set-token", "Historical OAuth token collection endpoint", if(action_network_http_url contains "/api/v1/proxies", "JeetBot proxy configuration request", if(action_network_http_url contains "/api/v1/forced-proxy", "JeetBot forced proxy configuration request", if(dns_query_name in ("enhanced.jeetbot.cc", "enhanced-1.jeetbot.cc", "ext-03.jeetbot.cc", "ext-styles.jeetbot.cc", "morphilina.me", "proxy.morphilina.me", "drisnya.online", "img.drisnya.online", "thebeholder-proxy.deno.dev", "proxy.thebeholder.deno.net", "alexue4.dev"), "Connection to JeetBot extension proxy/dev infrastructure", if(action_remote_ip in ("152.53.177.186", "132.243.113.25", "80.74.26.162"), "Connection to known JeetBot IP infrastructure", "Connection to JeetBot-associated domain"))))))
| fields _time, agent_hostname, agent_id, actor_effective_username, actor_process_image_name, actor_process_command_line, dns_query_name, action_remote_ip, action_remote_port, action_network_protocol, DetectionReason
| sort desc _time