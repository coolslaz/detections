// Title: AI Targeted Cloaking — Same URL Returning Different Content to AI and Human Clients
// Author: detections.ai
// Severity: Medium
// MITRE ATLAS: AML.T0134
// MITRE ATT&CK: T1036, T1027

dataset = xdr_data
| filter event_type = ENUM.NETWORK and action_network_http_status_code = 200
| filter dns_query_name != null and action_network_http_url != null
| filter not (dns_query_name ~= "(?i)\\.(cloudflare\\.com|cloudflare\\.net|akamaiedge\\.net|akamai\\.net|akamaitechnologies\\.com|fastly\\.net|cloudfront\\.net|googleusercontent\\.com|edgekey\\.net|edgesuite\\.net|azureedge\\.net|cdn77\\.net|stackpathcdn\\.com)$")
| alter ResponseSizeBytes = coalesce(action_network_http_response_size, action_network_http_request_size)
| alter UserAgent = action_network_http_user_agent
| alter NormalizedUrl = replace(replace(action_network_http_url, "#.*", ""), "\\?.*", "")
| alter UserAgentClass = if(UserAgent ~= "(?i)(GPTBot|ChatGPT-User|CCBot|ClaudeBot|Claude-Web|anthropic-ai|PerplexityBot|Google-Extended|Bytespider|cohere-ai|OAI-SearchBot|meta-externalagent)", "AIClient", if(UserAgent ~= "(?i)^Mozilla/5\\.0.*(Chrome/|Safari/|Firefox/|Edg/)" and not(UserAgent ~= "(?i)(bot|crawler|spider|headless|python-requests|curl/|wget/)"), "HumanBrowser", "Other"))
| filter UserAgentClass in ("AIClient", "HumanBrowser")
| bin _time span = 4h
| comp arg_max(_time, ResponseSizeBytes) as RepSize, count() as SessionCount by NormalizedUrl, _time, UserAgentClass, action_remote_ip
| alter AIClient_SessionCount = if(UserAgentClass = "AIClient", SessionCount, null),
        HumanBrowser_SessionCount = if(UserAgentClass = "HumanBrowser", SessionCount, null),
        AIClient_RepSize = if(UserAgentClass = "AIClient", RepSize, null),
        HumanBrowser_RepSize = if(UserAgentClass = "HumanBrowser", RepSize, null)
| comp sum(AIClient_SessionCount) as AISessionCount, sum(HumanBrowser_SessionCount) as HumanSessionCount, max(AIClient_RepSize) as AIResponseSize, max(HumanBrowser_RepSize) as HumanResponseSize by NormalizedUrl, _time, action_remote_ip
| filter AISessionCount >= 1 and HumanSessionCount >= 1
| alter SizeDeltaPct = round(multiply(100.0, divide(abs(subtract(double(AIResponseSize), double(HumanResponseSize))), max(double(AIResponseSize), double(HumanResponseSize), 1.0))), 2)
| filter SizeDeltaPct >= 50.0 and AIResponseSize > 500 and HumanResponseSize > 500
| dedup NormalizedUrl, _time, action_remote_ip by desc SizeDeltaPct
| comp dcount(_time) as DistinctWindowsFlagged, count() as SizeDeltaHits, min(_time) as FirstFlagged, max(_time) as LastFlagged, max(SizeDeltaPct) as MaxSizeDeltaPct, sum(AISessionCount) as TotalAISessions, sum(HumanSessionCount) as TotalHumanSessions, count_distinct(action_remote_ip) as DistinctServerIPs by NormalizedUrl
| filter SizeDeltaHits >= 3
| alter Confidence = "Medium-RecurringSizeDelta"
| fields NormalizedUrl, Confidence, DistinctWindowsFlagged, SizeDeltaHits, FirstFlagged, LastFlagged, MaxSizeDeltaPct, TotalAISessions, TotalHumanSessions, DistinctServerIPs
| sort desc MaxSizeDeltaPct