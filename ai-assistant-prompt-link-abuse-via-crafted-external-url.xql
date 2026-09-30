/* Title: AI Assistant Prompt-Link Abuse — External URL Launching Pre-Populated Agent Instructions */
dataset = xdr_data
| filter event_type = NETWORK and event_sub_type = ENUM.NETWORK_HTTP_HEADER
| alter Url = action_url
| filter Url != null
| alter UrlDomain = extract_url_host(Url)
| filter UrlDomain ~= "^(chat\.openai\.com|chatgpt\.com|claude\.ai|copilot\.microsoft\.com|gemini\.google\.com|poe\.com|perplexity\.ai)$"
| filter UrlDomain not in ("platform.openai.com", "help.openai.com", "community.openai.com", "support.anthropic.com", "docs.anthropic.com", "learn.microsoft.com", "support.microsoft.com", "support.google.com", "ai.google.dev")
| alter HighSignalMatch = if(Url ~= "[?&](prompt|instructions|system)=", 1, 0)
| alter GenericParamValue = regextract(Url, "[?&](?:q|query|input)=([^&#]*)")
| alter GenericSuspicious = if(GenericParamValue != null and (len(GenericParamValue) > 60 or GenericParamValue ~= "(ignore|disregard|override|act as|you are|system prompt|forget previous|bypass)"), 1, 0)
| filter HighSignalMatch = 1 or GenericSuspicious = 1
| alter ClickTime = _time, DeviceId = agent_id, AccountUpn = coalesce(actor_primary_username, os_actor_primary_username)
| join type=inner (dataset = xdr_data | filter event_type = EMAIL) as emails emails.email_url = Url
| join type=inner (dataset = xdr_data | filter event_type = PROCESS and event_sub_type = ENUM.PROCESS_START) as agentproc agentproc.agent_id = DeviceId
| filter agentproc._time >= ClickTime and agentproc._time <= add(ClickTime, 300)
| filter agentproc.actor_process_command_line != null and agentproc.actor_process_command_line ~= "(prompt|instructions|system|--input|--query)"
| alter SessionTime = agentproc._time, SessionSource = "Process", AgentCommandLine = agentproc.actor_process_command_line, AgentFilePath = agentproc.action_file_path
| fields AccountUpn, DeviceId, ClickTime, Url, UrlDomain, SessionTime, SessionSource, AgentCommandLine, AgentFilePath, emails.email_network_message_id
| dedup AccountUpn, DeviceId, Url by asc SessionTime
| sort desc SessionTime