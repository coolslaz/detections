// Title: AI Agent Trigger-Channel Recon — Repeated Cross-Channel Agent Probing
// MITRE ATT&CK: T1595.002 (Active Scanning: Vulnerability Scanning)
// MITRE ATLAS: AML.T0006.003 (Active Scanning: Probe AI Agent Trigger Channels)

dataset = xdr_data
| filter (event_type = ENUM.NETWORK and dns_query_name != null) or (event_type = EVENT_LOG and action_evtlog_data_fields != null)
| alter SenderIdentity = coalesce(actor_effective_username, os_actor_primary_username, lowercase(action_evtlog_data_fields->SenderFromAddress))
| alter Content = coalesce(dns_query_name, action_evtlog_data_fields->Subject, action_evtlog_data_fields->MessageText, action_evtlog_data_fields->Body)
| alter ChannelType = if(event_type = ENUM.NETWORK, "Email", "CollaborationApp")
| alter ProbeCmd = action_process_command_line
| alter RemoteIP = action_remote_ip
| filter SenderIdentity != null
| filter not(SenderIdentity ~= ".*@contoso\\.com$")
| filter not(SenderIdentity in ("no-reply", "noreply", "mailer-daemon", "donotreply"))
| filter not(SenderIdentity ~= "^notifications@.*")
// Exclude known scheduled health-check / synthetic monitoring probes to AI agent trigger channels
| filter not(dns_query_name ~= ".*\\.healthcheck\\.internal$")
| filter not(dns_query_name ~= ".*(uptime|monitoring|synthetic)-probe\\..*")
| filter not(RemoteIP incidr "10.0.0.0/8")
| filter not(ProbeCmd ~= ".*(healthcheck|synthetic-monitor|uptime-agent)\\.exe.*")
| filter Content ~= "(?i)(ignore previous instructions|you are an ai|execute the following|run this command|as an autonomous agent|process this automatically|do not verify|bypass approval|act on this immediately)"
| bin _time span = 24h
| dedup SenderIdentity, ChannelType, Content by asc _time
| comp count_distinct(ChannelType) as DistinctChannels, list(ChannelType) as Channels, count() as MessageCount, list(Content) as SampleContent, earliest(_time) as FirstSeen, latest(_time) as LastSeen by SenderIdentity, _time
| filter DistinctChannels >= 3 and MessageCount >= 3
| sort desc DistinctChannels, desc MessageCount