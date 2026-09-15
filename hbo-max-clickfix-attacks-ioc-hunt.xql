/*
 * Title: HBO Max ClickFix attacks IOC Hunt
 * Description: Detects network traffic matching a list of known malicious domains and IP addresses associated with HBO Max ClickFix attacks. Tightened to reduce false positives from scanner/TI-feed traffic, sinkhole/decommissioned infra, and generic reused IPs by requiring domain-specific selectors, excluding known scanner sources, and deduplicating repeated hits per host within a short window.
 * Level: high
 * Author: detections.ai
 */
dataset = xdr_data
| filter event_type = ENUM.NETWORK
| filter (
    dns_query_name in ("filequanticore.com", "filesiriuscore.com", "alfredaps.com", "hbomaxx.us", "hbomax-macos.com", "bright-links.com", "codex-notes.com", "storageprofiler.com", "cladesktop.gitlab.io", "cli-desktop.com", "cli-stack.com", "homebrwmac-hub.com", "clean-disk-guide.com", "flutelikelurkerunsinewy.com", "camaligsalvatrefoils.com", "press29.com", "leaf68.com", "basequill9.com", "perchframe15.com", "canvas-35.com", "pine63.com", "trekmesh15.com", "weaveridge7.com", "ember-bridge.com", "rudder-moss.com", "wuess.com", "arkypc.com", "harbor-29.com", "fern-plume.com", "node-slate.com", "grove-12.com", "verse-18.com", "lakhov.com", "mpasvw.com", "ouilov.com", "aforvm.com", "desktop-version.com", "oakenfjrod.ru", "sic180.com", "hbomaxx.app")
    or action_file_name in ("filequanticore.com", "filesiriuscore.com", "alfredaps.com", "hbomaxx.us", "hbomax-macos.com", "bright-links.com", "codex-notes.com", "storageprofiler.com", "cladesktop.gitlab.io", "cli-desktop.com", "cli-stack.com", "homebrwmac-hub.com", "clean-disk-guide.com", "flutelikelurkerunsinewy.com", "camaligsalvatrefoils.com", "press29.com", "leaf68.com", "basequill9.com", "perchframe15.com", "canvas-35.com", "pine63.com", "trekmesh15.com", "weaveridge7.com", "ember-bridge.com", "rudder-moss.com", "wuess.com", "arkypc.com", "harbor-29.com", "fern-plume.com", "node-slate.com", "grove-12.com", "verse-18.com", "lakhov.com", "mpasvw.com", "ouilov.com", "aforvm.com", "desktop-version.com", "oakenfjrod.ru", "sic180.com", "hbomaxx.app")
    or (
        (action_remote_ip in ("45.94.47.204", "77.91.65.13", "165.22.199.85", "164.90.161.147", "92.246.136.14", "62.60.226.69", "176.53.159.66", "172.236.51.169", "138.124.93.32", "168.100.9.122", "199.217.98.33", "38.244.158.103", "38.244.158.56") or action_local_ip in ("45.94.47.204", "77.91.65.13", "165.22.199.85", "164.90.161.147", "92.246.136.14", "62.60.226.69", "176.53.159.66", "172.236.51.169", "138.124.93.32", "168.100.9.122", "199.217.98.33", "38.244.158.103", "38.244.158.56"))
        and coalesce(dns_query_name, action_file_name, action_network_http) != null
    )
)
// Exclude known scanner/TI-feed sources hitting these indicators proactively rather than victim traffic
| filter action_local_ip not in ("45.94.47.204", "77.91.65.13", "165.22.199.85", "164.90.161.147", "92.246.136.14", "62.60.226.69", "176.53.159.66", "172.236.51.169", "138.124.93.32", "168.100.9.122", "199.217.98.33", "38.244.158.103", "38.244.158.56")
| filter lowercase(coalesce(http_user_agent, action_network_http_user_agent)) not contains "censys" and lowercase(coalesce(http_user_agent, action_network_http_user_agent)) not contains "shodan" and lowercase(coalesce(http_user_agent, action_network_http_user_agent)) not contains "masscan" and lowercase(coalesce(http_user_agent, action_network_http_user_agent)) not contains "zgrab" and lowercase(coalesce(http_user_agent, action_network_http_user_agent)) not contains "nmap" and lowercase(coalesce(http_user_agent, action_network_http_user_agent)) not contains "scanner" and lowercase(coalesce(http_user_agent, action_network_http_user_agent)) not contains "virustotal" and lowercase(coalesce(http_user_agent, action_network_http_user_agent)) not contains "threatfeed"
| alter matched_indicator = coalesce(dns_query_name, action_file_name, action_remote_ip, action_local_ip)
| bin _time span = 10m
| dedup agent_hostname, matched_indicator, _time by asc _time
| fields timestamp_desc, agent_hostname, agent_ip_addresses, action_remote_ip, action_local_ip, dns_query_name, action_file_name, matched_indicator
| sort desc timestamp_desc