rule novacookies_debugger_timing_js {
  meta:
    author = "detections.ai"
    description = "Detects JavaScript debugger-timing anti-analysis pattern used by NovaCookies phishing kit to withhold lure when developer tools are open"
  strings:
    $debugger_stmt = "debugger;" ascii
    $clock_call = "clock()" ascii
    $hidden_limit = "hidden_limit" ascii
    $stop_render = "stop_rendering(" ascii
  condition:
    $debugger_stmt and $clock_call and $hidden_limit and $stop_render
}