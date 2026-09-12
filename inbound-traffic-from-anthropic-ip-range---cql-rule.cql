(#event_simpleName = UserLogon) OR (#event_simpleName = NetworkConnectIP4 AND ActionType = "InboundConnectionAccepted") OR (#event_simpleName = GraphAPIAudit) OR (#event_simpleName = CloudAppEvents) OR (#event_simpleName = EmailEvents)
| case {
    #event_simpleName = UserLogon | SrcIP := IPAddress ;
    #event_simpleName = NetworkConnectIP4 | SrcIP := RemoteIP ;
    #event_simpleName = GraphAPIAudit | SrcIP := IpAddress ;
    #event_simpleName = CloudAppEvents | SrcIP := IPAddress ;
    * | SrcIP := SenderIPv4
  }
| cidr(SrcIP, subnet="160.79.104.0/21")