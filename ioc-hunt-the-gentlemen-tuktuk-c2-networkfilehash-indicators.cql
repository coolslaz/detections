(#event_simpleName=NetworkConnectIP4 OR #event_simpleName=NewExecutableWritten OR #event_simpleName=ProcessRollup2)
| case {
    #event_simpleName=NetworkConnectIP4 AND (RemoteIP="65.109.70.162" OR DomainName="borjumaniya.store" OR DomainName=/\.borjumaniya\.store$/) | MatchType := "NetworkIOC" ;
    #event_simpleName=NewExecutableWritten AND (SHA256="97bd65e98cdc4e93d49edd4ea905d43a61244df0fd3323e6649330de3b1be091" OR SHA256="e2b31ac7ee077b26332444a83a68ab75be641113e7d86979d844a0f3478f01f9" OR SHA256="e74088419de2e5b47b1889f2ba1369cb4b436405ce03cf07da452791681f9923" OR SHA256="096ec37870eb401793592c9b53b5b52fc7a70b113bc2d9cd3f53231142d6c584" OR SHA1="138c41085f5f07adbdeff4df97a6a80252571e28") | MatchType := "FileHashIOC" ;
    #event_simpleName=ProcessRollup2 AND (SHA256="97bd65e98cdc4e93d49edd4ea905d43a61244df0fd3323e6649330de3b1be091" OR SHA256="e2b31ac7ee077b26332444a83a68ab75be641113e7d86979d844a0f3478f01f9" OR SHA256="e74088419de2e5b47b1889f2ba1369cb4b436405ce03cf07da452791681f9923" OR SHA256="096ec37870eb401793592c9b53b5b52fc7a70b113bc2d9cd3f53231142d6c584" OR SHA1="138c41085f5f07adbdeff4df97a6a80252571e28") | MatchType := "ProcessHashIOC" ;
    * | MatchType := "none"
}
| MatchType != "none"
| table([aid, ComputerName, RemoteIP, DomainName, SHA256, SHA1, FileName, MatchType, @timestamp])
| sort(field=@timestamp, order=desc)