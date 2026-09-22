(#event_simpleName = ProcessRollup2 OR #event_simpleName = NetworkConnectIP4 OR #event_simpleName = UrlClick)
| (
    (#event_simpleName = ProcessRollup2 AND SHA256 =~ in(values=["0647336477bdd277450b0c36f104f3f82da721e98d56b67bbeeec05cc48f2d1c", "0e0b77f79fe5d06f11de2959559379e94d62512e073c267b481a58d19d265240", "34c20f5abc04375822f3f68e3e9915c7e388e8adb1ade597672920d53f2c067c", "ac340859805220f97f98b299b32d82b1ccbb2c04c8c09516f3937feda937af80", "8435ec938ca225c3131a624715832845ad9adc5faa93488486bc19c094b4d3ec", "a5e36cf05bcc9ac4e9ebf2a13f95aef8e3847086fe7340c36d6aba6616ae1174", "cceee5c983360842351ffdb8979676fd2fccd4e4c387ac77e4506291d8083c5c"]))
    OR
    (#event_simpleName = NetworkConnectIP4 AND (RemoteAddressIP4 = "45.61.157.22" OR DomainName = /(^|\.)(docsportal\.in|dns\.educationportals\.biz)$/i OR RemoteUrl =~ in(values=["https://docsportal.in/public/reps/com/161.php", "https://docsportal.in/public/reps/com/com.hta", "http://docsportal.in/public/reps/com/com.hta"])))
    OR
    (#event_simpleName = UrlClick AND Url =~ in(values=["https://docsportal.in/public/reps/com/161.php", "https://docsportal.in/public/reps/com/com.hta", "http://docsportal.in/public/reps/com/com.hta"]))
)
| case {
    #event_simpleName = ProcessRollup2 | MatchType := "SHA256_Match" ;
    #event_simpleName = NetworkConnectIP4 AND RemoteAddressIP4 = "45.61.157.22" | MatchType := "C2_IP" ;
    #event_simpleName = NetworkConnectIP4 AND DomainName = /(^|\.)(docsportal\.in|dns\.educationportals\.biz)$/i | MatchType := "C2_Domain" ;
    * | MatchType := "Malicious_URL"
}
| sort(field=@timestamp, order=desc)