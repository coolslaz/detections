rule softether_disguised_svchost_bridge_install {
  meta:
    author = "Arnold Chan"
    description = "Detects SoftEther VPN bridge dropper/installer disguised as svchost.exe with masquerading MixedRealityOpen service, based on install script and dropped files (a.Bat, hamcore.se2, vpn_server.config)"
    false_positive = "Removed the pairing of the generic filename 'a.bat' (common in many unrelated benign installers) with a standalone Defender-exclusion command; exclusion commands must now co-occur with each other (both ExclusionPath and ExclusionProcess) rather than firing alongside an unrelated generic batch filename"
strings:
    $path = "C:\\Windows\\system" ascii wide nocase
    $hamcore = "hamcore.se2" ascii wide nocase
    $vpnconfig = "vpn_server.config" ascii wide nocase
    $svcname = "MixedRealityOpen" ascii wide
    $dispname = "Windows Media Scheduler Service" ascii wide
    $exename = "EXE_NAME=svchost.exe" ascii nocase
    $installdir = "INSTALL_DIR=C:\\Windows\\system" ascii nocase
    $abat = "a.bat" ascii wide nocase
    $comment1 = "Silent install SoftEther bridge" ascii nocase
    $exclpath = "Add-MpPreference -ExclusionPath 'C:\\Windows\\system'" ascii nocase
    $exclproc = "Add-MpPreference -ExclusionProcess 'svchost.exe'" ascii nocase

  condition:
    ($path and ($hamcore or $vpnconfig)) or
    ($svcname and $dispname) or
    ($exename and $installdir) or
    ($abat and $comment1) or
    ($exclpath and $exclproc)
}