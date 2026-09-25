import "pe"

rule fake_claudedesktop_sectoprat_sideload {
  meta:
    author = "Arnold Chan"
    description = "Detects a fake ClaudeDesktop.exe installer / tampered libcef.dll sideload chain deploying the SectopRAT .NET RAT, requiring multiple corroborating indicators and a PE anomaly consistent with DLL sideloading rather than a single generic string"
    false_positive1 = "Legitimate applications that use libcef.dll and have been improperly repackaged"
    false_positive2 = "Custom .NET applications using libcef.dll that share similar metadata, though unlikely given the specific export signature checks"
strings:
    $_mz = { 4D 5A }

    // lure / masquerade indicators specific to this chain
    $installer_name = "ClaudeDesktop.exe" ascii wide nocase
    $libcef_name = "libcef.dll" ascii wide nocase
    $jetbrains_lure = "JetBrains" ascii wide nocase

    // payload-specific indicator
    $sectoprat = "SectopRAT" ascii wide nocase

    // .NET loader combination unusual for a genuine CEF/libcef.dll module
    $dotnet_runtime = "mscoree.dll" ascii nocase
    $dotnet_hdr = "_CorExeMain" ascii nocase

  condition:
    $_mz at 0 and
    pe.is_pe and
    (
      // require at least two independent lure/payload indicator groups
      (
        (
          ($installer_name and $libcef_name) +
          ($jetbrains_lure and ($dotnet_runtime or $dotnet_hdr)) +
          ($sectoprat and ($dotnet_runtime or $dotnet_hdr))
        ) >= 2
      )
      or
      (
        // a libcef.dll-named module that is not a genuine Chromium Embedded Framework
        // build (no CEF export surface) but carries a .NET CLR header and the
        // SectopRAT payload string - the hallmark of the tampered sideloaded DLL
        $libcef_name and $sectoprat and
        pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].size > 0 and
        not pe.exports("cef_initialize") and
        not pe.exports("cef_run_message_loop")
      )
    )
}