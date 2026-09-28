import "pe"

rule v2_nuget_build_dat_loader_reference {
    meta:
        author = "Arnold Chan"
        description = "Detects a .NET-hosting PE module (e.g. I++u.dll) that references both the NuGet-package-concealed Build.dat loader stage and the subsequent execute_engine_disconnect.raw decrypted container, matching the V2 ClickFix loader chain"
        false_positive1 = "Legitimate .NET applications that happen to share similar naming conventions for internal resources or NuGet packaging structures."
        false_positive2 = "Development or debugging tools that utilize similar internal naming for testing purposes."
strings:
        $build_dat = "Build.dat" ascii wide nocase
        $engine_raw = "execute_engine_disconnect.raw" ascii wide nocase
        $iplusplus = "I++u.dll" ascii wide nocase
        $nuget_marker1 = ".nuspec" ascii wide nocase
        $nuget_marker2 = "package/services/metadata/core-properties" ascii wide nocase
        $mscoree = "mscoree.dll" ascii wide nocase

    condition:
        pe.is_pe and
        $build_dat and
        $engine_raw and
        $mscoree and
        1 of ($iplusplus, $nuget_marker1, $nuget_marker2)
}