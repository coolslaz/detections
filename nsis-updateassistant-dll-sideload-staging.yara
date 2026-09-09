import "hash"

rule nsis_updateassistant_dll_sideload_staging {
    meta:
        author = "Arnold Chan"
        description = "Detects NSIS installer/archive contents bundling the specific unsigned/renamed UpdateAssistant.exe (aka AppUpdateHelper.exe) payload alongside its associated staged runtime DLLs and known malicious file paths/hashes used as cover noise for DLL sideloading staging"
        MITRE = "T1574.002, T1027, T1036.005"
        false_positives = "Narrowed to require the specific staged file paths (AppData\\Local\\Programs\\SystemComponents or AppData\\Roaming\\Programs\\Common) and/or matching known-bad MD5 hashes together with the bundled DLL set; legitimate use of the redistributable DLL names alone will no longer trigger this rule"
strings:
        $payload = "UpdateAssistant.exe" ascii wide nocase
        $payload_alt = "AppUpdateHelper.exe" ascii wide nocase
        $path1 = "AppData\\Local\\Programs\\SystemComponents\\UpdateAssistant.exe" ascii wide nocase
        $path2 = "AppData\\Roaming\\Programs\\Common\\AppUpdateHelper.exe" ascii wide nocase
        $mutex = "Global\\AppUpdateHelper_E7A2F" ascii wide nocase
        $dll1 = "concrt140.dll" ascii wide nocase
        $dll2 = "msvcp140.dll" ascii wide nocase
        $dll3 = "opencv_world4120.dll" ascii wide nocase
        $dll4 = "vcruntime140.dll" ascii wide nocase
        $dll5 = "vcruntime140_1.dll" ascii wide nocase
    condition:
        (
            (
                ($payload or $payload_alt) and
                3 of ($dll1, $dll2, $dll3, $dll4, $dll5) and
                (any of ($path1, $path2, $mutex))
            )
            or
            (
                hash.md5(0, filesize) == "9c2df9a72b0feeb0b166f0e4ab680851" or
                hash.md5(0, filesize) == "e6d97cdba1cbff8a5f48648839d3e99" or
                hash.md5(0, filesize) == "4796bb351c00d47717906bbee4e20837" or
                hash.md5(0, filesize) == "cd1b08f4930b276ad78853580b76b5c5" or
                hash.md5(0, filesize) == "07bc2f9c4c1b07e1cc013ca0079b31ac"
            )
        )
}