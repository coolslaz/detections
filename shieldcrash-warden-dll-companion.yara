import "pe"

rule shieldcrash_warden_dll_companion {
    meta:
        author = "Arnold Chan"
        description = "Detects the Warden.dll companion DLL shipped as part of the ShieldCrash (CVE-2026-69414) exploit chain, tightened to require an unsigned/unknown publisher or a suspicious install path alongside the generic filename"
        reference = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-69414"
        false_positive = "Legitimate software that uses a 'Warden.dll' library and is unsigned or stored in temporary directories during installation or update processes."
strings:
        $_mz = { 4D 5A }
        $name1 = "Warden.dll" ascii wide nocase
        $name2 = "Warden.pdb" ascii wide nocase
        $path_shieldcrash = "ShieldCrash_" ascii wide nocase
        $path_temp = "\\AppData\\Local\\Temp\\" ascii wide nocase
        $path_temp2 = "\\Windows\\Temp\\" ascii wide nocase

    condition:
        $_mz at 0
        and pe.is_pe
        and any of ($name*)
        and (
            pe.number_of_signatures == 0
            or any of ($path_shieldcrash, $path_temp, $path_temp2)
        )
}