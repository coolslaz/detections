import "pe"

rule PostGREShell_Malicious_Output_Plugin_PG_init
{
    meta:
        author = "detections.ai"
        description = "Detects PostgreSQL logical decoding output plugin shared libraries (.dll/.so) exporting _PG_init and embedding strings consistent with CVE-2026-6471 (PostGREShell) catalog/privilege tampering or persistence behavior"
        reference = "CVE-2026-6471"

    strings:
        $pg_init = "_PG_init" ascii
        $s_authid = "pg_authid" ascii wide
        $s_rolsuper = "rolsuper" ascii wide
        $s_preload = "shared_preload_libraries" ascii wide
        $s_hba = "pg_hba.conf" ascii wide
        $s_trust = "trust" ascii wide
        $s_bootstrap = "BootstrapSuperuserId" ascii wide
        $s_restrict_bypass = "check_restricted_library_name" ascii wide

        $api_loadlib = "LoadLibrary" ascii
        $api_dlopen = "dlopen" ascii

        $_mz = { 4D 5A }
        $_elf = { 7F 45 4C 46 }

    condition:
        ($_mz at 0 or $_elf at 0)
        and $pg_init
        and (
            2 of ($s_authid, $s_rolsuper, $s_preload, $s_hba, $s_trust, $s_bootstrap, $s_restrict_bypass)
            or (any of ($api_loadlib, $api_dlopen) and any of ($s_authid, $s_rolsuper, $s_preload))
        )
}