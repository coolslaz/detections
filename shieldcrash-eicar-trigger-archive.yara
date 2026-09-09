rule shieldcrash_eicar_trigger_archive {
    meta:
        author = "Arnold Chan"
        description = "Detects the eicar_com.zip test archive used by the ShieldCrash PoC (CVE-2026-69414) to trigger Windows Defender's vulnerable scan/read path, only when observed alongside ShieldCrash binary or staging path/context indicators to reduce false positives from routine EICAR AV testing"
        cve = "CVE-2026-69414"
        false_positive1 = "Legitimate security testing or red team operations using custom tools named ShieldCrash."
        false_positive2 = "Development or debugging activities involving similarly named files or paths on a research machine."
strings:
        $_pk_header = { 50 4B 03 04 }
        $filename = "eicar_com.zip" ascii wide nocase
        $eicar_str = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii

        $sc_binary = "ShieldCrash.exe" ascii wide nocase
        $sc_pdb = "ShieldCrash.pdb" ascii wide nocase
        $sc_stage_path = "ShieldCrash_" ascii wide
        $sc_elam_path = "ELAM." ascii wide
        $wd_target = "WD_TARGET_" ascii wide
        $wd_shadow = "WD_SHADOW_" ascii wide

    condition:
        $_pk_header at 0 and $filename and $eicar_str and
        1 of ($sc_binary, $sc_pdb, $sc_stage_path, $sc_elam_path, $wd_target, $wd_shadow)
}