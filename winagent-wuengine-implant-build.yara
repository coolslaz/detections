rule winagent_wuengine_implant_build {
    meta:
        author = "Arnold Chan"
        description = "Detects artifacts of the winAgent v2.0 Windows implant line, including mod_* modules, WUEngine persistence binaries, and COM/CLSID hijack strings used by AI-assisted implant development"
        false_positive1 = "Legitimate software that utilizes COM objects or similar registration keys for plugin modules."
        false_positive2 = "System administration scripts that use PowerShell WebClient or reflection mechanisms."
        false_positive3 = "Development or debugging environments containing similar naming conventions for modules."
strings:
        $winagent = "winAgent" ascii wide nocase
        $mod1 = "mod_persist" ascii wide nocase
        $mod2 = "mod_inject" ascii wide nocase
        $mod3 = "mod_recon" ascii wide nocase
        $mod4 = "mod_c2" ascii wide nocase
        $mod_generic = /mod_[a-zA-Z0-9_]{2,20}/ ascii wide

        $wuengine1 = "WUEngine" ascii wide nocase
        $wuengine2 = "WUEngine.exe" ascii wide nocase
        $msedge1 = "msedgeupdate_v3.exe" ascii wide nocase
        $msedge2 = "msedgeupdate.exe" ascii wide nocase

        $clsid1 = "CLSID\\" ascii wide nocase
        $clsid2 = "InprocServer32" ascii wide nocase
        $clsid3 = "IPersistFile" ascii wide nocase
        $clsid4 = "CoGetClassObject" ascii wide nocase

        $ps_loader1 = "IEX (New-Object Net.WebClient)" ascii wide nocase
        $ps_loader2 = "-EncodedCommand" ascii wide nocase
        $ps_loader3 = "System.Reflection.Assembly" ascii wide nocase

    condition:
        ( $winagent or 2 of ($mod1,$mod2,$mod3,$mod4) or $mod_generic )
        and
        ( any of ($wuengine1,$wuengine2,$msedge1,$msedge2) )
        and
        (
            ( 2 of ($clsid1,$clsid2,$clsid3,$clsid4) and ( $winagent or $mod1 or $mod2 or $mod3 or $mod4 or $mod_generic ) )
            or
            ( any of ($ps_loader1,$ps_loader2,$ps_loader3) and ( $winagent or $mod1 or $mod2 or $mod3 or $mod4 or $mod_generic ) )
        )
}