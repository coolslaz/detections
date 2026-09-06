rule sideload_exe_downloader_eNkge3e6
{
    meta:
        author = "detections.ai"
        description = "Detects droppers/scripts referencing the sideload.exe download to %TEMP%\\dl.exe and extraction into %LOCALAPPDATA%\\Microsoft\\eNkge3e6\\"
        malware = "ProRAM"

    strings:
        $url = "66.179.31.11/sideload.exe" ascii wide nocase
        $dl_path = "\\dl.exe" ascii wide nocase
        $stage_dir = "eNkge3e6" ascii wide nocase
        $localappdata_stage = "\\Microsoft\\eNkge3e6\\" ascii wide nocase

    condition:
        $url or ($dl_path and ($stage_dir or $localappdata_stage))
}