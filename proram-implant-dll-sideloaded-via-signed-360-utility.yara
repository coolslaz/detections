rule ProRAM_Sideloaded_DLL_somkernl {
  meta:
    author = "detections.ai"
    description = "Detects the ProRAM implant DLL (somkernl.dll) sideloaded via the signed 360speedld.exe/SoftupNotify.exe utility"

  strings:
    $_mz = { 4D 5A }

    $dll_name = "somkernl.dll" ascii wide nocase
    $sideload_carrier1 = "360speedld.exe" ascii wide nocase
    $sideload_carrier2 = "SoftupNotify.exe" ascii wide nocase

    $family1 = "ProRAM" ascii wide
    $family2 = "PRO_RAM" ascii wide
    $family3 = "PRO_RAM C NoCRT Agent/0.1" ascii wide

  condition:
    $_mz at 0 and
    (
      any of ($dll_name, $sideload_carrier1, $sideload_carrier2) and
      any of ($family1, $family2, $family3)
    )
}