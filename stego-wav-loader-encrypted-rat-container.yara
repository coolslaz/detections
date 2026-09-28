import "math"

rule stego_wav_loader_encrypted_rat_container {
    meta:
        author = "Arnold Chan"
        description = "Detects the WAV-based loader staging technique: a RIFF/WAVE file carrying a high-entropy appended blob, or a companion DLL chain (rdCore.dll/WMPCL.dll/WPFLocalizeExtension.dll) referencing the hidden audio payload and the encrypted monitor.raw container used to unpack the final RAT"
        false_positive1 = "Legitimate multimedia files with large metadata or appended headers for proprietary audio processing tools."
        false_positive2 = "Development or administrative scripts that use common filenames like 'monitor.raw' for benign diagnostic logging."
strings:
        $_riff = "RIFF"
        $_wave = "WAVE"
        $wav_name = "Common.Integrator.Preview.wav" ascii wide nocase
        $dll_rdcore = "rdCore.dll" ascii wide nocase
        $dll_wmpcl = "WMPCL.dll" ascii wide nocase
        $dll_wpflocal = "WPFLocalizeExtension.dll" ascii wide nocase
        $raw_container = "monitor.raw" ascii wide nocase
        $master_key_le = { D1 E8 AC 26 }

    condition:
        // Case 1: structurally a WAV, but the file is far larger than its own declared
        // RIFF chunk size (i.e. data appended after the legitimate audio stream) and that
        // appended tail is high-entropy - consistent with an embedded/XOR-encoded shellcode
        // loader rather than ordinary (even compressed) audio content.
        ($_riff at 0 and $_wave at 8 and
         filesize > (uint32(4) + 8 + 51200) and
         math.entropy(filesize - 100KB, 100KB) > 7.2)
        or
        // Case 2: the helper/loader component that ties together the audio
        // file name, the DLL chain used to open/decode it, and the encrypted
        // container it subsequently unpacks the RAT from.
        ((2 of ($dll_rdcore, $dll_wmpcl, $dll_wpflocal)) and
         ($wav_name or $raw_container or $master_key_le))
}