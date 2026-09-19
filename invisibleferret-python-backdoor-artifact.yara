rule invisibleferret_python_backdoor_artifact {
    meta:
        author = "Arnold Chan"
        description = "Detects file artifacts referencing InvisibleFerret, a Python-based backdoor used by WaterPlum/North Korean IT worker actors for persistent access to victim networks"
        malware = "InvisibleFerret"
        actor = "WaterPlum"
        reference = "https://attack.mitre.org/software/S1245/"
        false_positive1 = "Legitimate Python scripts that include standard network and subprocess libraries for administrative tasks."
        false_positive2 = "Python training scripts or examples that mimic common socket/subprocess boilerplate code."
strings:
        $family_name = "InvisibleFerret" ascii wide nocase
        $py_shebang = "#!/usr/bin/env python" ascii
        $py_import_socket = "import socket" ascii
        $py_import_subprocess = "import subprocess" ascii
        $py_backdoor_marker = "os.system" ascii

    condition:
        filesize < 500KB
        and $family_name
        and 3 of ($py_shebang, $py_import_socket, $py_import_subprocess, $py_backdoor_marker)
}