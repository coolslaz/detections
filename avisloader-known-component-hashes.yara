import "hash"

rule avisloader_known_component_hashes {
  meta:
    author = "Arnold Chan"
    description = "Matches known SHA-256 hashes of AvisLoader toolkit components recovered from an exposed staging server: the Windows loader client, UAC-bypass helper, and process-hiding DLL"
  strings:
    $_mz = { 4D 5A }
    $_pe = "PE\x00\x00"
  condition:
    $_mz at 0 and
    $_pe and
    filesize >= 10KB and filesize <= 20MB and
    (
      hash.sha256(0, filesize) == "35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc" or
      hash.sha256(0, filesize) == "f0a6870cb774a55775eda15fd39e8a17eb3169d5b9365186dae8edff07ff397" or
      hash.sha256(0, filesize) == "cd1e835f52e5f55279dcdf3857e11bc9298ea6caa88eb214ea2d40ff5d38b5f"
    )
}