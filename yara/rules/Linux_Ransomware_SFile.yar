rule Linux_Ransomware_SFile_9e347b52 {
  meta:
    author           = "Elastic Security"
    id               = "9e347b52-233a-4956-9f1f-7600c482e280"
    fingerprint      = "094af0030d51d1e28405fc02a51ccc1bedf9e083b3d24b82c36f4b397eefbb0b"
    creation_date    = "2023-07-29"
    last_modified    = "2024-02-13"
    threat_name      = "Linux.Ransomware.SFile"
    reference_sample = "49473adedc4ee9b1252f120ad8a69e165dc62eabfa794370408ae055ec65db9d"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "linux"

  strings:
    $a1 = { 49 74 27 73 20 6A 75 73 74 20 61 20 62 75 73 69 6E 65 73 73 2E }
    $a2 = "All data is properly protected against unauthorized access by steady encryption technology."

  condition:
    all of them
}

