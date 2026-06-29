rule Multi_Ransomware_Qilin_53ee48e0 {
    meta:
        author = "Elastic Security"
        id = "53ee48e0-9de4-45a2-b4ab-05bd17cd9476"
        fingerprint = "d5bb9c5357d6f25d56df3209defbe6526bd1d0d9823f2d20d490e745198b4822"
        creation_date = "2026-06-05"
        last_modified = "2026-06-26"
        threat_name = "Multi.Ransomware.Qilin"
        reference_sample = "bd1cf7823cabbac2ea7b45f2d7c9dfcd6b9a24714b6d40377bdef82b9c88021b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $seq_1 = { 89 85 68 FE FF FF 89 B5 70 FD FF FF C7 85 6C FE FF FF 30 E1 42 00 }
        $seq_2 = { C6 40 08 27 89 41 08 C7 41 04 03 00 00 00 C7 01 00 00 00 00 }
        $seq_3 = { 89 5D 88 C7 45 B0 90 44 5A 00 C7 45 8C 02 00 00 00 }
        $str_1 = "[DEBUG|VOLUME] Found logical volume:" fullword
        $str_2 = "no-sandbox" fullword
        $str_3 = "README-RECOVER-.txt" fullword
        $str_4 = "-- Qilin " fullword
    condition:
        2 of them
}

