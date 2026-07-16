rule Windows_Trojan_Telepuz_9e2c9a0b {
    meta:
        author = "Elastic Security"
        id = "9e2c9a0b-b8b7-404f-b8c9-7d5216b23413"
        fingerprint = "397fe11dd32a4d9810fa12db44185ea79ce3dff5a936360c98c8a0d1285561b9"
        creation_date = "2026-07-10"
        last_modified = "2026-07-15"
        threat_name = "Windows.Trojan.Telepuz"
        reference_sample = "58aec6e3835aaf20f7b4a7e308b36a19e7454673a6f71783871e9bcf6cae8eed"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a0 = { 0F 31 48 C1 E2 20 48 0B C2 65 48 8B 0C 25 30 00 00 00 48 33 C1 48 89 84 24 }
        $a1 = { 0F 31 48 C1 E2 20 48 0B C2 65 48 8B 0C 25 48 00 00 00 48 03 C1 48 89 }
        $a2 = { 22 04 00 00 23 04 00 00 3F 04 00 00 43 04 00 00 2B 04 00 00 2C 04 00 00 }
        $a3 = { 65 48 8B 04 25 60 00 00 00 48 C1 E8 03 48 89 84 24 }
        $a4 = { 0F B6 C0 33 C1 B9 01 00 00 00 48 6B C9 }
        $a5 = { 66 41 0F 6E C0 66 0F 6E C8 48 8D 52 10 66 0F 70 C9 00 }
    condition:
        3 of them
}

