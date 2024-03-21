rule Windows_Trojan_Latrodectus_841ff697 {
    meta:
        author = "Elastic Security"
        id = "841ff697-f389-497a-b813-3b9e19cba26e"
        fingerprint = "e52d8706aeeedb09d5e4e223af74d8de2f136a20db96c0a823c1e8b3af379e19"
        creation_date = "2024-03-13"
        last_modified = "2024-03-21"
        threat_name = "Windows.Trojan.Latrodectus"
        reference_sample = "aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $Str1 = { 48 83 EC 38 C6 44 24 20 73 C6 44 24 21 63 C6 44 24 22 75 C6 44 24 23 62 C6 44 24 24 }
        $Str2 = { 48 89 44 24 40 EB 02 EB 90 48 8B 4C 24 20 E8 1B D7 FF FF 48 8B 44 24 40 48 81 C4 E8 02 00 00 C3 CC CC 48 81 EC B8 00 00 00 }
        $Str3 = { 44 24 68 BA 03 00 00 00 48 8B 4C 24 48 FF 15 ED D1 00 00 85 C0 75 14 48 8B 4C 24 50 E8 73 3E 00 00 B8 FF FF FF FF E9 A6 00 }
    condition:
        any of them
}

