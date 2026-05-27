rule Windows_Trojan_OxLoader_6b81720e {
    meta:
        author = "Elastic Security"
        id = "6b81720e-08d2-4f1b-8f2e-dd5f057c9a0c"
        fingerprint = "66fc7951390988c2a057e0afeb6838fe7022f4d979dbe29e6114b70a1326023f"
        creation_date = "2026-05-19"
        last_modified = "2026-05-26"
        threat_name = "Windows.Trojan.OxLoader"
        reference_sample = "9a9939dff297997732aaade9b243d695632cbd64033c5fbcb9de3d09b7e6c28d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 FF C3 49 C1 EA ?? 48 FF CB 81 40 [5] 48 0F 44 DB EB }
        $a2 = { E8 5C 74 09 00 4D 0F 46 F6 EB 05 }
        $a3 = { 4C 8D B4 24 00 01 00 00 4C 89 E1 89 C2 4D 89 F0 E8 [4] 49 8B 3E 48 89 7B 08 }
        $a4 = { 49 FF C0 48 0F 43 D2 49 FF C8 41 5B 41 C1 4B 04 5A EB 04 }
        $a5 = { E8 59 B9 08 00 45 8B E7 0A 04 FF E4 22 }
        $a6 = { 09 DE 21 D7 41 81 E2 [4] 41 09 FA 41 31 F2 44 09 DA F7 D2 }
        $a7 = { E2 F6 56 48 89 E6 48 83 E4 F0 48 83 EC 20 E8 ?? ?? 00 00 48 89 F4 5E C3 }
        $a8 = "SELECT CurrentRefreshRate FROM Win32_VideoController" wide fullword
    condition:
        2 of them
}

