rule Windows_Trojan_GhostPulse_a1311f49 {
    meta:
        author = "Elastic Security"
        id = "a1311f49-65a7-4136-a5ab-28cf4de4d40f"
        fingerprint = "e07a8152ab75624aa8dd0a8301d690a6a4bdd3b0e069699632541fb6a32e419b"
        creation_date = "2023-10-06"
        last_modified = "2023-10-26"
        threat_name = "Windows.Trojan.GhostPulse"
        reference = "https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks"
        reference_sample = "0175448655e593aa299278d5f11b81f2af76638859e104975bdb5d30af5c0c11"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 0F BE 00 48 0F BE C0 85 C0 74 0D B8 01 00 00 00 03 45 00 89 45 00 EB E1 8B 45 00 48 8D 65 10 5D C3 }
        $a2 = { 88 4C 24 08 48 83 EC 18 0F B6 44 24 20 88 04 24 0F BE 44 24 20 83 F8 41 7C 13 0F BE 04 24 83 F8 5A 7F 0A 0F BE 04 24 83 C0 20 88 04 24 }
    condition:
        any of them
}

rule Windows_Trojan_GhostPulse_3fe1d02d {
    meta:
        author = "Elastic Security"
        id = "3fe1d02d-5de3-42df-8389-6a55fc2b8afd"
        fingerprint = "18aed348ba64bee842fb6af3b3220e108052a67f49724cf34ba52c8ec7c15cac"
        creation_date = "2023-10-12"
        last_modified = "2023-10-26"
        threat_name = "Windows.Trojan.GhostPulse"
        reference = "https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 89 5C 24 08 48 89 7C 24 10 8B DA 45 33 D2 48 8B F9 41 2B D9 74 50 4C 8B D9 4C 2B C1 0F 1F 00 33 C9 }
    condition:
        all of them
}

rule Windows_Trojan_GhostPulse_3673d337 {
    meta:
        author = "Elastic Security"
        id = "3673d337-218b-4ea8-93f5-ecbc6fe51885"
        fingerprint = "0b46a0e04ab2ca2760b2ace397a09b681bc6c0da5581c3f0f5cdb1a60f307a15"
        creation_date = "2023-12-11"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.GhostPulse"
        reference = "https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks"
        reference_sample = "3013ba32838f6d97d7d75e25394f9611b1c5def94d93588f0a05c90b25b7d6d5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $IDAT_parser_x86 = { 80 F9 3F 75 ?? 38 54 1E 02 74 ?? 80 FA 3F 75 ?? 38 6C 1E 03 74 ?? 80 FD 3F 75 ?? 8A 74 24 04 38 74 1E 04 }
        $IDAT_parser_x64 = { 80 FB 3F 0F 94 44 24 27 3C 3F 0F 94 44 24 30 40 80 FF 3F 0F 94 44 24 31 41 80 FD 3F 0F 94 44 24 32 41 80 FC 3F 0F 94 44 24 33 }
    condition:
        any of them
}

