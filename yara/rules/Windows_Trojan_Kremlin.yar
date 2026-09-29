rule Windows_Trojan_Kremlin_d15eb999 {
    meta:
        author = "Elastic Security"
        id = "d15eb999-819a-4315-b51b-e1bbe1dfb873"
        fingerprint = "3d81db124feed487d5cec23e01317e56d6268659b7616d0a4569bee3250d54e2"
        creation_date = "2026-09-11"
        last_modified = "2026-09-25"
        threat_name = "Windows.Trojan.Kremlin"
        reference_sample = "8f7d67c51cf8388b6e01526984952fb58bad47dd511d02bf7f73cd4846f84274"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a0 = { BA 90 5F 01 00 48 8B C8 FF 15 [4] 44 89 75 C7 85 C0 }
        $a1 = { 48 8B 94 24 [4] 48 2B 94 24 [4] 48 83 C2 1F }
        $a2 = { B8 40 77 1B 00 48 2B C6 48 3B C1 48 0F 42 C8 }
        $a3 = { 48 3D FE 0B 00 00 76 12 E8 }
        $b0 = "[EXT] failed to calculate extension id"
        $b1 = "[BROWSER] Extracting ext into %s"
    condition:
        4 of them
}

rule Windows_Trojan_Kremlin_35be03d1 {
    meta:
        author = "Elastic Security"
        id = "35be03d1-b1e2-4bba-8475-2315e72058a1"
        fingerprint = "ea382a0c50a208b9db65dd345a81999f435ec02946639a4fa19afdfe5e65cff9"
        creation_date = "2026-09-11"
        last_modified = "2026-09-25"
        threat_name = "Windows.Trojan.Kremlin"
        reference_sample = "1a2e65ff3e5b00b167af07b2797719c822efbaeff6fca2fec8b0b5b9a1f33734"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a0 = { BA 90 5F 01 00 48 8B 4C 24 40 FF 15 [4] 89 44 24 3C }
        $a1 = { 0F B6 C0 85 C0 75 ?? 48 8D 8C 24 [9] 48 83 F8 02 74 }
        $a2 = { 89 44 24 68 83 7C 24 68 00 7C ?? 48 8D 8C 24 [9] 8B 8C 24 E0 02 00 00 48 3B C8 76 }
        $a3 = { BA 40 77 1B 00 B9 C0 D4 01 00 E8 }
        $a4 = { 48 81 7C 24 ?? FE 0B 00 00 76 12 E8 }
        $b0 = "[EXT] failed to download extension from remote host"
        $b1 = "[BROWSER] Extension fully extracted to '%s'"
    condition:
        3 of them
}

rule Windows_Trojan_Kremlin_dd4e05d3 {
    meta:
        author = "Elastic Security"
        id = "dd4e05d3-e8a6-419b-894f-d66e8976b5f4"
        fingerprint = "00bab956d7afad787e0c90997bfa0e4d39356c388501ece40814baa03f6576ea"
        creation_date = "2026-09-11"
        last_modified = "2026-09-25"
        threat_name = "Windows.Trojan.Kremlin"
        reference_sample = "17c60e17d75348b055687d1ad4f66c8b12f593f68952b6de5ab181c2b7905a6c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a0 = { 83 7C 24 38 00 74 ?? 83 7C 24 38 02 74 ?? 44 8B 4C 24 38 }
        $a1 = { 85 FF 74 27 83 FF 02 74 22 44 8B CF }
        $a2 = { 83 7C 24 50 00 0F 84 [4] 83 BC 24 18 48 00 00 00 0F 85 }
        $a3 = { 81 7C 24 74 90 00 00 00 0F 8C }
        $a4 = { 8B 00 89 44 24 6C 81 7C 24 6C 90 00 00 00 0F 8C }
        $b0 = "[BROWSER] Failed to extract to file"
        $b1 = "[BROWSER] Failed to init Miniz"
    condition:
        3 of them
}

rule Windows_Trojan_Kremlin_50d5b6d2 {
    meta:
        author = "Elastic Security"
        id = "50d5b6d2-230f-413b-81db-adf019770feb"
        fingerprint = "d0c3e59d57e1da50e9e77dc27d333dae4644d01315758cafeb5e8962490dc9ef"
        creation_date = "2026-09-11"
        last_modified = "2026-09-25"
        threat_name = "Windows.Trojan.Kremlin"
        reference_sample = "0553ef3338bf99f17c185706381ee546989fc2dedae627ef222b3d50befbe9d5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a0 = { 48 85 C0 74 2E 48 8D 94 24 [4] 48 8D 8C 24 A0 13 00 00 E8 [4] 85 C0 74 15 }
        $a1 = { 48 85 C0 74 2E 48 8D 94 24 [4] 48 8D 8C 24 F0 05 00 00 E8 [4] 85 C0 74 15 }
        $a2 = { 48 85 C0 74 30 48 8D 94 24 [4] 48 8D 8C 24 F0 05 00 00 E8 [4] 85 C0 74 17 }
        $a3 = { 83 7C 24 58 00 75 2F 48 8D 94 24 [4] 48 8D 8C 24 50 0D 00 00 E8 [4] 48 8B C8 E8 [4] 89 44 24 58 }
        $a4 = { 0F B6 C0 85 C0 74 15 48 8D 8C 24 48 08 00 00 E8 [4] C7 44 24 38 01 00 00 00 }
        $a5 = { 0F B6 C0 85 C0 74 15 48 8D 8C 24 C0 06 00 00 E8 [4] C7 44 24 30 01 00 00 00 }
        $a6 = { 83 7C 24 48 00 74 ?? 83 7C 24 48 02 74 ?? 44 8B 4C 24 48 }
        $a7 = { 83 7C 24 5C 00 0F 84 [4] 83 BC 24 C0 18 00 00 00 0F 85 }
    condition:
        2 of them
}

rule Windows_Trojan_Kremlin_c241b245 {
    meta:
        author = "Elastic Security"
        id = "c241b245-2d29-4f8e-a8f0-cc4b252414e7"
        fingerprint = "d26cf2b8a4697669bbf740458e10e9212bd9efadf9f075ad2d56c0645b57c7aa"
        creation_date = "2026-09-11"
        last_modified = "2026-09-25"
        threat_name = "Windows.Trojan.Kremlin"
        reference_sample = "4f48cb6909213f851ac99074815b0be7ad746efff9dfb2c579fc8426397eae57"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a0 = { 48 85 C0 0F 84 [4] 48 8D 95 78 03 00 00 48 8D 8D F8 03 00 00 E8 [4] 85 C0 0F 84 }
        $a1 = { 39 7D B0 75 ?? 48 8D 95 18 04 00 00 48 8D 8D 60 07 00 00 E8 [4] 48 8B C8 E8 }
    condition:
        all of them
}

