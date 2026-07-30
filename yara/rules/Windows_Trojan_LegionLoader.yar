rule Windows_Trojan_LegionLoader_9699226a {
    meta:
        author = "Elastic Security"
        id = "9699226a-3299-41c0-8a56-bb9c2db967eb"
        fingerprint = "ff05b5b2a1b05769ba6cb7ba1feccf093d27928b578601c6d038ec51b3caa0db"
        creation_date = "2025-05-01"
        last_modified = "2025-05-27"
        threat_name = "Windows.Trojan.LegionLoader"
        reference_sample = "45670ffa9b24542ae84e3c9eb5ce609c2bcd29129215a7f37eb74b6211e32b22"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 83 EC 14 89 4D FC C7 45 F4 00 00 00 00 8D 45 F4 50 8B 4D FC 51 8D 4D EC E8 ?? ?? ?? ?? 8B 55 08 52 8D 4D EC E8 ?? ?? ?? ?? 8B 4D FC E8 DC 0A 00 00 0F B6 C0 85 C0 74 08 0F B6 4D 0C }
    condition:
        all of them
}

rule Windows_Trojan_LegionLoader_a00bfc62 {
    meta:
        author = "Elastic Security"
        id = "a00bfc62-17a4-4ac3-9170-16f320fa7dfe"
        fingerprint = "5a0bcdcdd0499393527dd2c73cbf77bd9b96ccae6d97e645d7444b80821d9f8e"
        creation_date = "2026-07-16"
        last_modified = "2026-07-29"
        threat_name = "Windows.Trojan.LegionLoader"
        reference_sample = "334d5cfc5581ce985bfd6b29bac2c840a312ca0f5a042412cab86ab08c489a88"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 45 0F B6 02 4D 8D 52 01 44 33 C0 41 FF C3 41 8B C0 41 D1 E8 83 E0 01 F7 D8 }
        $b = { 8D 43 01 0F B6 C8 48 8D 7F 01 8B D9 0F B6 14 0C 42 8D 04 02 44 0F B6 C0 }
        $c = { 6E 6F 6E 20 65 73 74 20 68 6F 6D 6F 2E 20 41 20 72 65 70 65 61 74 20 6E 65 63 65 73 73 65 20 65 73 74 2E }
    condition:
        2 of them
}

