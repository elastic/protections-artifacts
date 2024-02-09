rule Windows_Trojan_PikaBot_8c6750b5 {
    meta:
        author = "Elastic Security"
        id = "8c6750b5-d232-4b72-8fe0-3a00f7058420"
        fingerprint = "5995c2857b660d92afc197d8a2b0323f4b4f6a0d65d1aeea5d53353c10e8092a"
        creation_date = "2023-06-05"
        last_modified = "2023-06-19"
        threat_name = "Windows.Trojan.PikaBot"
        reference_sample = "59f42ecde152f78731e54ea27e761bba748c9309a6ad1c2fd17f0e8b90f8aed1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $byte_seq0 = { B8 00 00 00 00 CD 2D 90 C3 CC CC CC CC CC CC CC }
        $byte_seq1 = { 64 A1 30 00 00 00 8B 40 ?? C3 }
        $byte_seq2 = { 8B 45 FC 8B 44 85 B4 89 45 F0 8B 45 08 89 45 F8 8B 45 10 C1 E8 02 89 45 F4 }
        $byte_seq3 = { 8B 4C 8D BC ?? 75 FC 33 C0 64 A1 30 00 00 00 8B 40 68 83 E0 70 89 45 FC }
        $byte_seq4 = { 8B 45 F8 8B 4D 0C 89 08 8B 45 F8 83 C0 04 89 45 F8 8B 45 F4 48 89 45 F4 }
        $byte_seq5 = { 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 8B 00 8B 40 18 C3 }
    condition:
        4 of them
}

rule Windows_Trojan_PikaBot_5b220e9c {
    meta:
        author = "Elastic Security"
        id = "5b220e9c-3232-4a86-82b7-31f96c95242c"
        fingerprint = "3a7ba8156f9ad017cdb8630770bf900c198215306a125f6f7dcd845f2c683948"
        creation_date = "2024-02-06"
        last_modified = "2024-02-08"
        threat_name = "Windows.Trojan.PikaBot"
        reference_sample = "d836b06b0118e6d258e318b1cfdc509cacc0859c6a6b3d7c5f4d2525e00d97b2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $byte_seq0 = { 03 44 95 ?? 42 83 FA ?? 7C ?? EB ?? }
        $byte_seq1 = { 3B C1 73 ?? 80 3C 18 ?? 75 ?? C6 04 18 ?? 40 EB ?? }
        $byte_seq2 = { 03 C7 03 C8 0F B6 F9 8A 84 3D 34 FD FF FF 88 84 35 34 FD FF FF }
        $byte_seq3 = { 55 8B EC 83 EC 0C 33 C0 C7 45 F4 05 00 00 00 C7 45 F8 32 00 00 00 8B D0 C7 45 FC C9 FF FF FF }
        $byte_seq4 = { 55 8B EC 51 51 53 56 89 55 F8 89 4D FC 8B 75 FC 8B 45 F8 33 C9 0F A2 89 06 89 5E 04 89 4E 08 89 }
        $byte_seq5 = { 8D 5D E8 59 33 D2 C7 45 F8 04 00 00 00 8A 03 8D 0C 16 43 88 04 39 83 6D F8 01 8D 52 04 75 EE 46 }
        $byte_seq6 = { 55 8B EC 51 51 53 56 89 55 F8 89 4D FC 8B 75 FC 8B 45 F8 33 C9 0F A2 89 06 89 5E 04 89 4E 08 89 }
    condition:
        2 of them
}

