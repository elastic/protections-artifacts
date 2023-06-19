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

