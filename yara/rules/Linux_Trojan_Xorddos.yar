rule Linux_Trojan_Xorddos_2aef46a6 {
    meta:
        author = "Elastic Security"
        id = "2aef46a6-6daf-4f02-b1b4-e512cea12e53"
        fingerprint = "e583729c686b80e5da8e828a846cbd5218a4d787eff1fb2ce84a775ad67a1c4d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 25 64 2D 2D 25 73 5F 25 64 3A 25 73 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_a6572d63 {
    meta:
        author = "Elastic Security"
        id = "a6572d63-f9f3-4dfb-87e6-3b0bafd68a79"
        fingerprint = "fd32a773785f847cdd59d41786a8d8a7ba800a71d40d804aca51286d9bb1e1f0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2ff33adb421a166895c3816d506a63dff4e1e8fa91f2ac8fb763dc6e8df59d6e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C8 0F B6 46 04 0F B6 56 05 C1 E0 08 09 D0 89 45 CC 0F B6 46 06 0F B6 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_e41143e1 {
    meta:
        author = "Elastic Security"
        id = "e41143e1-52d9-45c7-b19f-a5475b18a510"
        fingerprint = "f621a2e8c289772990093762f371bb6d5736085695881e728a0d2c013c2ad1d4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 1E 80 3C 06 00 8D 14 30 8D 4C 37 FF 74 0D EB 36 0F B6 42 01 83 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_0eb147ca {
    meta:
        author = "Elastic Security"
        id = "0eb147ca-ec6d-4a6d-b807-4de8c1eff875"
        fingerprint = "6a1667f585a7bee05d5aece397a22e376562d2b264d3f287874e5a1843e67955"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 45 F0 01 8B 45 F0 89 45 E8 8B 45 E8 83 C4 18 5F 5D C3 55 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_884cab60 {
    meta:
        author = "Elastic Security"
        id = "884cab60-214f-4879-aa51-c00de1a5ffc4"
        fingerprint = "47895e9c8acf66fc853c7947dc53730967d5a4670ef59c96569c577e1a260a72"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E4 8B 51 64 F6 C2 10 75 12 89 CB 89 D1 83 C9 40 89 D0 F0 0F B1 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ba961ed2 {
    meta:
        author = "Elastic Security"
        id = "ba961ed2-b410-4da5-8452-a03cf5f59808"
        fingerprint = "fff4804164fb9ff1f667d619b6078b00a782b81716e217ad2c11df80cb8677aa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 C9 C3 55 89 E5 83 EC 38 C7 45 F8 FF FF FF FF C7 45 FC FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_2084099a {
    meta:
        author = "Elastic Security"
        id = "2084099a-1df6-4481-9d13-3a5bd6a53817"
        fingerprint = "dfb813a5713f0e7bdb5afd500f1e84c6f042c8b1a1d27dd6511dca7f2107c13b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 FC 8B 50 18 8B 45 08 89 50 18 8B 45 FC 8B 40 08 85 C0 }
    condition:
        all of them
}

