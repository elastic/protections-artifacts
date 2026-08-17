rule Windows_VulnDriver_Mihoyo_bc2c38e2 {
    meta:
        author = "Elastic Security"
        id = "bc2c38e2-f16a-4d2a-9434-19359606d669"
        fingerprint = "1e4ea724d64aae4d7dd792eb7436d683f20ace3eff956c9bddccfc8b6e6ef227"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Mihoyo"
        reference_sample = "8bf84bed9b5fa4576182c84d2f31679dc472acd0f83c9813498e9f71ed9fef3e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $seq1 = { 49 89 40 08 66 41 0F B6 C2 48 98 9C 48 C1 D0 FF 66 41 0F B6 C1 41 8F 00 49 81 EB 04 00 00 00 66 41 03 C4 41 8B 03 66 41 85 D9 33 C6 E9 65 65 0D 00 }
        $seq2 = { 63 00 3A 00 5C 00 77 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 6B 00 6D 00 6C 00 6F 00 67 00 2E 00 6C 00 6F 00 67 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $seq1 and $seq2
}

rule Windows_VulnDriver_Mihoyo_36086ffc {
    meta:
        author = "Elastic Security"
        id = "36086ffc-2928-4645-9646-384932e34357"
        fingerprint = "6bc70c1cb0a692957f33a81024d7bb5e84faa79a8fa2722b86c2c9ce5a087fb9"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: Sex Shop SRL, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Mihoyo"
        reference_sample = "19dba69b48b085d9487cc23a4135f3ef4849c181965bffc55baed9fa6c205429"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 65 78 20 53 68 6F 70 20 53 52 4C }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $seq1 = { 0F 10 48 D0 0F 11 4A D0 0F 10 40 E0 0F 11 42 E0 0F 10 48 F0 0F 11 4A F0 49 83 E8 01 75 AE 0F 10 00 0F 11 02 48 8B 40 10 48 89 42 10 48 8B 1B 33 D2 48 8B CD FF C7 }
        $seq2 = { 75 0C C7 05 A8 35 00 00 3D 00 00 00 EB A3 83 F8 02 75 0C C7 05 97 35 00 00 3E 00 00 00 EB 92 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $seq1 and $seq2
}

rule Windows_VulnDriver_Mihoyo_a1811a83 {
    meta:
        author = "Elastic Security"
        id = "a1811a83-2c4d-4bc0-81ee-d558b810d5f0"
        fingerprint = "1e1e8772bdcf658f0f249507a120d9eab1f882aeffccb031400f4c0be2278200"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: miHoYo Co.,Ltd., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Mihoyo"
        reference_sample = "f7d72d22cd4ad3e44fd617bdb4c90b9a884f4eb045688c0e3fb64dd33e033eaa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 6D 69 48 6F 59 6F 20 43 6F 2E 2C 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $seq1 = { 4D 8B 0A 47 8B 44 0B 08 47 33 04 0B 4C 23 C7 4F 33 04 0B 49 8B C8 49 D1 E8 83 E1 01 48 8B 14 CE 4B 33 94 0B 20 FB FF FF 49 33 D0 4B 89 14 0B 49 83 C3 08 49 81 FB B8 09 00 00 7C C4 4D 8B 0A 45 8B 81 B8 09 00 00 45 33 01 4C 23 C7 4D 33 81 B8 09 00 00 49 8B C8 49 D1 E8 83 E1 01 48 8B 14 CE 49 33 91 D8 04 00 00 49 33 D0 49 89 91 B8 09 00 00 41 83 62 08 00 45 33 C0 }
        $seq2 = { 73 DB 0F B7 C1 48 C1 E0 06 4C 8B 44 38 48 45 84 F6 75 17 48 8D 05 0E 01 00 00 4C 3B C0 75 17 33 C9 E8 8A 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $seq1 and $seq2
}

rule Windows_VulnDriver_Mihoyo_644e6c25 {
    meta:
        author = "Elastic Security"
        id = "644e6c25-17ea-4273-ae4a-23d1a422f8b5"
        fingerprint = "5034d2560b3c3fc802739711f92e83add08959cdfac4688161d0c96f502113e6"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: miHoYo Co.,Ltd."
        threat_name = "Windows.VulnDriver.Mihoyo"
        reference_sample = "edeb35e4341034b2de389017c4884b081a821f34349a620897a2a845c84cb09e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 6D 69 48 6F 59 6F 20 43 6F 2E 2C 4C 74 64 2E }
        $seq1 = { 51 41 80 D9 F8 4C 0F A4 D7 DD 48 8B BC 24 90 00 00 00 49 0F A3 EB 66 41 C1 E2 86 81 EF 44 66 67 0C C1 E0 6F F7 D7 24 95 41 D2 EA 81 C7 E2 58 CC 00 40 D2 F5 F8 81 F7 96 3C B3 4A 48 03 F9 48 0F BF E9 66 44 0F BE D1 D2 D4 48 B8 00 00 00 00 01 00 00 00 }
        $seq2 = { D1 CE F5 0F CE 44 84 CD 57 48 C1 F7 76 31 34 24 40 80 D7 BF 66 FF CF 40 FE C7 5F E9 48 14 02 00 }
        $seq3 = { 66 0F B6 33 80 D9 72 C0 E1 AF 8A 4B 02 41 80 D3 A6 66 44 0F BC DD 66 41 0F A3 E3 48 81 EB 06 00 00 00 40 D2 E6 44 0F 4C DC 4D 0F B7 D8 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $seq1 and $seq2 and $seq3
}

