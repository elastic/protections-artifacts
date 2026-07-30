rule Windows_VulnDriver_Sandra_5d112feb {
    meta:
        author = "Elastic Security"
        id = "5d112feb-dc0a-464c-9753-695bb510f5a8"
        fingerprint = "13572e1155a5417549508952504b891f0e4f40cb6ff911bdda6f152c051c401c"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: SANDRA, Version: 10.12.0.0"
        threat_name = "Windows.VulnDriver.Sandra"
        reference_sample = "3a364a7a3f6c0f2f925a060e84fb18b16c118125165b5ea6c94363221dc1b6de"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 41 00 4E 00 44 00 52 00 41 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x0c][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x0b][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Sandra_612a7a16 {
    meta:
        author = "Elastic Security"
        id = "612a7a16-b616-4a70-9994-cb5aebfa0ca9"
        fingerprint = "ead3bd8256fbb5d26c4a177298a5cdd14e5eeb73d9336999c0a68ece9efa2d55"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: sandra.sys, Version: 10.12.0.0"
        threat_name = "Windows.VulnDriver.Sandra"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 61 00 6E 00 64 00 72 00 61 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x0c][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x0b][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Sandra_81e6c38d {
    meta:
        author = "Elastic Security"
        id = "81e6c38d-427b-4a56-98aa-6abcde2a0270"
        fingerprint = "997e5ead529970442fe3f80b9875ae745977f6e5a38b50bf5d4a64f9f5d49d12"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SiSoftware Ltd, Version: <= 15.18.1.1"
        threat_name = "Windows.VulnDriver.Sandra"
        reference_sample = "0eab16c7f54b61620277977f8c332737081a46bc6bbde50742b6904bdd54f502"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 69 53 6F 66 74 77 61 72 65 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 41 00 4E 00 44 00 52 00 41 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x11][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x12-\x12][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x12-\x12][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]|[\x12-\x12][\x00-\x00][\x0f-\x0f][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "SANDRA.pdb"
        $str2 = "SiSoftware Sandra" wide
        $str3 = "Sandra Device Driver (x64)(Unicode)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Sandra_5f32c12f {
    meta:
        author = "Elastic Security"
        id = "5f32c12f-cb12-4fd5-8813-907b0b6b4aad"
        fingerprint = "4e653f1446caea584d747aac6d93dc5fa5391d0f092a9f001f504222fe432ce1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SiSoftware LTD, Version: <= 10.2.1.1"
        threat_name = "Windows.VulnDriver.Sandra"
        reference_sample = "1284a1462a5270833ec7719f768cdb381e7d0a9c475041f9f3c74fa8eea83590"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 69 53 6F 66 74 77 61 72 65 20 4C 54 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 41 00 4E 00 44 00 52 00 41 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x0a-\x0a][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "SANDRA.pdb"
        $str2 = "SiSoftware Sandra" wide
        $str3 = "Sandra Device Driver (Win32 x86)(Unicode)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Sandra_11b4de5a {
    meta:
        author = "Elastic Security"
        id = "11b4de5a-a9ed-48dc-8aac-1da50f4429bf"
        fingerprint = "fbe89322c7c52e01a55e9ab02f4752c0f86a35192eee15f44d17b9ca1f98561e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SiSoftware Ltd, Version: <= 10.11.1.1"
        threat_name = "Windows.VulnDriver.Sandra"
        reference_sample = "1aaf4c1e3cb6774857e2eef27c17e68dc1ae577112e4769665f516c2e8c4e27b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 69 53 6F 66 74 77 61 72 65 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 41 00 4E 00 44 00 52 00 41 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x0a][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0b-\x0b][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x0b-\x0b][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]|[\x0b-\x0b][\x00-\x00][\x0a-\x0a][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "SANDRA.pdb"
        $str2 = "SiSoftware Sandra" wide
        $str3 = "Sandra Device Driver (Win64 x64)(Unicode)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Sandra_bf6f6023 {
    meta:
        author = "Elastic Security"
        id = "bf6f6023-e02c-4371-a6a5-115ff29f3559"
        fingerprint = "f898f2e0d6250a98c104ba6ff705fb1b25dd556aea7bd3ca833cd8282eca492b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SiSoftware LTD, Version: <= 10.3.1.1"
        threat_name = "Windows.VulnDriver.Sandra"
        reference_sample = "881bca6dc2dafe1ae18aeb59216af939a3ac37248c13ed42ad0e1048a3855461"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 69 53 6F 66 74 77 61 72 65 20 4C 54 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 41 00 4E 00 44 00 52 00 41 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]|[\x03-\x03][\x00-\x00][\x0a-\x0a][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "SANDRA.pdb"
        $str2 = "SiSoftware Sandra" wide
        $str3 = "Sandra Device Driver (Win64 x64)(Unicode)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Sandra_18dbc89b {
    meta:
        author = "Elastic Security"
        id = "18dbc89b-0846-42de-b171-ee4f879edd2a"
        fingerprint = "1507b8cac4aa9af4f4b240fb42fa66a428316c804d0a8c19e100f553e25bfefc"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SiSoftware Ltd, Version: <= 10.7.1.1"
        threat_name = "Windows.VulnDriver.Sandra"
        reference_sample = "b019ebd77ac19cdd72bba3318032752649bd56a7576723a8ae1cccd70ee1e61a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 69 53 6F 66 74 77 61 72 65 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 41 00 4E 00 44 00 52 00 41 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x07-\x07][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]|[\x07-\x07][\x00-\x00][\x0a-\x0a][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "SANDRA.pdb"
        $str2 = "SiSoftware Sandra" wide
        $str3 = "Sandra Device Driver (Win32 x86)(Unicode)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Sandra_a01afd7b {
    meta:
        author = "Elastic Security"
        id = "a01afd7b-c290-421c-adeb-f232bcacbb4b"
        fingerprint = "1308d41d52a89df089775672ed7f22b2ce59609c257863a2583b625949037fed"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SiSoftware Ltd, Version: <= 15.18.1.1"
        threat_name = "Windows.VulnDriver.Sandra"
        reference_sample = "cbf74bed1a4d3d5819b7c50e9d91e5760db1562d8032122edac6f0970f427183"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 69 53 6F 66 74 77 61 72 65 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 41 00 4E 00 44 00 52 00 41 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x11][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x12-\x12][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x12-\x12][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]|[\x12-\x12][\x00-\x00][\x0f-\x0f][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "SANDRA.pdb"
        $str2 = "SiSoftware Sandra" wide
        $str3 = "Sandra Device Driver (IA64)(Unicode)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Sandra_10f04f46 {
    meta:
        author = "Elastic Security"
        id = "10f04f46-eace-4f23-b0fe-5dcada870880"
        fingerprint = "7e135e5a3e8938e38df70eebb7c3a2aa250b97bfdcaae6e8a88c4b2d94f26349"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: SiSoftware Ltd, Version: <= 15.18.1.1"
        threat_name = "Windows.VulnDriver.Sandra"
        reference_sample = "d7c79238f862b471740aff4cc3982658d1339795e9ec884a8921efe2e547d7c3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 69 53 6F 66 74 77 61 72 65 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 41 00 4E 00 44 00 52 00 41 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x11][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x12-\x12][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x12-\x12][\x00-\x00][\x0f-\x0f][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]|[\x12-\x12][\x00-\x00][\x0f-\x0f][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "SANDRA.pdb"
        $str2 = "SiSoftware Sandra" wide
        $str3 = "Sandra Device Driver (x86)(Unicode)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

