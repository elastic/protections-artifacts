rule Windows_VulnDriver_GameDriverX64_5ddd8a3b {
    meta:
        author = "Elastic Security"
        id = "5ddd8a3b-cecf-471f-bd0e-1f71a5b43526"
        fingerprint = "3434c3beffd106185ac45045cae3c18e6a6dd34b1117558a4d7a9b01cabad4df"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Fedeen Games Limited, Version: <= 7.23.4.7"
        threat_name = "Windows.VulnDriver.GameDriverX64"
        reference_sample = "794bb1fc1b9b86d41d2a296511124a95fe0c43b59c977c702e4f5b368b0f7d4b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 65 64 65 65 6E 20 47 61 6D 65 73 20 4C 69 6D 69 74 65 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 61 00 6D 00 65 00 44 00 72 00 69 00 76 00 65 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x06][\x00-\x00][\x04-\x04][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x07-\x07][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "PwrdDriver.pdb"
        $str2 = "GameDriverX64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_GameDriverX64_ede96f80 {
    meta:
        author = "Elastic Security"
        id = "ede96f80-e31d-4c85-ad57-73bd94b90a20"
        fingerprint = "338430ba85b4e490ef4e149287fccb5adf7228ee238b8b66cf216fdf21ac8139"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Shanghai Yuelong IE Culture Technology Co., Ltd., Version: <= 7.23.4.7"
        threat_name = "Windows.VulnDriver.GameDriverX64"
        reference_sample = "9d396b83647f5233cd93f47caa05e0a0d0dd5dd2f17ba2b0ae5cd1afc0afa69d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 61 6E 67 68 61 69 20 59 75 65 6C 6F 6E 67 20 49 45 20 43 75 6C 74 75 72 65 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 61 00 6D 00 65 00 44 00 72 00 69 00 76 00 65 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x06][\x00-\x00][\x04-\x04][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x07-\x07][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "PwrdDriver.pdb"
        $str2 = "GameDriverX64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_GameDriverX64_955b72f9 {
    meta:
        author = "Elastic Security"
        id = "955b72f9-2e6c-4c9c-baac-070836d82a01"
        fingerprint = "35239fb8bd185d59c63c162c51076510627bf659e760fce7fe7dc048fe3c2f05"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Hunan Goldmind Education Equipment Co., Ltd., Version: <= 7.23.4.7"
        threat_name = "Windows.VulnDriver.GameDriverX64"
        reference_sample = "bf881b14745a870b792c263555c0920a6cc82d36dc3ff29c08a968d028b0fc04"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 6E 61 6E 20 47 6F 6C 64 6D 69 6E 64 20 45 64 75 63 61 74 69 6F 6E 20 45 71 75 69 70 6D 65 6E 74 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 61 00 6D 00 65 00 44 00 72 00 69 00 76 00 65 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x06][\x00-\x00][\x04-\x04][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x07-\x07][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "PwrdDriver.pdb"
        $str2 = "GameDriverX64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_GameDriverX64_7fe38a35 {
    meta:
        author = "Elastic Security"
        id = "7fe38a35-17da-470c-9f11-45265248208c"
        fingerprint = "5d467c2b3343497d0b551246f36583159aa6a9f3c526f0ca42afd5ecbda8077e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Iwplay World Interactive Entertainment Technology Co,Ltd., Version: <= 7.23.4.7"
        threat_name = "Windows.VulnDriver.GameDriverX64"
        reference_sample = "fd08ac95226585436c03b01745c608035bfb15a3a832135589a049cb243cefd9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 77 70 6C 61 79 20 57 6F 72 6C 64 20 49 6E 74 65 72 61 63 74 69 76 65 20 45 6E 74 65 72 74 61 69 6E 6D 65 6E 74 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2C 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 61 00 6D 00 65 00 44 00 72 00 69 00 76 00 65 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x06][\x00-\x00][\x04-\x04][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x07-\x07][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "PwrdDriver.pdb"
        $str2 = "GameDriverX64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_GameDriverX64_b7454da7 {
    meta:
        author = "Elastic Security"
        id = "b7454da7-c556-482e-ad69-eef97e05ee94"
        fingerprint = "9facd8e81ae1ef0b729d3dca891a3153de7ba40cdadfa612cfe39137ae416fb2"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: 完美世界（北京）软件科技发展有限公司, Version: <= 7.22.8.19"
        threat_name = "Windows.VulnDriver.GameDriverX64"
        reference_sample = "7c18489959c26a82fa2703feb972ce14709d2a377e9c044b48b5be8a02b0929e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E5 AE 8C E7 BE 8E E4 B8 96 E7 95 8C EF BC 88 E5 8C 97 E4 BA AC EF BC 89 E8 BD AF E4 BB B6 E7 A7 91 E6 8A 80 E5 8F 91 E5 B1 95 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 61 00 6D 00 65 00 44 00 72 00 69 00 76 00 65 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x15][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x16-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00]|[\x16-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x12][\x00-\x00][\x08-\x08][\x00-\x00]|[\x16-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x13-\x13][\x00-\x00][\x08-\x08][\x00-\x00])/
        $str1 = "PwrdDriver.pdb"
        $str2 = "GameDriverX64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_GameDriverX64_ad4cc4a0 {
    meta:
        author = "Elastic Security"
        id = "ad4cc4a0-fa9b-4659-8312-abd770c6bb46"
        fingerprint = "7013631b0f674af41a43584ec2f9dc6321cdd777cf4cf47ccf09b587f1dbaac9"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Crunchyroll, LLC, Version: <= 7.23.4.7"
        threat_name = "Windows.VulnDriver.GameDriverX64"
        reference_sample = "ca22e593362a8fa4f728e83f6861f983373f61480d0384e26ed149e507706d6a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 72 75 6E 63 68 79 72 6F 6C 6C 2C 20 4C 4C 43 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 61 00 6D 00 65 00 44 00 72 00 69 00 76 00 65 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x06][\x00-\x00][\x04-\x04][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x07-\x07][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "PwrdDriver.pdb"
        $str2 = "GameDriverX64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_GameDriverX64_df3f390e {
    meta:
        author = "Elastic Security"
        id = "df3f390e-f81a-4364-82fd-c2749e39b8a6"
        fingerprint = "b447616c4c13b6cc87552af86b20a2f9f2af80f9645b1f4d76d6c734908dd7c4"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Beijing Beingfungames Technology Co., Ltd., Version: <= 7.23.11.15"
        threat_name = "Windows.VulnDriver.GameDriverX64"
        reference_sample = "e55bfbb979143c6d1bc97129c9b5663639b895f1db605cef578b7f06633c08f6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 42 65 69 6E 67 66 75 6E 67 61 6D 65 73 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 61 00 6D 00 65 00 44 00 72 00 69 00 76 00 65 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x0e][\x00-\x00][\x0b-\x0b][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x0f-\x0f][\x00-\x00][\x0b-\x0b][\x00-\x00])/
        $str1 = "PwrdDriver.pdb"
        $str2 = "GameDriverX64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_GameDriverX64_f1400efc {
    meta:
        author = "Elastic Security"
        id = "f1400efc-3ed4-4ccf-8e9a-766f9daafe7b"
        fingerprint = "ac470ff40888c0238f190f273efd026cc456a35fd8666a5101555065c0573bca"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Fedeen Games Limited, Version: <= 7.23.11.15"
        threat_name = "Windows.VulnDriver.GameDriverX64"
        reference_sample = "f90cab0c3b8159162be3103fcca5bafc27fbf4ec24620900acedaf84b7c0cf30"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 65 64 65 65 6E 20 47 61 6D 65 73 20 4C 69 6D 69 74 65 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 61 00 6D 00 65 00 44 00 72 00 69 00 76 00 65 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x0e][\x00-\x00][\x0b-\x0b][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x0f-\x0f][\x00-\x00][\x0b-\x0b][\x00-\x00])/
        $str1 = "PwrdDriver.pdb"
        $str2 = "GameDriverX64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

