rule Windows_VulnDriver_NSecKrnl_182639a6 {
    meta:
        author = "Elastic Security"
        id = "182639a6-5389-4567-8681-91cb63311298"
        fingerprint = "116873acd84f61a9fec024a205e1f1f6a1052d4d0d9b5e285fac0284c3b95063"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 3.7.100.20515"
        threat_name = "Windows.VulnDriver.NSecKrnl"
        reference_sample = "053b5bc1d35c76f2e9574f8403c2f5ce07b9a44d00495ce546662d4c0476fd2d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 53 00 65 00 63 00 4B 00 72 00 6E 00 6C 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x63][\x00-\x00]|[\x07-\x07][\x00-\x00][\x03-\x03][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x4f]|[\x00-\x22][\x50-\x50])[\x64-\x64][\x00-\x00]|[\x07-\x07][\x00-\x00][\x03-\x03][\x00-\x00][\x23-\x23][\x50-\x50][\x64-\x64][\x00-\x00])/
        $str1 = "nskrnl-x86.pdb"
        $str2 = "NSecKrnl" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_NSecKrnl_6a5d3ceb {
    meta:
        author = "Elastic Security"
        id = "6a5d3ceb-d83d-45b3-a2d9-6590884335b6"
        fingerprint = "99dbd9def298ce7f312b9ac825ffb40b386743fd333d54b61f571a732ff645ae"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: NSecKrnl, Version: <= 3.6.12.2001"
        threat_name = "Windows.VulnDriver.NSecKrnl"
        reference_sample = "8f0aed4470879c2556689da8fdca417ca03d75cc6ef53feb2331eddb84e07e58"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 53 00 65 00 63 00 4B 00 72 00 6E 00 6C 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x06-\x06][\x00-\x00][\x03-\x03][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xd0][\x07-\x07])[\x0c-\x0c][\x00-\x00]|[\x06-\x06][\x00-\x00][\x03-\x03][\x00-\x00][\xd1-\xd1][\x07-\x07][\x0c-\x0c][\x00-\x00])/
        $str1 = "NSecKrnl64.pdb"
        $str2 = "NSecKrnl" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_NSecKrnl_b3a0c704 {
    meta:
        author = "Elastic Security"
        id = "b3a0c704-0081-4c3d-86c3-ea6aa43678ed"
        fingerprint = "8bdd30663681d5aef08dc63791e1486a2ff7218df7d9a9e96fb2a65b012a00e7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Shandong Anzai Information Technology CO.,Ltd., Version: <= 3.7.42.5591"
        threat_name = "Windows.VulnDriver.NSecKrnl"
        reference_sample = "bfcb8d9fdcf46bd55e9e1bb146d4358510493973620ebaace3dd2e618f251b55"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 61 6E 64 6F 6E 67 20 41 6E 7A 61 69 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 4F 2E 2C 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 53 00 65 00 63 00 4B 00 72 00 6E 00 6C 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x29][\x00-\x00]|[\x07-\x07][\x00-\x00][\x03-\x03][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x14]|[\x00-\xd6][\x15-\x15])[\x2a-\x2a][\x00-\x00]|[\x07-\x07][\x00-\x00][\x03-\x03][\x00-\x00][\xd7-\xd7][\x15-\x15][\x2a-\x2a][\x00-\x00])/
        $str1 = "NSecKrnl64.pdb"
        $str2 = "NSecKrnl" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

