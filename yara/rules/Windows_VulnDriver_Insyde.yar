rule Windows_VulnDriver_Insyde_4c6f78b1 {
    meta:
        author = "Elastic Security"
        id = "4c6f78b1-5640-47f5-a25f-464b7d10766a"
        fingerprint = "f581336f8943452ad98dfc2dbda299cde156dfa21d800b9fd6ccae44bb2a41a3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Insyde Software Corp., Version: <= 100.0.7.0"
        threat_name = "Windows.VulnDriver.Insyde"
        reference_sample = "0d30c6c4fa0216d0637b4049142bc275814fd674859373bd4af520ce173a1c75"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 73 79 64 65 20 53 6F 66 74 77 61 72 65 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 65 00 67 00 77 00 69 00 6E 00 64 00 72 00 76 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x63][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x64-\x64][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x00-\x00][\x00-\x00][\x64-\x64][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "segwindrvx64.pdb"
        $str2 = "SEG Windows Driver x64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Insyde_2191bef6 {
    meta:
        author = "Elastic Security"
        id = "2191bef6-be5f-4f06-bbb5-096c748ec26e"
        fingerprint = "f8ab2514df3c6e937747ae574a943b3a34d5ea1ffa230679f257d1c98701d08f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Insyde Software Corp., Version: <= 100.0.7.0"
        threat_name = "Windows.VulnDriver.Insyde"
        reference_sample = "7164aaff86b3b7c588fc7ae7839cc09c5c8c6ae29d1aff5325adaf5bedd7c9f5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 73 79 64 65 20 53 6F 66 74 77 61 72 65 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 65 00 67 00 77 00 69 00 6E 00 64 00 72 00 76 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x63][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x64-\x64][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x00-\x00][\x00-\x00][\x64-\x64][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "H2OSDE_Driver.pdb"
        $str2 = "SEG Windows Driver x64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Insyde_37c2011b {
    meta:
        author = "Elastic Security"
        id = "37c2011b-6fb8-490d-bc8d-8987373b0638"
        fingerprint = "e1a0152a52ec8e2f93ec34db64dd21ff6fff5b93f90188d2d8dff97f26343132"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Insyde Software Corp., Version: <= 100.0.7.1"
        threat_name = "Windows.VulnDriver.Insyde"
        reference_sample = "b9ae1d53a464bc9bb86782ab6c55e2da8804c80a361139a82a6c8eef30fddd7c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 73 79 64 65 20 53 6F 66 74 77 61 72 65 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 65 00 67 00 77 00 69 00 6E 00 64 00 72 00 76 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x63][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x64-\x64][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x00-\x00][\x00-\x00][\x64-\x64][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00]|[\x00-\x00][\x00-\x00][\x64-\x64][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "SegWinDrvx64.pdb"
        $str2 = "SEG Windows Driver x64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Insyde_311c2afc {
    meta:
        author = "Elastic Security"
        id = "311c2afc-ac2d-4353-9bb6-0a881e53bb16"
        fingerprint = "3dea9593b0e7e8a50effa34c527ae1594e81003a0f094c4718f16b06fb624371"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Insyde Software Corp., Version: <= 5.2.1.1"
        threat_name = "Windows.VulnDriver.Insyde"
        reference_sample = "ce0a4430d090ba2f1b46abeaae0cb5fd176ac39a236888fa363bf6f9fd6036d9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 73 79 64 65 20 53 6F 66 74 77 61 72 65 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 73 00 63 00 66 00 6C 00 61 00 73 00 68 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "iscflashx64.pdb"
        $str2 = "Insyde Flash Utility 64 bit Driver" wide
        $str3 = "iscflashx64.sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Insyde_9198f42c {
    meta:
        author = "Elastic Security"
        id = "9198f42c-9373-4e73-a6c6-2124ebe7eb7c"
        fingerprint = "d98f284075d0fd81dc007ed239892f3a906f1542c03a4bfae2309d687e81bb2b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Insyde Software Corp., Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Insyde"
        reference_sample = "e8d2424037f63aa395085c546aeac0cd7a09567a4e304c509e087d1b3ce199da"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 73 79 64 65 20 53 6F 66 74 77 61 72 65 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4F 00 41 00 54 00 6F 00 6F 00 6C 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "OAToolx64.pdb"
        $str2 = "OATool x64 Driver" wide
        $str3 = "OAToolx64.sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

