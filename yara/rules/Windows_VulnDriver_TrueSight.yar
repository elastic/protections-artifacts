rule Windows_VulnDriver_TrueSight_7429ac81 {
    meta:
        author = "Elastic Security"
        id = "7429ac81-04d5-4946-9fff-abe7be98fc4d"
        fingerprint = "775137e1f402f347504377eb86aa95a522e50237fa3b09db4f11def2af24b609"
        creation_date = "2024-06-21"
        last_modified = "2024-09-09"
        threat_name = "Windows.VulnDriver.TrueSight"
        reference_sample = "bfc2ef3b404294fe2fa05a8b71c7f786b58519175b7202a69fe30f45e607ff1c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 72 00 75 00 65 00 73 00 69 00 67 00 68 00 74 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x03][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x02][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version
}

rule Windows_VulnDriver_TrueSight_0f05afef {
    meta:
        author = "Elastic Security"
        id = "0f05afef-f4db-4af4-b63c-f257bbe786b8"
        fingerprint = "d4d3a33294abae75ce625bd7ea0f8b6de6074ebeacda7e758a5aad53248ffb95"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: Truesight, Version: <= 2.0.2.0"
        threat_name = "Windows.VulnDriver.TrueSight"
        reference_sample = "002744572989f91fd5edf800ffc6baefeea877eca3b8d7c9abbfa5e29b1b3b5e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 72 00 75 00 65 00 73 00 69 00 67 00 68 00 74 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "TrueSight.pdb"
        $str2 = "Truesight" wide
        $str3 = "Antirootkit module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_TrueSight_2e4f09dc {
    meta:
        author = "Elastic Security"
        id = "2e4f09dc-c63a-4846-9f8a-9a7ccf202e44"
        fingerprint = "67b6002fc0790a18df1f975d31c93fbb995ee4ca9c2eef142eb4629366d775c0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Adlice, Version: <= 2.0.2.0"
        threat_name = "Windows.VulnDriver.TrueSight"
        reference_sample = "3807e9a1bc159b9e8fc0c7caad10d7213ff8ed8ad1cea9ea552b093c81bf624b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 64 6C 69 63 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 72 00 75 00 65 00 73 00 69 00 67 00 68 00 74 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "TrueSight.pdb"
        $str2 = "Truesight" wide
        $str3 = "Antirootkit module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_TrueSight_9fe336da {
    meta:
        author = "Elastic Security"
        id = "9fe336da-c693-472b-96a0-444125332d50"
        fingerprint = "674c3da69c4e4492c00de699751144908dde743955a45599f013ee688ef90e4a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: Truesight, Version: <= 3.3.0.0"
        threat_name = "Windows.VulnDriver.TrueSight"
        reference_sample = "5d6c8873e4db456526321973d02bcdc382b9af3c5c2a12ff597e91d4d7ca5c84"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 72 00 75 00 65 00 73 00 69 00 67 00 68 00 74 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "truesight.pdb"
        $str2 = "Truesight" wide
        $str3 = "RogueKiller Antirootkit Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

