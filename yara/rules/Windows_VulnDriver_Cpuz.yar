rule Windows_VulnDriver_Cpuz_a53d1446 {
    meta:
        author = "Elastic Security"
        id = "a53d1446-ebf7-44f3-843c-2ea5f043e168"
        fingerprint = "1b74df56b73fa8d178a968427480332c6935e023af295e4fff5810bb66db6aab"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: cpuz.sys, Version: 1.0.4.3"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "8c95d28270a4a314299cf50f05dcbe63033b2a555195d2ad2f678e09e00393e6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x04][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x03][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Cpuz_3b6e8aa2 {
    meta:
        author = "Elastic Security"
        id = "3b6e8aa2-058f-439e-90a8-bd333d3a186a"
        fingerprint = "8cb963d82555e4eb0054b28cd9cb3f2d3e09dcb420723c3dbfe8132f4984e962"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.6"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "0484defcf1b5afbe573472753dc2395e528608b688e5c7d1d178164e48e7bed7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x05][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz136_x64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_7d66353e {
    meta:
        author = "Elastic Security"
        id = "7d66353e-88c0-45e0-b759-59a02e03d07c"
        fingerprint = "13339d6cb355f82c3257684fe480360d0cba38bf08f567a66a0e93b4518e77e9"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.5"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "0d3790af5f8e5c945410929e31d06144a471ac82f828afe89a4758a5bbeb7f9f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x04][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz135_x32.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_d4d18c14 {
    meta:
        author = "Elastic Security"
        id = "d4d18c14-c708-4750-8af7-bdb5e437f9b2"
        fingerprint = "cb93af6a4bd1522ac46fd311cfff3c34f1f618c71700daa9949e100624b8c366"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.4.1"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "0e8595217f4457757bed0e3cdea25ea70429732b173bba999f02dc85c7e06d02"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "cpuz141_x32.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_519f80a9 {
    meta:
        author = "Elastic Security"
        id = "519f80a9-2340-4f9e-833b-3fcca896c217"
        fingerprint = "144da6c3199119382f7f3b6644b4463709e1cf8cf9b9bb5d592d642646fd3658"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.4.3"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "11a4b08e70ebc25a1d4c35ed0f8ef576c1424c52b580115b26149bd224ffc768"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x02][\x00-\x00][\x04-\x04][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "cpuz143_x32.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_6f2e7aae {
    meta:
        author = "Elastic Security"
        id = "6f2e7aae-068e-4635-a1ba-574893737fd4"
        fingerprint = "088381bd95edccd920e4fc9a8592a543427c610decf8b3721a35f547300901c3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.3"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "192c0404df5de4cd26f535602573d441e6343eb1e55d82083bcd06d25d6e5cf1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x02][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz133_x64.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_b3dd0b88 {
    meta:
        author = "Elastic Security"
        id = "b3dd0b88-fc4e-4661-a008-1ece15d9a150"
        fingerprint = "a51e89bb3dff1082a7a281936c58e274a3c829d1ad0cbf500221999cfbfb113c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.4.1"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "1be1c99c35434f368d1d41384ce915dcc8d5213e4c160a310006d86e1b9b392c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "cpuz141_x64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_b254e88d {
    meta:
        author = "Elastic Security"
        id = "b254e88d-31e1-42fb-ac93-acd2e9326599"
        fingerprint = "6dff58acec7b153845a203542753289776cf77733570842410fd435f25b1be79"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.8"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "2101d5e80e92c55ecfd8c24fcf2202a206a4fd70195a1378f88c4cc04d336f22"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x07][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x08-\x08][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz138_x64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_6c3a225d {
    meta:
        author = "Elastic Security"
        id = "6c3a225d-2ff1-4655-bb22-de3af9dc0ee4"
        fingerprint = "e97fc239277e2562a1f5308ba1f78085406e27adbf4e2e8736286224665f2f99"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.6"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "2298e838e3c015aedfb83ab18194a2503fe5764a862c294c8b39c550aab2f08e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x05][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz136_x32.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_34844564 {
    meta:
        author = "Elastic Security"
        id = "34844564-1611-4143-a0b2-3ca2aef04b37"
        fingerprint = "5548384c1739f2b2bb49e3496842ec78e05a3ed0499f2d01ab96ef604397c1de"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.3"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "2a9d481ffdc5c1e2cb50cf078be32be06b21f6e2b38e90e008edfc8c4f2a9c4e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x02][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz133_x32.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_7ebc5b10 {
    meta:
        author = "Elastic Security"
        id = "7ebc5b10-adfd-472c-b924-318784ff2bc2"
        fingerprint = "db75266609fca7df872d95e8e595f16ad0aeb6fcc9a71df9d00847a312dff784"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: cpuz.sys, Version: <= 1.0.2.8"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "2c71c9b829fb368e1145ea98e1f6498c5a8c650fe849dc325babac70fc3bc03c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x07][\x00-\x00][\x02-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x08-\x08][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "cpuz_x64.pdb"
        $str2 = "Windows (R) Server 2003 DDK driver" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_e441b19d {
    meta:
        author = "Elastic Security"
        id = "e441b19d-b49b-4420-abd2-3571f15a7602"
        fingerprint = "45659781ff07f39cabe222f8a3588d9a2961d36db0f687fb0fe878db7e7881ad"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.8"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "3301b49b813427fa37a719988fe6446c6f4468dfe15aa246bec8d397f62f6486"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x07][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x08-\x08][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz138_ia64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_8e4b0e76 {
    meta:
        author = "Elastic Security"
        id = "8e4b0e76-9487-4cc4-b6c3-350e2c08c597"
        fingerprint = "8dc5e94d3d9fa38f2b36231f083d0ea183ce63892c333bb102a864dc1becacf0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.4.3"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "34bee22c18ddbddbe115cf1ab55cabf0e482aba1eb2c343153577fb24b7226d3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x02][\x00-\x00][\x04-\x04][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "cpuz143_x64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_b8fd8dd1 {
    meta:
        author = "Elastic Security"
        id = "b8fd8dd1-3803-4122-946a-c85dc5ef47b2"
        fingerprint = "118a163075c3605d4aff4d41eb93f7070a8116dda4dd42c7cf94e83521256323"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: cpuz.sys, Version: <= 1.0.3.2"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "39d8387a283a18b956b9a9df439759104e15bf1214b8bc15de60a99827851c08"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x01][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz132_x64.pdb"
        $str2 = "Windows (R) Codename Longhorn DDK driver" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_a9665f44 {
    meta:
        author = "Elastic Security"
        id = "a9665f44-1e80-4761-9917-e5e24af56881"
        fingerprint = "f4b742cf7ce42f4b4bb7ccc004cec247d24be8f90da78082cf90acb29330e667"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.4.1"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "405a99028c99f36ab0f84a1fd810a167b8f0597725e37513d7430617106501f1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "cpuz141_ia64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_3a5a156e {
    meta:
        author = "Elastic Security"
        id = "3a5a156e-8927-43c2-9757-2cf5dc845112"
        fingerprint = "4fa4c5bd68104860faa505e40996c93c935e99b0a2fdfd1a4d6a37d7283bc620"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.4.0"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "40da0adf588cbb2841a657239d92f24b111d62b173204b8102dd0e014932fe59"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "cpuz140_x32.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_aa1951e3 {
    meta:
        author = "Elastic Security"
        id = "aa1951e3-373b-4022-8bbf-5b8cc3013960"
        fingerprint = "d645798da86f138dfe38dfd8bdb75867b255e2677ec93cede6bddea5f92e29d4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: cpuz.sys, Version: <= 1.0.3.5"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "4ba987cf131e118b5c1b2b9ff333c685086696591d039f2f1ba2e75de35cfd0a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x04][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz135_x64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_f529c070 {
    meta:
        author = "Elastic Security"
        id = "f529c070-f38a-435d-940e-2182d061bbe0"
        fingerprint = "65e1c5209b809de284212fda99236c483cd06d93dcba44b79e1370b53b0e4aa8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.4.3"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "4d5059ec1ebd41284b9cea6ce804596e0f386c09eee25becdd3f6949e94139ba"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x02][\x00-\x00][\x04-\x04][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "cpuz143_ia64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_49ca1882 {
    meta:
        author = "Elastic Security"
        id = "49ca1882-eae8-4e33-9e59-e7e6d7ddcb6e"
        fingerprint = "75a33d65d2c3669dacc95e0218571ce95ee7375338db25528ed68cc026f8df32"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.0.5.7"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "58cb5439e34be4ede6d93c463cb0433c99a100a1c06fca777eda751fd72c07bf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x05-\x05][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x05-\x05][\x00-\x00])/
        $str1 = "cpuz157_x64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_2ab29868 {
    meta:
        author = "Elastic Security"
        id = "2ab29868-fe52-4d49-ab34-f6067484b5e1"
        fingerprint = "b5ed83a1fe1f1bbbd877dae967a32176fbd82c36484ec922efbfedd7496e3cc7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.4"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "592f56b13e7dcaa285da64a0b9a48be7562bd9b0a190208b7c8b7d8de427cf6c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x03][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x04-\x04][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz134_ia64.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_143ae678 {
    meta:
        author = "Elastic Security"
        id = "143ae678-4f01-421b-bc81-320ce19dfb6d"
        fingerprint = "21c149cabcd476bbad75c574049978b8ec9cb1a473b1bc5613b2ac72e35fbca1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.5"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "636b4c1882bcdd19b56370e2ed744e059149c64c96de64ac595f20509efa6220"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x04][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz135_ia64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_4a8299b2 {
    meta:
        author = "Elastic Security"
        id = "4a8299b2-cff2-4f9e-b21d-73f7440a7135"
        fingerprint = "afcaa2e5f2121905a86acb3b5db9adf204675b4ea4e551a7d827e1dda59eb576"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.7"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "6befa481e8cca8084d9ec3a1925782cd3c28ef7a3e4384e034d48deaabb96b63"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz137_ia64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_44c90af4 {
    meta:
        author = "Elastic Security"
        id = "44c90af4-a1e4-4808-b5a5-b6d7e90f651b"
        fingerprint = "1c4aad86ed6a80e46f2c5ae4935e7b15d62b336487bb3c509031691cdfd98703"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.9"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "6c5c6c350c8dd4ca90a8cca0ed1eeca185ebc67b1100935c8f03eb3032aca388"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x08][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x09-\x09][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz139_x32.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_ed492f4c {
    meta:
        author = "Elastic Security"
        id = "ed492f4c-f68b-420d-bb5f-947449af7f45"
        fingerprint = "40ae56e2ff19c93acdaad8421ca73303a75b157c05a57c60ebdfa4943169c078"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.9"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "771015b2620942919bb2e0683476635b7a09db55216d6fbf03534cb18513b20c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x08][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x09-\x09][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz139_ia64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_64edb9e0 {
    meta:
        author = "Elastic Security"
        id = "64edb9e0-fe63-46d5-9c39-cd06e6345b8d"
        fingerprint = "027ce18f7f2f18ed45d1078291b4fcef0347e419ea0ccf5856654f5ede3410ab"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.4.0"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "78d49094913526340d8d0ef952e8fe9ada9e8b20726b77fb88c9fb5d54510663"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "cpuz140_ia64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_41285e2e {
    meta:
        author = "Elastic Security"
        id = "41285e2e-dd42-4d61-8461-b5d61f4aa3af"
        fingerprint = "d2b66c75a3cacdab8ff07183446a8f839f3743b8d135807b6660c07a98d43883"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Beijing Gigabit Times Technology Co., Ltd, Version: <= 1.0.3.1"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "79440da6b8178998bdda5ebde90491c124b1967d295db1449ec820a85dc246dd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 47 69 67 61 62 69 74 20 54 69 6D 65 73 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz_x32.pdb"
        $str2 = "Windows (R) Codename Longhorn DDK driver" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_7af21541 {
    meta:
        author = "Elastic Security"
        id = "7af21541-162a-4878-a7a5-f47995eb9174"
        fingerprint = "d3529386db848436c0080d5736624339dc05616e87ffd2e1cce889fe5483813f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: cpuz.sys, Version: <= 1.0.3.1"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "85db840233e93d8f8f7361d844c70499c7a2cc9ce65cc17ce9eae72a9fa6c2dd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz_x64.pdb"
        $str2 = "Windows (R) Codename Longhorn DDK driver" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_1599e387 {
    meta:
        author = "Elastic Security"
        id = "1599e387-3bf3-495d-ad54-4bd3a2f8c947"
        fingerprint = "22c0b112a107473a712f545986b5e7e182817c2a6dd89c965f5ea4f3c9f43178"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.9"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "8d57e416ea4bb855b78a2ff3c80de1dfbb5dc5ee9bfbdddb23e46bd8619287e2"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x08][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x09-\x09][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz139_x64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_74794ce0 {
    meta:
        author = "Elastic Security"
        id = "74794ce0-2ee0-4dd5-b77f-d072b5e1c97a"
        fingerprint = "424589dee2b7ef46557d33f06208ba9d382465570b9432ce7b79890b035563b7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.2"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "8e92aacd60fca1f09b7257e62caf0692794f5d741c5d1eec89d841e87f2c359c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x01][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz132_x32.pdb"
        $str2 = "Windows (R) Codename Longhorn DDK driver" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_e0562333 {
    meta:
        author = "Elastic Security"
        id = "e0562333-f748-468c-adf5-a720c0803d23"
        fingerprint = "de059f15e4c979e1f3860df945bbb5d2479c8e7382330af9719d5750cd939fff"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.4.0"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "a072197177aad26c31960694e38e2cae85afbab070929e67e331b99d3a418cf4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "cpuz140_x64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_0a6d2276 {
    meta:
        author = "Elastic Security"
        id = "0a6d2276-0c7f-4215-9750-4682f09da027"
        fingerprint = "68ef10752814cdd5057b4ef2430cd4df2cdb14988ae6a70ec9dce1899aa76ea5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.8"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "a3975db1127c331ba541fffff0c607a15c45b47aa078e756b402422ef7e81c2c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x07][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x08-\x08][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz138_x32.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_4e4da707 {
    meta:
        author = "Elastic Security"
        id = "4e4da707-0f70-4d9b-ad79-ae6354407d50"
        fingerprint = "f86742ccc666ef7d4cdf1359212bd15045efc4270e0b2c82d7f715dee06f2f3e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.6"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "aebcbfca180e372a048b682a4859fd520c98b5b63f6e3a627c626cb35adc0399"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x05][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz136_ia64.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_a002946b {
    meta:
        author = "Elastic Security"
        id = "a002946b-8e6d-47a9-a32f-e2a75a2055c3"
        fingerprint = "6809205250dc98008076382e4b6038061d40642031dfe8c0fac43be41a1d02b7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: cpuz.sys, Version: <= 1.0.3.4"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "b7e43374761d9e7718a79009ee13f06ac1fcabcb16955ceb3b421c87c79caa9e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x03][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x04-\x04][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz134_x64.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_44cdfd67 {
    meta:
        author = "Elastic Security"
        id = "44cdfd67-8e0d-475d-9411-7214607e1ab3"
        fingerprint = "acb897afa9b99554543755312aa82bf3341eee70b8c13cf02c170a0261a0665c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.2.6"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "be683cd38e64280567c59f7dc0a45570abcb8a75f1d894853bbbd25675b4adf7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x05][\x00-\x00][\x02-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "cpuz.pdb"
        $str2 = "Windows (R) Server 2003 DDK driver" wide
        $str3 = "CPU-Z Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_eff7b3e3 {
    meta:
        author = "Elastic Security"
        id = "eff7b3e3-5629-4d0b-9dd7-d42ecfbb3b39"
        fingerprint = "1e5b324fe18fc14e4f1cc0caff55e98bc2f614762eac7a1aa8006d38d001bc13"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.4"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "c673f2eed5d0eed307a67119d20a91c8818a53a3cb616e2984876b07e5c62547"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x03][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x04-\x04][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz134_x32.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_c60eacc6 {
    meta:
        author = "Elastic Security"
        id = "c60eacc6-a1bc-4372-a442-9a39ad7c217c"
        fingerprint = "ed368b59a50abe269e4160ff09dd46d02bfa3d8c00283921128f4e14ddbb44be"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.3.7"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "deecbcd260849178de421d8e2f177dce5c63cf67a48abb23a0e3cf3aa3e00578"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "cpuz137_x32.pdb"
        $str2 = "CPUID service" wide
        $str3 = "CPUID Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Cpuz_146d4870 {
    meta:
        author = "Elastic Security"
        id = "146d4870-f68c-4dea-ab6c-b4f9afb23866"
        fingerprint = "089ae074cef666c555f7f8ec157261127c52ef91b3a7841387ef49894d9f5900"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CPUID, Version: <= 1.0.2.6"
        threat_name = "Windows.VulnDriver.Cpuz"
        reference_sample = "eaa5dae373553024d7294105e4e07d996f3a8bd47c770cdf8df79bf57619a8cd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 50 55 49 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 75 00 7A 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x05][\x00-\x00][\x02-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "cpuz.pdb"
        $str2 = "Windows (R) Codename Longhorn DDK driver" wide
        $str3 = "CPU-Z Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

