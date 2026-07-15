rule Windows_VulnDriver_Elby_65b09743 {
    meta:
        author = "Elastic Security"
        id = "65b09743-029d-456a-b7f4-3cd055a0e0e2"
        fingerprint = "88bfab229f2f2d66b4c732a6548ee6f31e6b0905eeea3b8f0f874094c1dbc98a"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: ElbyCDIO.sys, Version: 6.0.3.2"
        threat_name = "Windows.VulnDriver.Elby"
        reference_sample = "eea53103e7a5a55dc1df79797395a2a3e96123ebd71cdd2db4b1be80e7b3f02b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 6C 00 62 00 79 00 43 00 44 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x06][\x00-\x00])([\x00-\x02][\x00-\x00])([\x00-\x03][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x06][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Elby_1aeb3f45 {
    meta:
        author = "Elastic Security"
        id = "1aeb3f45-500b-48de-a9e1-481ab8452e5d"
        fingerprint = "0d5a53a71f350b0a74ca8edca15f16bc1bf3e0e32d0b2ae08f088717da2a28b6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: ElbyCDIO.sys, Version: <= 3.0.0.0"
        threat_name = "Windows.VulnDriver.Elby"
        reference_sample = "07af8c5659ad293214364789df270c0e6d03d90f4f4495da76abc2d534c64d88"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 6C 00 62 00 79 00 43 00 44 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "CDRTools" wide
        $str2 = "ElbyCD Windows NT/2000 I/O driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Elby_6abed6fb {
    meta:
        author = "Elastic Security"
        id = "6abed6fb-9095-4554-bbf2-f2eb570e4b56"
        fingerprint = "c39321a9da77a0c8c0a4d28e7544d1ecfa41fcace72403842531b9033cb0c0ca"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Elaborate Bytes AG, Version: <= 6.0.3.2"
        threat_name = "Windows.VulnDriver.Elby"
        reference_sample = "238046cfe126a1f8ab96d8b62f6aa5ec97bab830e2bae5b1b6ab2d31894c79e4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 6C 61 62 6F 72 61 74 65 20 42 79 74 65 73 20 41 47 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 6C 00 62 00 79 00 43 00 44 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x01][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "ElbyCDIO.pdb"
        $str2 = "CDRTools" wide
        $str3 = "ElbyCD Windows x64 I/O driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Elby_4ea48bf6 {
    meta:
        author = "Elastic Security"
        id = "4ea48bf6-4ca8-477e-9a62-3b86b125bfd5"
        fingerprint = "ae00907e80aee147225b351064098ff49d4431db8443266ac21ba793020753cf"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: ElbyCDIO.sys, Version: <= 5.1.0.1"
        threat_name = "Windows.VulnDriver.Elby"
        reference_sample = "83a1fabf782d5f041132d7c7281525f6610207b38f33ff3c5e44eb9444dd0cbc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 6C 00 62 00 79 00 43 00 44 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ElbyCDIO.pdb"
        $str2 = "CDRTools" wide
        $str3 = "ElbyCD Windows NT/2000/XP I/O driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Elby_8838db2c {
    meta:
        author = "Elastic Security"
        id = "8838db2c-dc45-43bd-9efa-bc25c2968696"
        fingerprint = "c947976b38173d7de55a98b45adf8f57490c6fa3521b5a52bc07f69393740517"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: ElbyCDIO.sys, Version: <= 4.2.0.0"
        threat_name = "Windows.VulnDriver.Elby"
        reference_sample = "af16c36480d806adca881e4073dcd41acb20c35ed0b1a8f9bd4331de655036e1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 6C 00 62 00 79 00 43 00 44 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "CDRTools" wide
        $str2 = "ElbyCD Windows NT/2000/XP I/O driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Elby_eaf62795 {
    meta:
        author = "Elastic Security"
        id = "eaf62795-e8f4-48cf-bba8-b690495253e5"
        fingerprint = "a0119de52085c3d7e13647fb96b50d530db4eb1c55604d1e5a7e77c495f6ab34"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Elaborate Bytes AG, Version: <= 6.0.3.2"
        threat_name = "Windows.VulnDriver.Elby"
        reference_sample = "b9ad7199c00d477ebbc15f2dcf78a6ba60c2670dad0ef0994cebccb19111f890"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 6C 61 62 6F 72 61 74 65 20 42 79 74 65 73 20 41 47 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 6C 00 62 00 79 00 43 00 44 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x01][\x00-\x00][\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "ElbyCDIO.pdb"
        $str2 = "CDRTools" wide
        $str3 = "ElbyCD Windows NT/2000/XP I/O driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

