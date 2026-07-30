rule Windows_VulnDriver_RwDrv_a9b9dbaf {
    meta:
        author = "Elastic Security"
        id = "a9b9dbaf-6c4f-48bb-96d5-2aa543ab17af"
        fingerprint = "1e17a9116740bdbe99d89dc8f9119ed4dfe9f613598b3ab07b592fe24f3cb323"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: RwDrv.sys, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.RwDrv"
        reference_sample = "03d2f865b0f5adfdf7cba84ba2ef68e5f601bea134d42d7ec5302e83fcc9c71d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AxtuDrv.pdb"
        $str2 = "RW-Everything Read & Write Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_RwDrv_5b88e19b {
    meta:
        author = "Elastic Security"
        id = "5b88e19b-340c-44ff-bc7a-d61ca993f29b"
        fingerprint = "e07c4f2b18145d788aecbae0beee802e274a9e8616d9cf6e9ebc1f0862b5e398"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: ccf(TestCo), Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.RwDrv"
        reference_sample = "3279593db91bb7ad5b489a01808c645eafafda6cc9c39f50d10ccc30203f2ddf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 63 63 66 28 54 65 73 74 43 6F 29 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RwDrv.pdb"
        $str2 = "RwDrv Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_RwDrv_b2267cc6 {
    meta:
        author = "Elastic Security"
        id = "b2267cc6-d27a-4da7-abdf-acfa328c2f9e"
        fingerprint = "47a99a320c05e961cd10c7e49ba460b5ecce1655ad4b5d64f5cfa9850d55d9d4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: lab-z.com, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.RwDrv"
        reference_sample = "45ba688a4bded8a7e78a4f5b0dc21004e951ddceb014bb92f51a3301d2fbc56a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 6C 61 62 2D 7A 2E 63 6F 6D }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RwDrv.pdb"
        $str2 = "RwDrv Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_RwDrv_762c4453 {
    meta:
        author = "Elastic Security"
        id = "762c4453-e733-4453-97dd-f57993cc27c2"
        fingerprint = "a32ce9fdbe60d25d7001e27e982bfd831155c0088927f26305da9ae12b4414a8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: ChongKim Chan, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.RwDrv"
        reference_sample = "ea0b9eecf4ad5ec8c14aec13de7d661e7615018b1a3c65464bf5eca9bbf6ded3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 6F 6E 67 4B 69 6D 20 43 68 61 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RwDrv.pdb"
        $str2 = "RwDrv Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

