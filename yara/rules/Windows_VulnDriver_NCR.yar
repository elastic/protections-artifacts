rule Windows_VulnDriver_NCR_d77e8532 {
    meta:
        author = "Elastic Security"
        id = "d77e8532-82af-4f19-a122-de172bf000f0"
        fingerprint = "4f808bfa7573440a2158713f8bff34dc7eb69ea90500b4234c29561ceb12a5ab"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NCR Corporation, Version: <= 2.20.0.7"
        threat_name = "Windows.VulnDriver.NCR"
        reference_sample = "0f30ecd4faec147a2335a4fc031c8a1ac9310c35339ebeb651eb1429421951a0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 43 52 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 61 00 64 00 48 00 77 00 4D 00 67 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x13][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x14-\x14][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x06][\x00-\x00][\x00-\x00][\x00-\x00]|[\x14-\x14][\x00-\x00][\x02-\x02][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RadHwMgr.pdb"
        $str2 = "IOCTL_RADHWMGR_READ_IO"
        $str3 = "Radiant Systems, Inc.  Hardware Manager driver" wide
        $str4 = "Radiant Hardware Manager for P15xx Platform" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_NCR_a35dc334 {
    meta:
        author = "Elastic Security"
        id = "a35dc334-8052-4125-9afd-5de772b25be3"
        fingerprint = "b6a6eb3332323fa56bdf86dc30f6ad0e7350153ca3be45d49a2d70527bb845d6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.3.2.1"
        threat_name = "Windows.VulnDriver.NCR"
        reference_sample = "5f84dc9d30e167c69e68c5812bef5526377cd544b226b569a2e21584371a7b70"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 63 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "CcProtect.pdb"
        $str2 = "CnCrypt Protect Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_NCR_cb57babd {
    meta:
        author = "Elastic Security"
        id = "cb57babd-9c7b-4ff2-9f11-f41bf30b8e23"
        fingerprint = "7cef0bae1ae6dbc708cc1f95b8b7c9fcb484a02ce950c2b1dbc456db7d1b165a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.33.0.0"
        threat_name = "Windows.VulnDriver.NCR"
        reference_sample = "7c8ad57b3a224fdc2aac9dd2d7c3624f1fcd3542d4db804de25a90155657e2cc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 61 00 64 00 48 00 77 00 4D 00 67 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x20][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x21-\x21][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RadHwMgr.pdb"
        $str2 = "IOCTL_RADHWMGR_READ_IO"
        $str3 = "NCR Corporation Hardware Manager driver" wide
        $str4 = "Radiant Hardware Manager for P15xx Platform" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

