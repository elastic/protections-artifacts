rule Windows_VulnDriver_Getac_de43338c {
    meta:
        author = "Elastic Security"
        id = "de43338c-87ef-4536-973b-eac1cb15896b"
        fingerprint = "184033de187ff7e426c40ac19257d7e3c83a4d01e9c545aa727525650294e07b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Getac Technology Corp., Version: <= 21.2.0.4"
        threat_name = "Windows.VulnDriver.Getac"
        reference_sample = "0abca92512fc98fe6c2e7d0a33935686fc3acbd0a4c68b51f4a70ece828c0664"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 65 74 61 63 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 74 00 63 00 4B 00 6D 00 64 00 66 00 42 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x15-\x15][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x15-\x15][\x00-\x00][\x00-\x03][\x00-\x00][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x15-\x15][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "GtcKmdfBs.pdb"
        $str2 = "Getac System Service Provider" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Getac_550858a4 {
    meta:
        author = "Elastic Security"
        id = "550858a4-186a-4238-bf0b-da0ad4d058f8"
        fingerprint = "9c3c322cff01c3e6476b68512e1d542c4f3b624efffe3c45d41b8325990ee4ae"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Getac Technology Corp., Version: <= 20.2.0.3"
        threat_name = "Windows.VulnDriver.Getac"
        reference_sample = "e6d1ee0455068b74cf537388c874acb335382876aa9d74586efb05d6cc362ae5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 65 74 61 63 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 74 00 63 00 4B 00 6D 00 64 00 66 00 42 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x14-\x14][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "GtcKmdfBs.pdb"
        $str2 = "Getac System Service Provider" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

