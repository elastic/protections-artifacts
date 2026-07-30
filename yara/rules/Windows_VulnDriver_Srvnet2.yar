rule Windows_VulnDriver_Srvnet2_9a170718 {
    meta:
        author = "Elastic Security"
        id = "9a170718-ace6-417e-bc35-ab046696e53b"
        fingerprint = "ca0ef4003d893b435526c62e5c08cc44872c36856ff15d838c828f142430d308"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zhuhai liancheng Technology Co., Ltd., Version: <= 10.0.18362.693"
        threat_name = "Windows.VulnDriver.Srvnet2"
        reference_sample = "f6c316e2385f2694d47e936b0ac4bc9b55e279d530dd5e805f0d963cb47c3c0d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 68 75 68 61 69 20 6C 69 61 6E 63 68 65 6E 67 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 52 00 56 00 4E 00 45 00 54 00 32 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x46]|[\x00-\xb9][\x47-\x47])|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x01]|[\x00-\xb4][\x02-\x02])[\xba-\xba][\x47-\x47]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\xb5-\xb5][\x02-\x02][\xba-\xba][\x47-\x47])/
        $str1 = { 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 AE 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6D 00 }
        $str2 = "Server Network driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

