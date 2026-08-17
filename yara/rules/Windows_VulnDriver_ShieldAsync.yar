rule Windows_VulnDriver_ShieldAsync_60033c4f {
    meta:
        author = "Elastic Security"
        id = "60033c4f-72ea-4b51-824c-102b0210b6d0"
        fingerprint = "15d3cf4787b870632f0958ef41864876db629174a9b2d1fc79443595dc2f4b97"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: New Horizon Datasys Inc, Version: <= 13.0.0.0"
        threat_name = "Windows.VulnDriver.ShieldAsync"
        reference_sample = "da3315363989b564a1b8b690bddfeb3bd81c1690a3da5813ca0c46a715fe94b0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 65 77 20 48 6F 72 69 7A 6F 6E 20 44 61 74 61 73 79 73 20 49 6E 63 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 68 00 69 00 65 00 6C 00 64 00 2D 00 61 00 73 00 79 00 6E 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0c][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0d-\x0d][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Shield.pdb"
        $str2 = "Reboot Restore Standard" wide
        $str3 = "Shield async disk filter driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

