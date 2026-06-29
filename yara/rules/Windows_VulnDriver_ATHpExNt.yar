rule Windows_VulnDriver_ATHpExNt_1738382c {
    meta:
        author = "Elastic Security"
        id = "1738382c-7b41-4910-98a8-4c7421df7442"
        fingerprint = "6e5d80463312c6aa2226ba8fd4ca5da790ed0b6ddf66c3c14a24a203fd6dd491"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AhnLab, Inc., Version: <= 1.0.0.2"
        threat_name = "Windows.VulnDriver.ATHpExNt"
        reference_sample = "fa0902daefbd9e716faaac8e854144ea0573e2a41192796f3b3138fe7a1d19f1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 68 6E 4C 61 62 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 54 00 48 00 70 00 45 00 78 00 4E 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ATHpExNt.pdb"
        $str2 = "AhnLab Security Product" wide
        $str3 = "Sample Driver (AMD64)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

