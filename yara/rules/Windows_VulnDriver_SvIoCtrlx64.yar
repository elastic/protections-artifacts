rule Windows_VulnDriver_SvIoCtrlx64_0640388e {
    meta:
        author = "Elastic Security"
        id = "0640388e-843b-4b42-8929-7267362c680b"
        fingerprint = "d1552065e031298b1fc6f807b127c2bea8282fc8c94e6032efdba00d8b360873"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Shenzhen Seavo Technology Co.,Ltd, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.SvIoCtrlx64"
        reference_sample = "9ade632e54c3f5e8c75eaf636f2910bad3a8a07d6f078e48c9641d3af1fe811c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 53 65 61 76 6F 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 76 00 49 00 6F 00 43 00 74 00 72 00 6C 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SvIoCtrlx64.pdb"
        $str2 = "Seavo API Driver" wide
        $str3 = "API Driver for Seavo System Device" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

