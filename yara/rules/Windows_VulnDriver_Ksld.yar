rule Windows_VulnDriver_Ksld_c608656e {
    meta:
        author = "Elastic Security"
        id = "c608656e-cc7f-47f8-9b45-515c2cfd496f"
        fingerprint = "3d588cc95a7f07fb80f8c5361b2a43397c2a67690cde6a9eec736d2efc7db4bc"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows, Version: <= 1.1.25041.64017"
        threat_name = "Windows.VulnDriver.Ksld"
        reference_sample = "2b3195346d9b62b08bb61bb61f0da20b2abb0c726186c09a2e4fa926baacbfc5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 53 00 4C 00 44 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x60]|[\x00-\xd0][\x61-\x61])|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\xf9]|[\x00-\x10][\xfa-\xfa])[\xd1-\xd1][\x61-\x61]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x11-\x11][\xfa-\xfa][\xd1-\xd1][\x61-\x61])/
        $str1 = "KSLD.pdb"
        $str2 = "Microsoft Malware Protection" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

