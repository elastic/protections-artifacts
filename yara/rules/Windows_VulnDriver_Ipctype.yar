rule Windows_VulnDriver_Ipctype_02c74529 {
    meta:
        author = "Elastic Security"
        id = "02c74529-02c8-4f44-b604-d0451e337672"
        fingerprint = "b37f90a35ebddf7475930f9b1598a8301ddbec5e7e06880f99ab0fdcc3a2cf31"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Digital Electronics Corporation, Version: <= 1.0.2.0"
        threat_name = "Windows.VulnDriver.Ipctype"
        reference_sample = "8e2acce10d704c8b511c8b6211a2be5d8e4ade91ebcbda2ac10018e4c0ae99fb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 69 67 69 74 61 6C 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 70 00 63 00 74 00 79 00 70 00 65 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "ipctype.pdb"
        $str2 = "IPCType Device Driver for 64bit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

