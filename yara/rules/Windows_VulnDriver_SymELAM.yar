rule Windows_VulnDriver_SymELAM_791cdbf0 {
    meta:
        author = "Elastic Security"
        id = "791cdbf0-50c3-439c-be33-6a5ef0441e3e"
        fingerprint = "7d05e2aeb59a156f6f385c12c2967017a3cb6a1392cfba278042ab6bcb77103c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Early Launch Anti-malware Publisher, Version: <= 2.5.0.120"
        threat_name = "Windows.VulnDriver.SymELAM"
        reference_sample = "021badff5a3c84ee422d9fa40a842f89b1c60e0164eabd58da7374327ea99d3c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 45 61 72 6C 79 20 4C 61 75 6E 63 68 20 41 6E 74 69 2D 6D 61 6C 77 61 72 65 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 79 00 6D 00 45 00 4C 00 41 00 4D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x77][\x00-\x00][\x00-\x00][\x00-\x00]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x78-\x78][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SymELAM.pdb"
        $str2 = "Broadcom ELAM" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

