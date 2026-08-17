rule Windows_VulnDriver_Selfprot_f2783c36 {
    meta:
        author = "Elastic Security"
        id = "f2783c36-418a-455c-abfc-a3ad51ca582e"
        fingerprint = "4a82a5292e055cc300984610e6f2d75fb393b98057fd602b08b37755eb27dff6"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Hubei Century Network Technology Co.,Ltd, Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Selfprot"
        reference_sample = "c46e907886e2158cbc453e767183aecf07887b5ac8848f19684451883d69f5f0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 62 65 69 20 43 65 6E 74 75 72 79 20 4E 65 74 77 6F 72 6B 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 65 00 6C 00 66 00 70 00 72 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "selfprot64.pdb"
        $str2 = "SelfProtect" wide
        $str3 = "SelfProtect Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

