rule Windows_VulnDriver_Shield_3daabcad {
    meta:
        author = "Elastic Security"
        id = "3daabcad-848b-480f-86c7-fb28e658fb64"
        fingerprint = "5dd62b574850e9f0aa5f6992f4a3c2ff6726f5cd83a6ba2aa5c0f2472fa892d8"
        creation_date = "2026-07-20"
        last_modified = "2026-08-11"
        description = "Subject: New Horizon Datasys Inc, Version: <= 13.0.0.0"
        threat_name = "Windows.VulnDriver.Shield"
        reference_sample = "b11db76aeab05f29e8f5d51cdfe70898a46fbd50a1245ca1aed39de10aafd401"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 65 77 20 48 6F 72 69 7A 6F 6E 20 44 61 74 61 73 79 73 20 49 6E 63 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 68 00 69 00 65 00 6C 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0c][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0d-\x0d][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Shield.pdb"
        $str2 = "Reboot Restore Standard" wide
        $str3 = "Shield disk filter driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Shield_89bb2993 {
    meta:
        author = "Elastic Security"
        id = "89bb2993-ef12-41e8-a9bd-7eaf0848b7b3"
        fingerprint = "d13388b6b5235f78ee9fa5a12aec92ede792623591c08d016ca1a97327e8832c"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: New Horizon Datasys Inc, Version: <= 13.0.0.0"
        threat_name = "Windows.VulnDriver.Shield"
        reference_sample = "b1547490f3040b1e3668ee195adbf2d312024809915d01a71ed75fae72971a9d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 65 77 20 48 6F 72 69 7A 6F 6E 20 44 61 74 61 73 79 73 20 49 6E 63 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 68 00 69 00 65 00 6C 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0c][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0d-\x0d][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ShieldWP.pdb"
        $str2 = "Reboot Restore Standard" wide
        $str3 = "Shield disk filter driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

