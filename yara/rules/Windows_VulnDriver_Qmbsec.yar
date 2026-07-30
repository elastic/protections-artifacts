rule Windows_VulnDriver_Qmbsec_13e922a8 {
    meta:
        author = "Elastic Security"
        id = "13e922a8-abf2-452a-ba43-e1ce5fd4b10f"
        fingerprint = "f235ac05a4442b63c173a2cecea25a16942914fed7b9a9674c0f2f81f0515800"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Early Launch Anti-malware Publisher, Version: <= 1.0.10.52"
        threat_name = "Windows.VulnDriver.Qmbsec"
        reference_sample = "51745c658c506484ed79e2d71862b36351bac95a897ddc41aaeb9ba5bdfb2a37"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 45 61 72 6C 79 20 4C 61 75 6E 63 68 20 41 6E 74 69 2D 6D 61 6C 77 61 72 65 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 71 00 6D 00 62 00 73 00 65 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x33][\x00-\x00][\x0a-\x0a][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x34-\x34][\x00-\x00][\x0a-\x0a][\x00-\x00])/
        $str1 = "qmbsec.pdb"
        $str2 = { 35 75 11 81 A1 7B B6 5B 2D 00 71 9A A8 52 21 6A 57 57 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

