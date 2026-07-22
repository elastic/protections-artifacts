rule Windows_VulnDriver_PanMonFlt_3eb2ad30 {
    meta:
        author = "Elastic Security"
        id = "3eb2ad30-f6a9-479f-b8a1-e1d20551ecbd"
        fingerprint = "48656500d9e4d4a48ee4f60ec4dd9cf008b4d66321585601b0c2d0b72b459ba4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: PAN YAZILIM BILISIM TEKNOLOJILERI TICARET LTD. STI., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.PanMonFlt"
        reference_sample = "7e0124fcc7c95fdc34408cf154cb41e654dade8b898c71ad587b2090b1da30d7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 41 4E 20 59 41 5A 49 4C 49 4D 20 42 49 4C 49 53 49 4D 20 54 45 4B 4E 4F 4C 4F 4A 49 4C 45 52 49 20 54 49 43 41 52 45 54 20 4C 54 44 2E 20 53 54 49 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 61 00 6E 00 4D 00 6F 00 6E 00 46 00 6C 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "PanMonFlt.pdb"
        $str2 = "PanCafe Manager" wide
        $str3 = "PanCafe Manager File Monitor" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

