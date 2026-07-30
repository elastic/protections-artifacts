rule Windows_VulnDriver_Tboflhelper_413ac8c7 {
    meta:
        author = "Elastic Security"
        id = "413ac8c7-c12b-43f9-9da8-8bc5536fc547"
        fingerprint = "1bfda475a84ec6b159f702880a4f612142eab783777cdee3ba56e71ff4b7d4bd"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: TeraByte Unlimited SHA1, Version: <= 1.0.1.0"
        threat_name = "Windows.VulnDriver.Tboflhelper"
        reference_sample = "265259015d4fda3e9d14b7740b8153b9097ab054cf6873b46f9fefdc97266d35"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 72 61 42 79 74 65 20 55 6E 6C 69 6D 69 74 65 64 20 53 48 41 31 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 74 00 62 00 6F 00 66 00 6C 00 68 00 65 00 6C 00 70 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "TBOFLHelper.pdb"
        $str2 = "TBOFLHelper" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

