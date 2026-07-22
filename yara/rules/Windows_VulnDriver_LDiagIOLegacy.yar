rule Windows_VulnDriver_LDiagIOLegacy_4059aeeb {
    meta:
        author = "Elastic Security"
        id = "4059aeeb-f2e2-4047-bd97-eb5973457fa0"
        fingerprint = "bfff0f670022e3e406cb2b4db84c02bbb8d9e3f4d9c08172b7e8660113b7fb16"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: LENOVO, Version: <= 3.1.0.4000"
        threat_name = "Windows.VulnDriver.LDiagIOLegacy"
        reference_sample = "68ca1b5151181a98cd6da55d6dfd6ef0c94f0cf9379be37a8f86dd996d677946"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 45 4E 4F 56 4F }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 44 00 69 00 61 00 67 00 49 00 4F 00 5F 00 6C 00 65 00 67 00 61 00 63 00 79 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0e]|[\x00-\x9f][\x0f-\x0f])[\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\xa0-\xa0][\x0f-\x0f][\x00-\x00][\x00-\x00])/
        $str1 = "ldiagio_legacy.pdb"
        $str2 = "LDiagIO for Windows XP/2003, installed only on legacy mode" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

