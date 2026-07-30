rule Windows_VulnDriver_TeraByte_11f4312b {
    meta:
        author = "Elastic Security"
        id = "11f4312b-eb41-4244-9f63-6604916541c3"
        fingerprint = "59135ae28806f165a898a7437268c558cf20baf6efc98b215a93a402d96d6a7d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: TeraByte, Inc., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.TeraByte"
        reference_sample = "aa20aa2316cd6d203146bd2bc5b7466ba7b83a8500654a688172bcafa82ab168"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 72 61 42 79 74 65 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 74 00 62 00 6F 00 66 00 6C 00 68 00 65 00 6C 00 70 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "TBOFLHelper.pdb"
        $str2 = "TBOFLHelper" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

