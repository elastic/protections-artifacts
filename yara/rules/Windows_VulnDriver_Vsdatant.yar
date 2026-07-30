rule Windows_VulnDriver_Vsdatant_dd40151b {
    meta:
        author = "Elastic Security"
        id = "dd40151b-d661-4a57-8d4d-c9091d68c652"
        fingerprint = "be2a6cc9f4e5f2fb3e5365d22c3a9224250b525fe5310a7cd0df83e785b0dd87"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Check Point Software Technologies Ltd., Version: <= 14.1.32.0"
        threat_name = "Windows.VulnDriver.Vsdatant"
        reference_sample = "1c43f33573a0815c5edc5e18ba1038afdd11f55a7cd8b08ba59b8f7357117e4c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 65 63 6B 20 50 6F 69 6E 74 20 53 6F 66 74 77 61 72 65 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 53 00 44 00 41 00 54 00 41 00 4E 00 54 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0d][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0e-\x0e][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x0e-\x0e][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x1f][\x00-\x00]|[\x01-\x01][\x00-\x00][\x0e-\x0e][\x00-\x00][\x00-\x00][\x00-\x00][\x20-\x20][\x00-\x00])/
        $str1 = "vsdatant.pdb"
        $str2 = "ZoneAlarm" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

