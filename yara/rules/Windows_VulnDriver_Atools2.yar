rule Windows_VulnDriver_Atools2_9f173b60 {
    meta:
        author = "Elastic Security"
        id = "9f173b60-49b9-4191-9ba4-25f9f113a445"
        fingerprint = "169d8f715a082d5df65a342750afc3082940f4519d2de01664491da7aba52298"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Antiy Labs, Version: <= 2.0.25.709"
        threat_name = "Windows.VulnDriver.Atools2"
        reference_sample = "7026b3aeccd0c647614fb357a887b7c3963661d024355998dbbec363fd5f3854"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 6E 74 69 79 20 4C 61 62 73 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 74 00 6F 00 6F 00 6C 00 73 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x18][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x01]|[\x00-\xc4][\x02-\x02])[\x19-\x19][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\xc5-\xc5][\x02-\x02][\x19-\x19][\x00-\x00])/
        $str1 = "Kernel Call Services" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

