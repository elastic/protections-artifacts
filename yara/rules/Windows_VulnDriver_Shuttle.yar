rule Windows_VulnDriver_Shuttle_21e85eb9 {
    meta:
        author = "Elastic Security"
        id = "21e85eb9-047f-4caa-9909-1127fe2d7c77"
        fingerprint = "31002ac8e5e35ffca4d387011f73459e9e09c173e11f3aa09b5cca241062fb3d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Shuttle Inc., Version: <= 1.0.5.0"
        threat_name = "Windows.VulnDriver.Shuttle"
        reference_sample = "21ccdd306b5183c00ecfd0475b3152e7d94b921e858e59b68a03e925d1715f21"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 75 74 74 6C 65 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 77 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00])/
        $str1 = "HwRwDrv.pdb"
        $str2 = "Hardware read & write driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

