rule Windows_VulnDriver_KSophonX64_348b460b {
    meta:
        author = "Elastic Security"
        id = "348b460b-b57f-4262-bd26-45fdf9992199"
        fingerprint = "87a59508231f3ab08a4be3036d65346459387c4daf0b12df8918728be068aab5"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: PROXIMA BETA PTE. LIMITED, Version: <= 0.0.0.174"
        threat_name = "Windows.VulnDriver.KSophonX64"
        reference_sample = "4ea893c2da9f60590c6223b3c71b13e071d5f700cc3b93f4508b90187ef6091a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 52 4F 58 49 4D 41 20 42 45 54 41 20 50 54 45 2E 20 4C 49 4D 49 54 45 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 53 00 6F 00 70 00 68 00 6F 00 6E 00 5F 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xad][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\xae-\xae][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "\\Device\\HardDiskVolume"
        $str2 = "KSophon_x64" wide
        $str3 = "KSophon_x64 NT Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

