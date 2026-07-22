rule Windows_VulnDriver_Mbamchameleon_c1c7b973 {
    meta:
        author = "Elastic Security"
        id = "c1c7b973-b8d8-4d7f-b367-3f0e5935aa47"
        fingerprint = "36c3ae176cb2b7994407b73e11638d6657de5af8820f2c9ab530cf483940dfab"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Malwarebytes Corporation, Version: <= 3.0.0.155"
        threat_name = "Windows.VulnDriver.Mbamchameleon"
        reference_sample = "0025d232ed0ff9a572f8004094cfe21f62070db832398345425554334e036da6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 61 6C 77 61 72 65 62 79 74 65 73 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6D 00 62 00 61 00 6D 00 63 00 68 00 61 00 6D 00 65 00 6C 00 65 00 6F 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x9a][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x9b-\x9b][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "MbamChameleon.pdb"
        $str2 = "Malwarebytes Chameleon" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

