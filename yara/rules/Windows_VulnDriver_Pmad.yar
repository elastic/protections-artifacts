rule Windows_VulnDriver_Pmad_9f74506e {
    meta:
        author = "Elastic Security"
        id = "9f74506e-3bc5-4aad-95b2-73b9c7a76de7"
        fingerprint = "71d5e26015d96836a63dcf226a018c62a400c1961cf84dcb24f519350a5b41f9"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: LeCroy Corp, Version: <= 2.1.2.5"
        threat_name = "Windows.VulnDriver.Pmad"
        reference_sample = "37784d01f84aa4d60c8738f7a75dac1bf712941fc08ed9f32f3e89d044d9c71f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 65 43 72 6F 79 20 43 6F 72 70 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 4D 00 41 00 44 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x04][\x00-\x00][\x02-\x02][\x00-\x00]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "pmad.pdb"
        $str2 = "Physical Memory Access Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

