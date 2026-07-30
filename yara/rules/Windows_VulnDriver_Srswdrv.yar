rule Windows_VulnDriver_Srswdrv_0499df04 {
    meta:
        author = "Elastic Security"
        id = "0499df04-86c3-4d63-87d0-7accd4e11f23"
        fingerprint = "381462a80523cba882d56f4c26fdb707c8a77a23d6436643f8a1647dd5454694"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: WDKTestCert ddhankecha,132886868762491660, Version: <= 5.0.3.0"
        threat_name = "Windows.VulnDriver.Srswdrv"
        reference_sample = "57414e532a7a10ae7af7fa6294d1d95ad4d9d506882258c5e59d53b4e4f2c91a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 64 64 68 61 6E 6B 65 63 68 61 2C 31 33 32 38 38 36 38 36 38 37 36 32 34 39 31 36 36 30 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 72 00 73 00 77 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "srswdrv64.pdb"
        $str2 = "SRSETUPWIN" wide
        $str3 = "SRSETUPWIN Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

