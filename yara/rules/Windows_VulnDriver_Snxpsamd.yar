rule Windows_VulnDriver_Snxpsamd_19be62e9 {
    meta:
        author = "Elastic Security"
        id = "19be62e9-7d9c-41c7-b78d-4d133dd1c4cd"
        fingerprint = "b571cf4b1bb67c204de2620a8def1503fa26ebc8749950f88bd2f5400a849c93"
        creation_date = "2026-09-09"
        last_modified = "2026-09-25"
        description = "Subject: SUNIX CO., LTD., Version: <= 10.1.0.0"
        threat_name = "Windows.VulnDriver.Snxpsamd"
        reference_sample = "1eaaa7dd2f187a5f25600f6fc6c8f0b905d9e6aeacd0803643ae58367354a513"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 55 4E 49 58 20 43 4F 2E 2C 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 6E 00 78 00 70 00 73 00 61 00 6D 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "snxpsamd.pdb"
        $str2 = "SUNIX Multi I/O Card" wide
        $str3 = "SUNIX Serial Driver (x64)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

