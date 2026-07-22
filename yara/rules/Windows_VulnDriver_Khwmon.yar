rule Windows_VulnDriver_Khwmon_730efe7d {
    meta:
        author = "Elastic Security"
        id = "730efe7d-1a07-4018-a7b9-d1ee902ed1b0"
        fingerprint = "f7e8503102c8d1d4ec51572366f9a0eb52452b282677e4867ae8ddedf3d6e5ed"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: 上饶市云网科技有限公司, Version: <= 2013.4.15.5"
        threat_name = "Windows.VulnDriver.Khwmon"
        reference_sample = "103ce48e8491684f383d9851e4710cbb5c739b5c7f332f2d11b88babc2c217b5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E4 B8 8A E9 A5 B6 E5 B8 82 E4 BA 91 E7 BD 91 E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 68 00 77 00 6D 00 6F 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xdc][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\xdd-\xdd][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\xdd-\xdd][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00]|[\x04-\x04][\x00-\x00][\xdd-\xdd][\x07-\x07][\x00-\x04][\x00-\x00][\x0f-\x0f][\x00-\x00]|[\x04-\x04][\x00-\x00][\xdd-\xdd][\x07-\x07][\x05-\x05][\x00-\x00][\x0f-\x0f][\x00-\x00])/
        $str1 = "Khwmon64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

