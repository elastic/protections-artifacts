rule Windows_VulnDriver_MonProcess_ab56d470 {
    meta:
        author = "Elastic Security"
        id = "ab56d470-9de0-4b2c-a10b-af4b5b09239d"
        fingerprint = "5a9f8463f68217be3aec4e17c6327ea66cbfa2dcc81bb5325d9f694b15ea99ff"
        creation_date = "2026-07-20"
        last_modified = "2026-08-11"
        description = "Subject: Honor Device Co., Ltd., Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.MonProcess"
        reference_sample = "72d0b5615b996cbb01b1ca139e627079094f734da48a0435ffd8480a25d0a258"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 6F 6E 6F 72 20 44 65 76 69 63 65 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4D 00 6F 00 6E 00 50 00 72 00 6F 00 63 00 65 00 73 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "MonProcessEX.pdb"
        $str2 = "MonProcess" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

