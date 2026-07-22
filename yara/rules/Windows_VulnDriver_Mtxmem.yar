rule Windows_VulnDriver_Mtxmem_64490477 {
    meta:
        author = "Elastic Security"
        id = "64490477-6ec8-40e8-8c4f-e4320cda0a1b"
        fingerprint = "de45ee805ac762f44bc295f2f05fa65ef091d15d447142b0fb2f39b0429f2d96"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: MATROX ELECTRONIC SYSTEMS, LTD, Version: <= 10.50.923.4242"
        threat_name = "Windows.VulnDriver.Mtxmem"
        reference_sample = "bd434c90eba514f5448978edb8b9fcd424f2e5cf3c0df9040efe5c25ec692dbc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 41 54 52 4F 58 20 45 4C 45 43 54 52 4F 4E 49 43 20 53 59 53 54 45 4D 53 2C 20 4C 54 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6D 00 74 00 78 00 6D 00 65 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x31][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x32-\x32][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x9a][\x03-\x03])|[\x32-\x32][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0f]|[\x00-\x91][\x10-\x10])[\x9b-\x9b][\x03-\x03]|[\x32-\x32][\x00-\x00][\x0a-\x0a][\x00-\x00][\x92-\x92][\x10-\x10][\x9b-\x9b][\x03-\x03])/
        $str1 = "mtxmem.pdb"
        $str2 = { 4D 00 61 00 74 00 72 00 6F 00 78 00 AE 00 20 00 49 00 6D 00 61 00 67 00 69 00 6E 00 67 00 20 00 4C 00 69 00 62 00 72 00 61 00 72 00 79 00 20 00 28 00 4D 00 49 00 4C 00 29 00 }
        $str3 = "Matrox Memory Manager (64-bit)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

