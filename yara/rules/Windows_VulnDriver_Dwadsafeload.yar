rule Windows_VulnDriver_Dwadsafeload_58e47c03 {
    meta:
        author = "Elastic Security"
        id = "58e47c03-d654-4a58-ba78-70d777031c81"
        fingerprint = "0d2d9949e82109fb64463919b4b8e2f4ec196da252428093fa21d6f8742fb87b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: EVANGEL TECHNOLOGY (HK) LIMITED, Version: <= 2022.1.16.1000"
        threat_name = "Windows.VulnDriver.Dwadsafeload"
        reference_sample = "e1123b59a801e243a64270d0c6ab1277e5e3afba9c19023807409f53c1b0204b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 56 41 4E 47 45 4C 20 54 45 43 48 4E 4F 4C 4F 47 59 20 28 48 4B 29 20 4C 49 4D 49 54 45 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 64 00 77 00 61 00 64 00 73 00 61 00 66 00 65 00 6C 00 6F 00 61 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe5][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x0f][\x00-\x00]|[\x01-\x01][\x00-\x00][\xe6-\xe6][\x07-\x07]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xe7][\x03-\x03])[\x10-\x10][\x00-\x00]|[\x01-\x01][\x00-\x00][\xe6-\xe6][\x07-\x07][\xe8-\xe8][\x03-\x03][\x10-\x10][\x00-\x00])/
        $str1 = "DwAdsafeLoad.pdb"
        $str2 = { FE 76 51 7F 3B 4E A8 52 32 96 A1 5F FB 7C DF 7E }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

