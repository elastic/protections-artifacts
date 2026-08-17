rule Windows_Rootkit_Vusbbus_3e2eb67f {
    meta:
        author = "Elastic Security"
        id = "3e2eb67f-c74b-418d-9a80-2db62f7939d1"
        fingerprint = "72a5f4d3d4e04da29a70d2d85d982eb623fe7f6cd19ac1c44244ff7473160f25"
        creation_date = "2026-05-22"
        last_modified = "2026-08-10"
        description = "Subject: Shenzhen yundian Technology Co., Ltd, Version: <= 0.1.0.0"
        threat_name = "Windows.Rootkit.Vusbbus"
        reference_sample = "b4f33ffef069c18e8a8834eb448dd1f1dbdaae93b140cfff5a1db015eb3ada2f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 79 75 6E 64 69 61 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 76 00 75 00 73 00 62 00 62 00 75 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Virtual USB bus driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

