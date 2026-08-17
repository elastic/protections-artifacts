rule Windows_VulnDriver_HW64_c6ecd076 {
    meta:
        author = "Elastic Security"
        id = "c6ecd076-ac7f-406d-833f-7995c5f36c58"
        fingerprint = "75d9629ec4ac9262a5ca28a0447370fc035c86cda31fde9653b1b9cee6d3fc4d"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 5.0.2.0"
        threat_name = "Windows.VulnDriver.HW64"
        reference_sample = "0483b32f9544e9c3cc3f206e7bc983ea83f5a9ca44864f2af9b8fc10ff45949f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 57 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "HW64.pdb"
        $str2 = "HW - Windows XP-11 (32/64 bit) kernel mode driver for PC ports/memory/PCI access" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

