rule Windows_VulnDriver_LG_607ef495 {
    meta:
        author = "Elastic Security"
        id = "607ef495-d9a7-4aa7-b5fb-be81c8991bd9"
        fingerprint = "551784ca9b0ccfde0df6e8b97cd127112eaec3499c128dfa578310444ba21172"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: LG Electronics Inc., Version: <= 1.1.1512.2901"
        threat_name = "Windows.VulnDriver.LG"
        reference_sample = "11c9cbc39b6e028f2e8f9e7f83b47ae83ca73961ecfebb2f7213f9478f5446d5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 47 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 58 00 4C 00 48 00 41 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x04]|[\x00-\xe7][\x05-\x05])|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0a]|[\x00-\x54][\x0b-\x0b])[\xe8-\xe8][\x05-\x05]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x55-\x55][\x0b-\x0b][\xe8-\xe8][\x05-\x05])/
        $str1 = "xlha.pdb"
        $str2 = { 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 AE 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6D 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_LG_34eb70ee {
    meta:
        author = "Elastic Security"
        id = "34eb70ee-5ac5-4513-ac3c-f86c9fe08b32"
        fingerprint = "9d6b559bbb9eb3941c15a5987e303e26860cb8ab461d71b71f234658c02fe267"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: LG Electronics Inc., Version: <= 1.1.1512.2801"
        threat_name = "Windows.VulnDriver.LG"
        reference_sample = "23ba19352b1e71a965260bf4d5120f0200709ee8657ed381043bec9a938a1ade"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 47 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 48 00 41 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x04]|[\x00-\xe7][\x05-\x05])|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x09]|[\x00-\xf0][\x0a-\x0a])[\xe8-\xe8][\x05-\x05]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\xf1-\xf1][\x0a-\x0a][\xe8-\xe8][\x05-\x05])/
        $str1 = "lha.pdb"
        $str2 = { 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 AE 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6D 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

