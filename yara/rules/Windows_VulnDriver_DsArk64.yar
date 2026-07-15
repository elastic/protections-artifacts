rule Windows_VulnDriver_DsArk64_206e7e6f {
    meta:
        author = "Elastic Security"
        id = "206e7e6f-89bc-4bfe-a713-56a089cd89ef"
        fingerprint = "5f30aa2514caf8dfc70aecdbac6903c4e29eec210767981de6f92447cdf93a95"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.1.0.1235"
        threat_name = "Windows.VulnDriver.DsArk64"
        reference_sample = "86127dbc92e2896319d1c9117b85e6db01ff001f3a85614d5ef9088d181b044a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 73 00 41 00 72 00 6B 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\xd2][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\xd3-\xd3][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "DsArk64.pdb"
        $str2 = "Qihoo360 Kernel Mode Driver" wide
        $str3 = "DsArk64.sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

