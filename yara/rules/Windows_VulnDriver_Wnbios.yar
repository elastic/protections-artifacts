rule Windows_VulnDriver_Wnbios_24be3d2a {
    meta:
        author = "Elastic Security"
        id = "24be3d2a-c80e-4564-ac6f-37a3ca34d035"
        fingerprint = "e601c4bf089fff6d69c34dc41b4983881b5d6b844cbf1ef8d64bf2d64e3df86e"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Name: wnbios.sys, Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.Wnbios"
        reference_sample = "76a83d27216f7f3c148c3b6b909e121ba5c7c93493bc6fc288c6061dd1802ed0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 6E 00 62 00 69 00 6F 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "wnBios.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "WnBios Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

