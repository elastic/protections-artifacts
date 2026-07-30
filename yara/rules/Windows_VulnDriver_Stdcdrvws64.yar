rule Windows_VulnDriver_Stdcdrvws64_1257b708 {
    meta:
        author = "Elastic Security"
        id = "1257b708-9e45-4044-852c-92e8d66acc74"
        fingerprint = "434ddcd924493d7dc3df99df425ff93e1e423b69ba874a506766604e9a46b3c2"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: stdcdrvws64.sys, Version: <= 1.0.1.0"
        threat_name = "Windows.VulnDriver.Stdcdrvws64"
        reference_sample = "32a31a84bbdee6d6dc29046a4cddc12bc7fc88dc6a4220954869eb33478f37b4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 74 00 64 00 63 00 64 00 72 00 76 00 77 00 73 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "stdcdrvws64.pdb"
        $str2 = "SelfTest Data Collector Driver for Windows 7 x64" wide
        $str3 = "SelfTest Data Collector Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

