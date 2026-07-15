rule Windows_VulnDriver_EnTech_23ff2cf7 {
    meta:
        author = "Elastic Security"
        id = "23ff2cf7-3919-4d05-a8a3-243827fc56ce"
        fingerprint = "e21ab8596fa6534d83688929aed20ef3d9c0396040802da159281ca5eb2d7712"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: EnTech Taiwan, Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.EnTech"
        reference_sample = "4a8b6b462c4271af4a32cf8705fa64913bfcdaefb6cf02d1e722c611d428cb16"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 6E 54 65 63 68 20 54 61 69 77 61 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 73 00 74 00 72 00 61 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ASTRA64.pdb"
        $str2 = "Astra Generic Device Driver for Windows 95/98/ME/NT/2000/2003/XP/XP64" wide
        $str3 = "Astra driver for Windows XP 64-bit edition" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_EnTech_5211a0dd {
    meta:
        author = "Elastic Security"
        id = "5211a0dd-555e-4caa-8e61-54ac98a4b166"
        fingerprint = "c259140b2418b881efda510b8147d737396e18a55e5ee668794fc596c3ad1b70"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: EnTech Taiwan, Version: <= 5.0.1.1"
        threat_name = "Windows.VulnDriver.EnTech"
        reference_sample = "6cb51ae871fbd5d07c5aad6ff8eea43d34063089528603ca9ceb8b4f52f68ddc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 6E 54 65 63 68 20 54 61 69 77 61 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 65 00 36 00 34 00 61 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "Se64a.pdb"
        $str2 = "softEngine-x64" wide
        $str3 = "EnTech softEngine x64 kernel-mode driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_EnTech_2a1cb6b6 {
    meta:
        author = "Elastic Security"
        id = "2a1cb6b6-cf2f-4e95-9b04-0dfaa24d592f"
        fingerprint = "c894e2e0fc737436c2a73d337eba0af8037d75048451731d7f3b9393051f46fb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: EnTech Taiwan, Version: <= 5.2.1.0"
        threat_name = "Windows.VulnDriver.EnTech"
        reference_sample = "9c9ab56c8bcf5ec958e7c2346f23a3027f69abdf8af923b591518eee64ad98ad"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 6E 54 65 63 68 20 54 61 69 77 61 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 56 00 69 00 63 00 50 00 6F 00 72 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "TVicPort64.pdb"
        $str2 = "TVicPort Generic Device Driver for Windows 95/98/ME/NT/2000/2003/XP/XP64" wide
        $str3 = "TVicPort Driver for Windows NT/2000/XP" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

