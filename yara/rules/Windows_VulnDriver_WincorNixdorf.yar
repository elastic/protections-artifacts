rule Windows_VulnDriver_WincorNixdorf_363c6236 {
    meta:
        author = "Elastic Security"
        id = "363c6236-a559-4c83-9fd9-cd2df14cb704"
        fingerprint = "9b8452e7d122f40dcebd3ba2b5233c55d789c206eb59adead1e290aa59c139a5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Wincor Nixdorf International GmbH, Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.WincorNixdorf"
        reference_sample = "004269ce6d324f0e5d861d656b7fddff19511e237c5dd51c1ac434e25cab6a82"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 69 6E 63 6F 72 20 4E 69 78 64 6F 72 66 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 47 6D 62 48 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 6E 00 62 00 69 00 6F 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "wnBios.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "WnBios Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

