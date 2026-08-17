rule Windows_VulnDriver_ZYArKit_0b9b5dd2 {
    meta:
        author = "Elastic Security"
        id = "0b9b5dd2-c20c-4915-8b10-163e3162d3c6"
        fingerprint = "7a35957c2b15953521a0f0ebb18f8df1812fe38d3b2b19a67b132166fac9550a"
        creation_date = "2026-07-20"
        last_modified = "2026-08-11"
        description = "Subject: Beijing chenxinlingchuang Information Technology CO.,Ltd., Version: <= 2.0.13.5"
        threat_name = "Windows.VulnDriver.ZYArKit"
        reference_sample = "46883bc25c77678f60c1b836f4c438d87158c9af6b229f533522f635a0d5276e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 63 68 65 6E 78 69 6E 6C 69 6E 67 63 68 75 61 6E 67 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 4F 2E 2C 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 5A 00 59 00 41 00 72 00 4B 00 69 00 74 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0c][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x04][\x00-\x00][\x0d-\x0d][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x0d-\x0d][\x00-\x00])/
        $str1 = "ZyArk.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

