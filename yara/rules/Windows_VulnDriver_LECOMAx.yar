rule Windows_VulnDriver_LECOMAx_b9a53b82 {
    meta:
        author = "Elastic Security"
        id = "b9a53b82-aa2f-4084-8745-ace9af110bf5"
        fingerprint = "e293cadcba05f27b229abc77c4e462e05caba05bccee00538c4bd4d43af2081e"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: LECO Corporation, Version: <= 2.3.1.0"
        threat_name = "Windows.VulnDriver.LECOMAx"
        reference_sample = "0f2dff4116a84241d8cafe534b63454fb4ea26272da8977be03670701ec6631c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 45 43 4F 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 45 00 43 00 4F 00 4D 00 41 00 78 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "LECOMA64_2.pdb"
        $str2 = { 4C 00 45 00 43 00 4F 00 AE 00 20 00 4C 00 45 00 43 00 4F 00 4D 00 41 00 20 00 44 00 65 00 76 00 69 00 63 00 65 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_LECOMAx_2d2f09d5 {
    meta:
        author = "Elastic Security"
        id = "2d2f09d5-46c2-4bba-81fc-9dd1200173a4"
        fingerprint = "1d04343a68a4d8477d876fe3642ab3f2b8bead8fc37bf5de4d92b20f361fbce5"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Name: LECOMAx.SYS, Version: <= 2.3.1.0"
        threat_name = "Windows.VulnDriver.LECOMAx"
        reference_sample = "0bca54b5545e57c68d2f7c7891505d4e67c1d0a54013abbb0b22fc7219d3fc0e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 45 00 43 00 4F 00 4D 00 41 00 78 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "LECOMA64_2.pdb"
        $str2 = { 4C 00 45 00 43 00 4F 00 AE 00 20 00 4C 00 45 00 43 00 4F 00 4D 00 41 00 20 00 44 00 65 00 76 00 69 00 63 00 65 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

