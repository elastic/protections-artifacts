rule Windows_VulnDriver_ArgusMonitor_a31db35b {
    meta:
        author = "Elastic Security"
        id = "a31db35b-9dc5-4c83-907a-67d19bb3e703"
        fingerprint = "71c33eaad888906e040170c93f9a8651e0602a61bec2e8b5d5efe0b2dcfb48e9"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.40.2.0"
        threat_name = "Windows.VulnDriver.ArgusMonitor"
        reference_sample = "df9b2892498c68805fdc0fabb369f8bcf011e784898cb32fdc5d85f6123f1126"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 72 00 67 00 75 00 73 00 4D 00 6F 00 6E 00 69 00 74 00 6F 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x27][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x28-\x28][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x28-\x28][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "ArgusMonitor.pdb"
        $str2 = "Argus Monitor Driver" wide
        $str3 = "Argus Monitor Hardware Access Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

