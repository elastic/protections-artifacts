rule Windows_VulnDriver_Fujitsu_aadfba70 {
    meta:
        author = "Elastic Security"
        id = "aadfba70-43f0-4c07-a1be-fb5a0900675d"
        fingerprint = "f47aaee6c58be96724c00ef49cad8e43a4ea44c07bd29442d644421901afb64d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: FUJITSU LIMITED , Version: <= 2.0.0.0"
        threat_name = "Windows.VulnDriver.Fujitsu"
        reference_sample = "04a85e359525d662338cae86c1e59b1d7aa9bd12b920e8067503723dc1e03162"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 55 4A 49 54 53 55 20 4C 49 4D 49 54 45 44 20 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 44 00 56 00 36 00 34 00 44 00 52 00 56 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ADV64DRV.pdb"
        $str2 = "MicrosoftR WindowsR Operating System" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Fujitsu_12b515fc {
    meta:
        author = "Elastic Security"
        id = "12b515fc-7b47-4c6d-bef6-65b9d2876a08"
        fingerprint = "5ddc5208088596c72f24067cc267e0c16ffd5f808a4674af63ff83d799795808"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: FUJITSU LIMITED, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Fujitsu"
        reference_sample = "30ee861d6d34db31ed57273fe1b3e08c30260c46fbca2cc00725d08ffd1013f6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 55 4A 49 54 53 55 20 4C 49 4D 49 54 45 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 66 00 6A 00 66 00 77 00 75 00 70 00 67 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "fjfwupgd-x64.pdb"
        $str2 = "Fujitsu Firmware Update Tool Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

