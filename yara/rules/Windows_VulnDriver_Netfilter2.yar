rule Windows_VulnDriver_Netfilter2_fd949688 {
    meta:
        author = "Elastic Security"
        id = "fd949688-593e-4f68-a6c1-bb3be7ee7cf9"
        fingerprint = "4b350f5470a90d8c567da322ae9aa4126e6781efbf0a838a881362c0d3472687"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Shenzhen Hua’nan Xingfa Electronic Equipment Firm, Version: <= 1.6.5.7"
        threat_name = "Windows.VulnDriver.Netfilter2"
        reference_sample = "206006a11f233b9ae876952308f6d60d7a75c80b4d530a3e6146a0b4d8cd3e4f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 48 75 61 E2 80 99 6E 61 6E 20 58 69 6E 67 66 61 20 45 6C 65 63 74 72 6F 6E 69 63 20 45 71 75 69 70 6D 65 6E 74 20 46 69 72 6D }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 65 00 74 00 66 00 69 00 6C 00 74 00 65 00 72 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x05-\x05][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x05-\x05][\x00-\x00])/
        $str1 = "netfilter2.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "NetFilter SDK WFP Driver (WPP)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Netfilter2_86b8eb6c {
    meta:
        author = "Elastic Security"
        id = "86b8eb6c-2278-4379-b44e-91d713f997b4"
        fingerprint = "e6dc3b2937cd7812fac056834c675152299892601287f85e98ea0af51562604c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: 九江宏图无忧科技有限公司, Version: <= 1.4.9.5"
        threat_name = "Windows.VulnDriver.Netfilter2"
        reference_sample = "26d67d479dafe6b33c980bd1eed0b6d749f43d05d001c5dcaaf5fcddb9b899fe"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E4 B9 9D E6 B1 9F E5 AE 8F E5 9B BE E6 97 A0 E5 BF A7 E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 65 00 74 00 66 00 69 00 6C 00 74 00 65 00 72 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x04][\x00-\x00][\x09-\x09][\x00-\x00]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x09-\x09][\x00-\x00])/
        $str1 = "netfilter2.pdb"
        $str2 = "WYJSQ TDI Hook Driver (WPP)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Netfilter2_12e48ee6 {
    meta:
        author = "Elastic Security"
        id = "12e48ee6-a8d5-4e00-8ff3-636cef3b998a"
        fingerprint = "908d430714143df4d0165e2077b69943d87d91563607392c9be21a11cc244b6e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Orange, Version: <= 1.5.9.7"
        threat_name = "Windows.VulnDriver.Netfilter2"
        reference_sample = "8017e618b5a7aa608cc4bce16e4defd6b4e99138c4ba1bdd6ad78e39f035cf59"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 72 61 6E 67 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 65 00 74 00 66 00 69 00 6C 00 74 00 65 00 72 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x09-\x09][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x09-\x09][\x00-\x00])/
        $str1 = "netfilter2.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "NetFilter SDK WFP Driver (WPP)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Netfilter2_713604d3 {
    meta:
        author = "Elastic Security"
        id = "713604d3-aa24-4f77-b48e-c7786d350b16"
        fingerprint = "6934b299af8d77234233f36095dfab2981dda9e682fe7497950def5f56715b8e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.5.9.7"
        threat_name = "Windows.VulnDriver.Netfilter2"
        reference_sample = "81bcd8a3f8c17ac6dc4bad750ad3417914db10aa15485094eef0951a3f72bdbd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 65 00 74 00 66 00 69 00 6C 00 74 00 65 00 72 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x09-\x09][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x09-\x09][\x00-\x00])/
        $str1 = "netfilter2.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "NetFilter SDK WFP Driver (WPP)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Netfilter2_b5537c11 {
    meta:
        author = "Elastic Security"
        id = "b5537c11-1999-4f8d-a65e-d78b8935b366"
        fingerprint = "68daa35ecc5fbef4b336ef02738e0568ab91062dbab7d1ddf35fcf25aab9e4c1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: 九江宏图无忧科技有限公司, Version: <= 1.5.7.8"
        threat_name = "Windows.VulnDriver.Netfilter2"
        reference_sample = "f1718a005232d1261894b798a60c73d971416359b70d0e545d7e7a40ed742b71"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E4 B9 9D E6 B1 9F E5 AE 8F E5 9B BE E6 97 A0 E5 BF A7 E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 65 00 74 00 66 00 69 00 6C 00 74 00 65 00 72 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x07][\x00-\x00][\x07-\x07][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x08-\x08][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "netfilter2.pdb"
        $str2 = "WYJSQ WFP Driver (WPP)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

