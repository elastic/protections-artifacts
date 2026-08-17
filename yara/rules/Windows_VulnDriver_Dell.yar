rule Windows_VulnDriver_Dell_fb5dd51b {
    meta:
        author = "Elastic Security"
        id = "fb5dd51b-1161-434f-9bb6-3ee50ffd8379"
        fingerprint = "62e695d1be0822241318c2ea5adca4d5e0bd6ef29d3dd5c603388fc2230bb7f5"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.0.3.0"
        threat_name = "Windows.VulnDriver.Dell"
        reference_sample = "1f46f7a8f414bb1ac9f875799efa4b5f62bd18806c64b17d961007755accb5ab"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 64 00 64 00 64 00 72 00 69 00 76 00 65 00 72 00 36 00 34 00 44 00 63 00 73 00 61 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00])/
        $str1 = "dddriver64Dcsa.pdb"
        $str2 = "IOCTL_DIAG_READ_LAST_PWRSTATE"
        $str3 = "IOCTL_DIAG_WRITE_MSR"
        $str4 = "Dell Diags Universal Device Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_Dell_97cc4f8b {
    meta:
        author = "Elastic Security"
        id = "97cc4f8b-06c1-40c3-8a5f-d310715210ad"
        fingerprint = "f472405e1936a71d6aba4fc0664c545b215eb081719bfc50b58dc2a1b008542a"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Techporch Incorporated, Version: <= 1.1.0.0"
        threat_name = "Windows.VulnDriver.Dell"
        reference_sample = "51562209e16a1c0247d73d7bfc8827ae4a2e57af11350379a8fba1ec44e56e54"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 63 68 70 6F 72 63 68 20 49 6E 63 6F 72 70 6F 72 61 74 65 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 44 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "dddriver64Dcsa.pdb"
        $str2 = "Dell Diags Device Driver" wide
        $str3 = "DDDriver.sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Dell_2b558646 {
    meta:
        author = "Elastic Security"
        id = "2b558646-45b7-4265-b9d8-3cd0a5df8b81"
        fingerprint = "3e8dcde4aa13a51aa9887b244fbf19e6412df97a87f3b675e7c34d2b3177cfd0"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.8.9.4"
        threat_name = "Windows.VulnDriver.Dell"
        reference_sample = "bc2606740e4648c3732541db929f2e02ea8567520d35de57c671e93c71e632f3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x08-\x08][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x03][\x00-\x00][\x09-\x09][\x00-\x00]|[\x08-\x08][\x00-\x00][\x02-\x02][\x00-\x00][\x04-\x04][\x00-\x00][\x09-\x09][\x00-\x00])/
        $str1 = "DellInstrumentation.pdb"
        $str2 = "DellInstrumentation" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Dell_f02fb07f {
    meta:
        author = "Elastic Security"
        id = "f02fb07f-fe9b-44cb-bfd0-e8ab60250e17"
        fingerprint = "11269e3b777e0918e243604714cf774ec5a38be2f2ad0586c87efb0e9c0895d0"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = ""
        threat_name = "Windows.VulnDriver.Dell"
        reference_sample = "0584520b4b3bdad1d177329bd9952c0589b2a99eb9676cb324d1fce46dad0b9a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "c:\\work\\bios\\b6k\\dev\\new_drv\\flash2\\drv\\objfre_wnet_AMD64\\amd64\\DBDrvr64.pdb"
        $str2 = "Dell Inc. Flash BIOS upgrade driver, Copyright (c) Dell Inc. - Release Version 2.0"
        $seq1 = { 53 0F 09 E4 80 E6 80 48 8B C1 49 8B D8 EE E4 80 E6 80 E4 80 E6 80 0F 09 E4 80 E6 80 E4 80 E6 80 5B C3 }
        $seq2 = { 48 89 6C 24 58 0F B7 28 48 89 74 24 60 66 85 ED 8B 70 04 4C 89 64 24 40 44 0F B7 60 08 4C 89 6C 24 38 44 8B 68 0C 4C 89 74 24 30 75 1B 85 F6 75 17 44 8B 44 24 20 45 33 F6 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $str1 and $str2 and $seq1 and $seq2
}

rule Windows_VulnDriver_Dell_a78f79a2 {
    meta:
        author = "Elastic Security"
        id = "a78f79a2-6aed-4c29-8dcd-c65bb75ed4fd"
        fingerprint = "d1ee5951e1056ab8bb950023a064855cf50341e4612617c53e746770eb0a259d"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Dell Inc."
        threat_name = "Windows.VulnDriver.Dell"
        reference_sample = "0684e092f2b9d516d190f9c62ce83239b623ea44518ad425906f3059a885dbc3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 65 6C 6C 20 49 6E 63 2E }
        $str1 = "DBDrvr64.pdb"
        $seq1 = { 67 24 DC 31 AC F4 25 E3 6B 4C 14 73 24 B0 C1 C8 B7 EC 07 AE 6F 06 AA 3E A0 88 96 A1 4C CA 3D AE CA DF 31 01 51 D6 A5 B5 E9 91 DF CA 8D 17 31 2F 6D AA 6A C6 4B C3 40 F4 72 A2 85 53 8F 8B 71 69 12 5F D2 40 ED 0E B3 27 06 92 3B E2 79 B2 37 9D AC 17 4A 6D 51 D0 C7 60 53 1C C5 91 3D 61 21 6D 41 A3 19 8A 58 B4 34 27 91 47 1F 50 F3 E6 67 A0 E9 5E 46 E1 C1 EE C5 53 1E BD A1 F6 05 A5 64 EE 14 E1 04 DE C1 5D AF 37 20 1A 34 9D 5C D5 5D 92 E5 86 67 77 2D 00 EE A7 C8 5B 54 69 2B E1 46 99 A6 82 26 76 B1 61 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $seq1
}

