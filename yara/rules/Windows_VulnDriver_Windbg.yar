rule Windows_VulnDriver_Windbg_71acde08 {
    meta:
        author = "Elastic Security"
        id = "71acde08-7873-430b-89ed-9b260c0a99bd"
        fingerprint = "b2ed7aa876048287722a83a63be56e108d72f5a80ed18a464a4c9cc7eb46262d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Shenzhen Luyoudashi Technology Co., Ltd., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Windbg"
        reference_sample = "6661320f779337b95bbbe1943ee64afb2101c92f92f3d1571c1bf4201c38c724"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 4C 75 79 6F 75 64 61 73 68 69 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 69 00 6E 00 64 00 62 00 67 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "hpsafe.pdb"
        $str2 = "Microsoft? Windows? Operating System" wide
        $str3 = "Windows GUI symbolic debugger" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Windbg_e4f573bf {
    meta:
        author = "Elastic Security"
        id = "e4f573bf-edff-4829-8bda-60868d4b110d"
        fingerprint = "d954e86255c6afcebd5e261c2041358c6fb576f0e85177431a3f0a222894284c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: windbg.sys, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Windbg"
        reference_sample = "6994b32e3f3357f4a1d0abe81e8b62dd54e36b17816f2f1a80018584200a1b77"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 69 00 6E 00 64 00 62 00 67 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "hpsafe.pdb"
        $str2 = "Microsoft? Windows? Operating System" wide
        $str3 = "Windows GUI symbolic debugger" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Windbg_298a4ccc {
    meta:
        author = "Elastic Security"
        id = "298a4ccc-b190-4427-b21f-8ea8c4ca33b6"
        fingerprint = "e3748adc0858cecba9071fa9e12c32c11c3a3762b0f349613a31973bcb60d1df"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Wuhan Jiajia Yiyong Technology Co., Ltd., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Windbg"
        reference_sample = "e6f764c3b5580cd1675cbf184938ad5a201a8c096607857869bd7c3399df0d12"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 75 68 61 6E 20 4A 69 61 6A 69 61 20 59 69 79 6F 6E 67 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 69 00 6E 00 64 00 62 00 67 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Microsoft? Windows? Operating System" wide
        $str2 = "Windows GUI symbolic debugger" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Windbg_2912bbcc {
    meta:
        author = "Elastic Security"
        id = "2912bbcc-43ae-4c6e-8567-9f188a314820"
        fingerprint = "0601fd3dd4f7e4ab294bc9aa32ec967bc4ed2710de88402d1b01480a186177a3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Binzhoushi Yongyu Feed Co.,LTd., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Windbg"
        reference_sample = "f9f2091fccb289bcf6a945f6b38676ec71dedb32f3674262928ccaf840ca131a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 69 6E 7A 68 6F 75 73 68 69 20 59 6F 6E 67 79 75 20 46 65 65 64 20 43 6F 2E 2C 4C 54 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 69 00 6E 00 64 00 62 00 67 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "hpsafe.pdb"
        $str2 = "Microsoft? Windows? Operating System" wide
        $str3 = "Windows GUI symbolic debugger" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Windbg_e9970191 {
    meta:
        author = "Elastic Security"
        id = "e9970191-e38e-4d5a-97ec-cde06913d631"
        fingerprint = "a221c2fffb515681c6a6bd9039130d75370743026b269a85978fd804e798bdac"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Windbg"
        reference_sample = "fa9abb3e7e06f857be191a1e049dd37642ec41fb2520c105df2227fcac3de5d5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 69 00 6E 00 64 00 62 00 67 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "hpsafe.pdb"
        $str2 = "Microsoft? Windows? Operating System" wide
        $str3 = "Windows GUI symbolic debugger" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

