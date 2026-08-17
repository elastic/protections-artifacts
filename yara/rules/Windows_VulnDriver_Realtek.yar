rule Windows_VulnDriver_Realtek_8302b517 {
    meta:
        author = "Elastic Security"
        id = "8302b517-704a-466e-a060-c9691751bb70"
        fingerprint = "bf1d06f7bd567df8e2554c2f06fa414eeb9f4dc38b57117b1d2abcfc5574d2d2"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp., Version: <= 1.8.823.2017"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "082c39fe2e3217004206535e271ebd45c11eb072efde4cc9885b25ba5c39f91d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 77 00 38 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x36][\x03-\x03])|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe0][\x07-\x07])[\x37-\x37][\x03-\x03]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\xe1-\xe1][\x07-\x07][\x37-\x37][\x03-\x03])/
        $str1 = "rtkiow8x64.pdb"
        $str2 = "IOCTL_PHYMEM_INFORM_FP_FW_S3S4S5"
        $str3 = "IOCTL_PHYMEM_GETPCIULONG"
        $str4 = "Realtek IO Driver  " wide
        $str5 = "Realtek IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Realtek_792f0893 {
    meta:
        author = "Elastic Security"
        id = "792f0893-89d1-4016-bc84-54b96c3f8aac"
        fingerprint = "993ce77c2f5f99951e0cf1f3479243ea4c89dc5788317a2091df9cea36039d3f"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp, Version: <= 5.0.2195.1711"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "3c0a36990f7eef89b2d5f454b6452b6df1304609903f31f475502e4050241dd8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 70 00 6F 00 72 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x07]|[\x00-\x92][\x08-\x08])|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\xae][\x06-\x06])[\x93-\x93][\x08-\x08]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\xaf-\xaf][\x06-\x06][\x93-\x93][\x08-\x08])/
        $str1 = "rtport.pdb"
        $str2 = "Windows (R) 2003 DDK 3790 provider" wide
        $str3 = "Generic Port I/O for Win32" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Realtek_9316b8f8 {
    meta:
        author = "Elastic Security"
        id = "9316b8f8-b25a-4f37-9d2b-3121adab493b"
        fingerprint = "38665053063bee0beed1e8977b04d24670eb94fdf671cf84122b5b144eb0c00e"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "461c2a34dded78988addb0a5e8b7055ae4919f8bf2373056dcce5d03b76dd49d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 }
        $str1 = "LPTIO.pdb"
        $str2 = "IOCTL_WINIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_WINIO_MAPPHYSTOLIN"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Realtek_92bd8ead {
    meta:
        author = "Elastic Security"
        id = "92bd8ead-d3c4-4ebe-9d3f-c5bc25dd2388"
        fingerprint = "c8537d2affced1b198b323355b237915179418f9fe3ab7e4e931b868519eafd6"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp., Version: <= 1.8.823.2017"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "7133a461aeb03b4d69d43f3d26cd1a9e3ee01694e97a0645a3d8aa1a44c39129"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x36][\x03-\x03])|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe0][\x07-\x07])[\x37-\x37][\x03-\x03]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\xe1-\xe1][\x07-\x07][\x37-\x37][\x03-\x03])/
        $str1 = "rtkio64.pdb"
        $str2 = "IOCTL_PHYMEM_INFORM_FP_FW_S3S4S5"
        $str3 = "IOCTL_PHYMEM_GETPCIULONG"
        $str4 = "Realtek IO Driver  " wide
        $str5 = "Realtek IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Realtek_6fbf07b7 {
    meta:
        author = "Elastic Security"
        id = "6fbf07b7-bfb0-411c-a6ed-d7fe16a3fe05"
        fingerprint = "f06560888b3502129709d435af50a376bdba9a7a145025db39dc6384bf6e9f87"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp, Version: <= 5.0.2195.1711"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "71423a66165782efb4db7be6ce48ddb463d9f65fd0f266d333a6558791d158e5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 70 00 6F 00 72 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x07]|[\x00-\x92][\x08-\x08])|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\xae][\x06-\x06])[\x93-\x93][\x08-\x08]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\xaf-\xaf][\x06-\x06][\x93-\x93][\x08-\x08])/
        $str1 = "rtport.pdb"
        $str2 = "Windows (R) 2003 DDK 3790 provider" wide
        $str3 = "Generic Port I/O for Win64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Realtek_4de969a0 {
    meta:
        author = "Elastic Security"
        id = "4de969a0-87a6-4bdb-b131-26f8be781388"
        fingerprint = "22bbaa6947684ae30e81cc22598b87528d511ae02615399d44149d901dbb55a2"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp, Version: <= 1.2.116.2015"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "8ef59605ebb2cb259f19aba1a8c122629c224c58e603f270eaa72f516277620c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x73][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xde][\x07-\x07])[\x74-\x74][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\xdf-\xdf][\x07-\x07][\x74-\x74][\x00-\x00])/
        $str1 = "rtkio64.pdb"
        $str2 = "Realtek IODriver  " wide
        $str3 = "Realtek IODriver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Realtek_e98ed7d9 {
    meta:
        author = "Elastic Security"
        id = "e98ed7d9-83e3-4c63-afff-e5114ee1c39f"
        fingerprint = "9effdc5d6a141dcc1b6f2fcbaabeaf324fc021f740cc405f7cc07c616cc16ac6"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp, Version: <= 6.0.6000.16386"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "916c535957a3b8cbf3336b63b2260ea4055163a9e6b214f2a7005d6d36a4a677"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x16]|[\x00-\x6f][\x17-\x17])|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x3f]|[\x00-\x01][\x40-\x40])[\x70-\x70][\x17-\x17]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x02-\x02][\x40-\x40][\x70-\x70][\x17-\x17])/
        $str1 = "rtkio86.pdb"
        $str2 = "IOCTL_PHYMEM_SENDSMI"
        $str3 = "Windows (R) Codename Longhorn DDK driver" wide
        $str4 = "Realtek IODriver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_Realtek_99490073 {
    meta:
        author = "Elastic Security"
        id = "99490073-2f57-4ac2-9e05-c66a17db2a42"
        fingerprint = "4e9121ae638bf627170b1a66ae451ac763fb0ecb7eef37f4f41545794b60265c"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 10.0.22000.12024"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "b19ec8330b026100f705c05b793030ca109e15cbec4ada13b452acf259cc29d5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 74 00 73 00 54 00 70 00 78 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x54]|[\x00-\xef][\x55-\x55])|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x2d]|[\x00-\xf7][\x2e-\x2e])[\xf0-\xf0][\x55-\x55]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\xf8-\xf8][\x2e-\x2e][\xf0-\xf0][\x55-\x55])/
        $str1 = "RtsTpx.pdb"
        $str2 = "RtsTpx driver for Realtek Type-C device" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Realtek_d76d7c16 {
    meta:
        author = "Elastic Security"
        id = "d76d7c16-17e7-4184-ad02-2e2d0bf092d9"
        fingerprint = "b5251c3cc9f526e3e091e7589b898cba38d0dabf26f3ca32da1057ab4af7f50e"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp, Version: <= 6.0.6000.16386"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "caa85c44eb511377ea7426ff10df00a701c07ffb384eef8287636a4bca0b53ab"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x16]|[\x00-\x6f][\x17-\x17])|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x3f]|[\x00-\x01][\x40-\x40])[\x70-\x70][\x17-\x17]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x02-\x02][\x40-\x40][\x70-\x70][\x17-\x17])/
        $str1 = "rtkio64.pdb"
        $str2 = "IOCTL_PHYMEM_SENDSMI"
        $str3 = "Windows (R) Codename Longhorn DDK driver" wide
        $str4 = "Realtek IODriver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_Realtek_0c37ddd6 {
    meta:
        author = "Elastic Security"
        id = "0c37ddd6-4eb3-41f4-8cc3-2f249f7d0c0e"
        fingerprint = "469ab82f2cc6a36a2aeeff01aa8a8b1f5c78a9dec1488a608b2779a6b35e44e5"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp., Version: <= 1.13.0.0"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "cdf38928a13dfe0e6de054f0229945b9f7db9f88eb7269ecefdceb4b5fab4bfa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6D 00 55 00 70 00 78 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x0c][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0d-\x0d][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "CmUpx.pdb"
        $str2 = "CmUpx driver for Realtek USB device" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Realtek_b9a31363 {
    meta:
        author = "Elastic Security"
        id = "b9a31363-14ec-40d7-a4f1-541005eff078"
        fingerprint = "7675f9a2f57fe7f9ef18be5d88a6b1cd049ee827430fb5f23847f39b5fd5ec3c"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp, Version: <= 1.4.105.2016"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "db711ec3f4c96b60e4ed674d60c20ff7212d80e34b7aa171ad626eaa8399e8c7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x68][\x00-\x00]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xdf][\x07-\x07])[\x69-\x69][\x00-\x00]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\xe0-\xe0][\x07-\x07][\x69-\x69][\x00-\x00])/
        $str1 = "rtkio64.pdb"
        $str2 = "Realtek IO Driver  " wide
        $str3 = "Realtek IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Realtek_483cf476 {
    meta:
        author = "Elastic Security"
        id = "483cf476-ff98-448d-ba3b-ae17e955bf64"
        fingerprint = "b38279c6ec1c41f4cc0a55b3bb2677a30ef06fbc2cc7f02ff2eec7e8c6cf54fc"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Name: RTPORT.SYS, Version: <= 1.0.1.0"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "ff322cd0cc30976f9dbdb7a3681529aeab0de7b7f5c5763362b02c15da9657a1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 54 00 50 00 4F 00 52 00 54 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "rtport.pdb"
        $str2 = "REALTEK Port I/O" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

