rule Windows_VulnDriver_GDrv_5368078b {
    meta:
        author = "Elastic Security"
        id = "5368078b-5dba-42c7-a50c-ac8859d3393d"
        fingerprint = "ce6e81ee34ba47466684387bdb957c3018b9c06938dbb2f7eb830609bd085f66"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        description = "Name: gdrv.sys, Version: 5.2.3790.1830"
        threat_name = "Windows.VulnDriver.GDrv"
        reference_sample = "31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 67 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x02][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\x26][\x00-\x07]|[\x00-\xff][\x00-\x06])([\x00-\xce][\x00-\x0e]|[\x00-\xff][\x00-\x0d])|([\x00-\xff][\x00-\xff])([\x00-\x04][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x02][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xcd][\x00-\x0e]|[\x00-\xff][\x00-\x0d]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_GDrv_c3ec08da {
    meta:
        author = "Elastic Security"
        id = "c3ec08da-1735-4fda-8325-c0cbc8464d1e"
        fingerprint = "47a3bdd7df081e7c5c8ce3f1b2c1a24faf02bd191e445423cf30bda24212d809"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: GIGA-BYTE Technology Co., Ltd., Version: <= 1.0.1.1"
        threat_name = "Windows.VulnDriver.GDrv"
        reference_sample = "092d04284fdeb6762e65e6ac5b813920d6c69a5e99d110769c5c1a78e11c5ba0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 49 47 41 2D 42 59 54 45 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 67 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "gdrv86.pdb"
        $str2 = "GIGA-BYTE Software driver" wide
        $str3 = "GIGA-BYTE NonPnP Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_GDrv_62f80d5b {
    meta:
        author = "Elastic Security"
        id = "62f80d5b-d4f7-4806-a271-f391564143fb"
        fingerprint = "4355222154b034fb6b3ed440b54dc06f1813ca49429fdffb3f78033ed4d43a29"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Giga-Byte Technology, Version: <= 5.2.3790.1830"
        threat_name = "Windows.VulnDriver.GDrv"
        reference_sample = "17927b93b2d6ab4271c158f039cae2d60591d6a14458f5a5690aec86f5d54229"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 69 67 61 2D 42 79 74 65 20 54 65 63 68 6E 6F 6C 6F 67 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 67 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0d]|[\x00-\xcd][\x0e-\x0e])|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\x25][\x07-\x07])[\xce-\xce][\x0e-\x0e]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x26-\x26][\x07-\x07][\xce-\xce][\x0e-\x0e])/
        $str1 = "gdrv64.pdb"
        $str2 = "Windows (R) Server 2003 DDK driver" wide
        $str3 = "GIGABYTE Tools" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_GDrv_a51f996c {
    meta:
        author = "Elastic Security"
        id = "a51f996c-b908-4de7-929e-a717260c22fe"
        fingerprint = "79301e3d23ce49f9b5b57fc41c608c4ae659e34439c1de3548f3238c3d415e8f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: GIGA-BYTE TECHNOLOGY CO., LTD., Version: <= 1.0.0.5"
        threat_name = "Windows.VulnDriver.GDrv"
        reference_sample = "26c28746e947389856543837aa59a5b1f4697e5721a04d00aa28151a2659b097"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 49 47 41 2D 42 59 54 45 20 54 45 43 48 4E 4F 4C 4F 47 59 20 43 4F 2E 2C 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 67 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x04][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "gdrv.pdb"
        $str2 = "GIGA-BYTE Software driver" wide
        $str3 = "GIGA-BYTE NonPnP Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_GDrv_1178a4d2 {
    meta:
        author = "Elastic Security"
        id = "1178a4d2-c3f6-40ad-a591-86e5e655d762"
        fingerprint = "c4188bace0324dae73269fd06d0ae3fa3660b51fed723e435e869c5102d24819"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Giga-Byte Technology"
        threat_name = "Windows.VulnDriver.GDrv"
        reference_sample = "655110646bff890c448c0951e11132dc3592bda6e080696341b930d090224723"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 69 67 61 2D 42 79 74 65 20 54 65 63 68 6E 6F 6C 6F 67 79 }
        $str1 = "GPCIDrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_GDrv_62355c4a {
    meta:
        author = "Elastic Security"
        id = "62355c4a-95db-4de9-8c13-10c26b3ac115"
        fingerprint = "57776c35055d48ba48fdea440c12a0d56d0a0a1a4f60686cf9caee3d95446552"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 上海笑聘网络科技有限公司, Version: <= 5.2.3790.1830"
        threat_name = "Windows.VulnDriver.GDrv"
        reference_sample = "6f1fc8287dd8d724972d7a165683f2b2ad6837e16f09fe292714e8e38ecd1e38"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E4 B8 8A E6 B5 B7 E7 AC 91 E8 81 98 E7 BD 91 E7 BB 9C E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 67 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0d]|[\x00-\xcd][\x0e-\x0e])|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\x25][\x07-\x07])[\xce-\xce][\x0e-\x0e]|[\x02-\x02][\x00-\x00][\x05-\x05][\x00-\x00][\x26-\x26][\x07-\x07][\xce-\xce][\x0e-\x0e])/
        $str1 = "gdrv64.pdb"
        $str2 = "Windows (R) Server 2003 DDK driver" wide
        $str3 = "GIGABYTE Tools" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_GDrv_34ceb7f6 {
    meta:
        author = "Elastic Security"
        id = "34ceb7f6-f8e7-490c-94f2-f75d19339b87"
        fingerprint = "1228f561e8c699dea3b92da25a74f7ab18d30389523a4affdd0de6978d4d57c1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: GIGA-BYTE Technology Co., Ltd., Version: <= 1.1.0.2"
        threat_name = "Windows.VulnDriver.GDrv"
        reference_sample = "81aafae4c4158d0b9a6431aff0410745a0f6a43fb20a9ab316ffeb8c2e2ccac0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 49 47 41 2D 42 59 54 45 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 67 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "gdrv.pdb"
        $str2 = "GIGA-BYTE Software driver" wide
        $str3 = "GIGA-BYTE NonPnP Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_GDrv_3cda6b4b {
    meta:
        author = "Elastic Security"
        id = "3cda6b4b-7f24-41ae-bbd8-3577e211adce"
        fingerprint = "04825dc21dc81143f85f1419881a6ea686e6c4362a38b5636c17b49dec59c457"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: GIGA-BYTE Technology Co., Ltd., Version: <= 1.1.0.4"
        threat_name = "Windows.VulnDriver.GDrv"
        reference_sample = "a71c1aa13d7a1a9b55f07a09ad1e41ceb997f4369b8260e0eef49257f040a9c1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 49 47 41 2D 42 59 54 45 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 67 00 64 00 72 00 76 00 33 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x03][\x00-\x00][\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "gdrv.pdb"
        $str2 = "GIGA-BYTE Software Driver" wide
        $str3 = "GIGA-BYTE Nonpnp Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_GDrv_363fa432 {
    meta:
        author = "Elastic Security"
        id = "363fa432-05f8-499c-860e-8f3adf3da481"
        fingerprint = "1bb0c0d2079581c0b96b82b783594504c591d1cf71ca27ad0f0ce545a1467803"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Giga-Byte Technology, Version: <= 5.0.2195.1620"
        threat_name = "Windows.VulnDriver.GDrv"
        reference_sample = "cfc5c585dd4e592dd1a08887ded28b92d9a5820587b6f4f8fa4f56d60289259b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 69 67 61 2D 42 79 74 65 20 54 65 63 68 6E 6F 6C 6F 67 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 67 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x07]|[\x00-\x92][\x08-\x08])|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\x53][\x06-\x06])[\x93-\x93][\x08-\x08]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x54-\x54][\x06-\x06][\x93-\x93][\x08-\x08])/
        $str1 = "gdrv.pdb"
        $str2 = "Windows (R) 2000 DDK driver" wide
        $str3 = "GIGABYTE Tools" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_GDrv_8a7ef0e8 {
    meta:
        author = "Elastic Security"
        id = "8a7ef0e8-3e5a-4e07-b43e-09a73c7df735"
        fingerprint = "ba72769e774334b7c67308762955c50e33671cf7cd990b75ce3fcad60c01a2b3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: GIGA-BYTE Technology Co., Ltd."
        threat_name = "Windows.VulnDriver.GDrv"
        reference_sample = "f85784fa8e7a7ec86cb3fe76435802f6bb82256e1824ed7b5d61bf075f054573"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 49 47 41 2D 42 59 54 45 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "GVCIDrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_GDrv_989a396f {
    meta:
        author = "Elastic Security"
        id = "989a396f-5d1b-4381-97d5-8905a54ca441"
        fingerprint = "d6d2240316af34c29d34df7737ebb55752811928c70425cb4f85c586dff9778f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: GIGA-BYTE TECHNOLOGY CO., LTD., Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.GDrv"
        reference_sample = "ff6729518a380bf57f1bc6f1ec0aa7f3012e1618b8d9b0f31a61d299ee2b4339"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 49 47 41 2D 42 59 54 45 20 54 45 43 48 4E 4F 4C 4F 47 59 20 43 4F 2E 2C 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 67 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "gdrv64.pdb"
        $str2 = "GIGA-BYTE NonPNP Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

