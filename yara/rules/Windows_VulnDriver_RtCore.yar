rule Windows_VulnDriver_RtCore_4eeb2ce5 {
    meta:
        author = "Elastic Security"
        id = "4eeb2ce5-e481-4e9c-beda-2b01f259ed96"
        fingerprint = "ce2b0a6b9f1168b692362ef39c7014a41941555de6aed8c41fea016e931331b8"
        creation_date = "2022-04-04"
        last_modified = "2025-01-29"
        threat_name = "Windows.VulnDriver.RtCore"
        reference_sample = "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\Device\\RTCore64" wide fullword
        $str2 = "Kaspersky Lab Anti-Rootkit Monitor Driver" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and uint32(uint32(0x3C) + 8) < 1713095596 and $str1 and not $str2
}

rule Windows_VulnDriver_RtCore_b38e27a7 {
    meta:
        author = "Elastic Security"
        id = "b38e27a7-316f-41bf-bd96-9b5eadce107c"
        fingerprint = "1908cbe552bffb0e21a79894e8e04d44e41dc294deb5bdbcb18f8d7b4ea35cb3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: MICRO-STAR INTERNATIONAL CO., LTD."
        threat_name = "Windows.VulnDriver.RtCore"
        reference_sample = "077aa8ff5e01747723b6d24cc8af460a7a00f30cd3bc80e41cc245ceb8305356"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 49 43 52 4F 2D 53 54 41 52 20 49 4E 54 45 52 4E 41 54 49 4F 4E 41 4C 20 43 4F 2E 2C 20 4C 54 44 2E }
        $str1 = "RTCore64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_RtCore_1b4e556a {
    meta:
        author = "Elastic Security"
        id = "1b4e556a-2361-4ac1-a0f8-71356bfb269a"
        fingerprint = "b672813f9befb239b6a77f9f5cf3dba7b517dfd1e99b018d5591f4648cef7567"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: MICRO-STAR INTERNATIONAL CO., LTD., Version: <= 1.0.0.2"
        threat_name = "Windows.VulnDriver.RtCore"
        reference_sample = "09bedbf7a41e0f8dabe4f41d331db58373ce15b2e9204540873a1884f38bdde1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 49 43 52 4F 2D 53 54 41 52 20 49 4E 54 45 52 4E 41 54 49 4F 4E 41 4C 20 43 4F 2E 2C 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 54 00 49 00 4F 00 4C 00 69 00 62 00 5F 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "NTIOLib.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_RtCore_99fe40b2 {
    meta:
        author = "Elastic Security"
        id = "99fe40b2-4d93-440e-ad1a-7434d6354909"
        fingerprint = "8fcdfcd78cd4da9c1acb59343c35c108a3d902bed1c016aa0d5a12588587eedd"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: MICRO-STAR INTERNATIONAL CO., LTD., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.RtCore"
        reference_sample = "18776682fcc0c6863147143759a8d4050a4115a8ede0136e49a7cf885c8a4805"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 49 43 52 4F 2D 53 54 41 52 20 49 4E 54 45 52 4E 41 54 49 4F 4E 41 4C 20 43 4F 2E 2C 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 54 00 49 00 4F 00 4C 00 69 00 62 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "NTIOLib.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_RtCore_85687a1c {
    meta:
        author = "Elastic Security"
        id = "85687a1c-e121-483f-93d8-1ea72d772943"
        fingerprint = "30d572f2db60014769717208337ef4f1bc80ac005532f42f207e5b07753337e9"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: MICRO-STAR INTERNATIONAL CO., LTD., Version: <= 1.0.0.3"
        threat_name = "Windows.VulnDriver.RtCore"
        reference_sample = "1ddfe4756f5db9fb319d6c6da9c41c588a729d9e7817190b027b38e9c076d219"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 49 43 52 4F 2D 53 54 41 52 20 49 4E 54 45 52 4E 41 54 49 4F 4E 41 4C 20 43 4F 2E 2C 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 54 00 49 00 4F 00 4C 00 69 00 62 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "NTIOLib.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_RtCore_6fb16ce5 {
    meta:
        author = "Elastic Security"
        id = "6fb16ce5-427e-4402-8633-5b649ea86f8a"
        fingerprint = "61408c72cd6ce319d35c28c6c1d65f8011f2c8391e752a5142a468228c0d4bb8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Micro-Star Int'l Co. Ltd., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.RtCore"
        reference_sample = "38fa0c663c8689048726666f1c5e019feaa9da8278f1df6ff62da33961891d2a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 2D 53 74 61 72 20 49 6E 74 27 6C 20 43 6F 2E 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 54 00 49 00 4F 00 4C 00 69 00 62 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "NTIOLib.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}

rule Windows_VulnDriver_RtCore_729f70d7 {
    meta:
        author = "Elastic Security"
        id = "729f70d7-8491-41a6-b7be-f3677a7fd716"
        fingerprint = "7022f1f028e92cc123d98d4a7be372bcea2cc043a4ae16bd47d6c6ea3dc02f74"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: MICRO-STAR INTERNATIONAL CO., LTD."
        threat_name = "Windows.VulnDriver.RtCore"
        reference_sample = "bea8c6728d57d4b075f372ac82b8134ac8044fe13f533696a58e8864fa3efee3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 49 43 52 4F 2D 53 54 41 52 20 49 4E 54 45 52 4E 41 54 49 4F 4E 41 4C 20 43 4F 2E 2C 20 4C 54 44 2E }
        $str1 = "RTCoreMini64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

