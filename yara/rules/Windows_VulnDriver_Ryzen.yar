rule Windows_VulnDriver_Ryzen_7df5a747 {
    meta:
        author = "Elastic Security"
        id = "7df5a747-d924-459d-8363-9c12841ef37f"
        fingerprint = "1bf5d6b2739ce4fe5137cff84e7bfb9389e8d175480094fe831f8f68d84abb16"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: AMDRyzenMasterDriver.sys, Version: 1.5.0.0"
        threat_name = "Windows.VulnDriver.Ryzen"
        reference_sample = "a13054f349b7baa8c8a3fcbd31789807a493cc52224bbff5e412eb2bd52a6433"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4D 00 44 00 52 00 79 00 7A 00 65 00 6E 00 4D 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x05][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x04][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Ryzen_9b01c718 {
    meta:
        author = "Elastic Security"
        id = "9b01c718-ba36-4642-b27d-e9310d05d8a5"
        fingerprint = "18ad3df5ae549dddbe1f6f33db534b4fcfc603e0863f8262a8cb9c166a16af67"
        creation_date = "2023-01-22"
        last_modified = "2023-06-13"
        description = "Name: AMDRyzenMasterDriver.sys, Version: <= 1.7.0.0"
        threat_name = "Windows.VulnDriver.Ryzen"
        reference_sample = "bb82d8c29127955d58dff58978605a9daa718425c74c4bce5ae3e53712909148"
        severity = 49
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4D 00 44 00 52 00 79 00 7A 00 65 00 6E 00 4D 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x07][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x06][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version
}

rule Windows_VulnDriver_Ryzen_a05f22b5 {
    meta:
        author = "Elastic Security"
        id = "a05f22b5-bbf9-4245-9ec3-2b8faad05712"
        fingerprint = "1cc01cf5cfcd5358f3d32dc2fdb33f65a0b623d011c6010a4f9ca8f087471bc8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Advanced Micro Devices INC., Version: <= 1.7.0.0"
        threat_name = "Windows.VulnDriver.Ryzen"
        reference_sample = "4a0d0034f6deabb9369f553d4d9f3a7aa6f87fa8f2292be576d7b42897c686bb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 64 76 61 6E 63 65 64 20 4D 69 63 72 6F 20 44 65 76 69 63 65 73 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4D 00 44 00 52 00 79 00 7A 00 65 00 6E 00 4D 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AMDRyzenMasterDriver.pdb"
        $str2 = "IOCTL_WRITE_FUNCTION0"
        $str3 = "IOCTL_WRITE_FUNCTION1"
        $str4 = "AMD Ryzen Master Service Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_Ryzen_b0ac1fc8 {
    meta:
        author = "Elastic Security"
        id = "b0ac1fc8-295d-411f-a6b0-9ecb4d505877"
        fingerprint = "baecd46c53d0b9f7da95d65974018fc908a3acdfbde96bd56d0f3b8ff155dc0e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Advanced Micro Devices Inc., Version: <= 1.3.0.0"
        threat_name = "Windows.VulnDriver.Ryzen"
        reference_sample = "7e81beae78e1ddbf6c150e15667e1f18783f9b0ab7fbe52c7ab63e754135948d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 64 76 61 6E 63 65 64 20 4D 69 63 72 6F 20 44 65 76 69 63 65 73 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4D 00 44 00 52 00 79 00 7A 00 65 00 6E 00 4D 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AMDRyzenMasterDriver.pdb"
        $str2 = "IOCTL_WRITE_FUNCTION0"
        $str3 = "IOCTL_WRITE_FUNCTION1"
        $str4 = "AMD Ryzen Master Service Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_Ryzen_c103c2f1 {
    meta:
        author = "Elastic Security"
        id = "c103c2f1-acb9-4fce-985a-f6c91e69d55b"
        fingerprint = "32593a5c559c561d498946f05aeec14132074db862385d12ecec60487e367ee4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Advanced Micro Devices, Inc., Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.Ryzen"
        reference_sample = "f6cd7353cb6e86e98d387473ed6340f9b44241867508e209e944f548b9db1d5f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 64 76 61 6E 63 65 64 20 4D 69 63 72 6F 20 44 65 76 69 63 65 73 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4D 00 44 00 52 00 79 00 7A 00 65 00 6E 00 4D 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AMDRyzenMasterDriver.pdb"
        $str2 = "IOCTL_WRITE_FUNCTION0"
        $str3 = "IOCTL_WRITE_FUNCTION1"
        $str4 = "AMD Ryzen Master Service Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

