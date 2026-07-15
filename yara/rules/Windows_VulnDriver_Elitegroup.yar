rule Windows_VulnDriver_Elitegroup_2842c0d4 {
    meta:
        author = "Elastic Security"
        id = "2842c0d4-f7ab-416a-8b67-f1d226524d65"
        fingerprint = "179eab85327c2cc3445ccf45036ef8b236ff984c746dd3bebcee24becc93dc72"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Elitegroup Computer Systems Co Ltd, Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Elitegroup"
        reference_sample = "08675796b8712e0e4ccbdf7831450b907bb94c2e3e85560d9aba1b24931f0d55"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 6C 69 74 65 67 72 6F 75 70 20 43 6F 6D 70 75 74 65 72 20 53 79 73 74 65 6D 73 20 43 6F 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 63 00 63 00 65 00 6C 00 4C 00 69 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AccelLid.pdb"
        $str2 = "IOCTL_KEYBOARD_CONTROL_FUNC"
        $str3 = "IOCTL_KEYBOARD_STATUS_FUNC"
        $str4 = "Lid Accelerometer Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_Elitegroup_4ae43f88 {
    meta:
        author = "Elastic Security"
        id = "4ae43f88-a44c-4434-9b14-210fd3d5d082"
        fingerprint = "7f21a57f215caf22401a4663874b567d10ce8c9c64d20390739924319faa5be4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Elitegroup Computer Systems Co., Ltd."
        threat_name = "Windows.VulnDriver.Elitegroup"
        reference_sample = "14edfdc13aeb98db50d597367f132443b086df0728f4fdb8c3bb5d47a8a0cd4a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 6C 69 74 65 67 72 6F 75 70 20 43 6F 6D 70 75 74 65 72 20 53 79 73 74 65 6D 73 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "ECSIoDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_Elitegroup_3e285b24 {
    meta:
        author = "Elastic Security"
        id = "3e285b24-8f1c-4683-8bec-a0b43a831fe3"
        fingerprint = "8adb9f1bd5b7356ccc1e7d2b29850c31b860d8f66d7185012fc2a5410f6908ca"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: ELITEGROUP COMPUTER SYSTEMS CO, Version: <= 1.1.0.0"
        threat_name = "Windows.VulnDriver.Elitegroup"
        reference_sample = "270547552060c6f4f5b2ebd57a636d5e71d5f8a9d4305c2b0fe5db0aa2f389cc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 4C 49 54 45 47 52 4F 55 50 20 43 4F 4D 50 55 54 45 52 20 53 59 53 54 45 4D 53 20 43 4F }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 43 00 53 00 49 00 6F 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ECSIoDriver.pdb"
        $str2 = "ECSIoDriver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

