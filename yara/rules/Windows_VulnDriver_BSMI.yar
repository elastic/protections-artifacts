rule Windows_VulnDriver_BSMI_65223b8d {
    meta:
        author = "Elastic Security"
        id = "65223b8d-451a-4ae6-90cc-17d1482cc834"
        fingerprint = "9ad213d919719d0fb0a99dcb9863720adec173e9801663e1cf5b99881435914a"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: BSMI.sys, Version: 1.0.0.3"
        threat_name = "Windows.VulnDriver.BSMI"
        reference_sample = "59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 4D 00 49 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_BSMI_29f0ed5a {
    meta:
        author = "Elastic Security"
        id = "29f0ed5a-8b14-4ea3-b09e-0b4d4bf42ece"
        fingerprint = "4e7c2deb261832102b24e99a288b98974dc3d639112cba366fd534597bfe9374"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: BIOSTAR MICROTECH INT'L CORP, Version: <= 1.0.0.3"
        threat_name = "Windows.VulnDriver.BSMI"
        reference_sample = "1d881e9210ce09317201def197ad333f25ef58c7add5256eb05508a75974c11b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 49 4F 53 54 41 52 20 4D 49 43 52 4F 54 45 43 48 20 49 4E 54 27 4C 20 43 4F 52 50 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 4D 00 49 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "BSMI.pdb"
        $str2 = "IOCTL_GET_PHYSICALADDRESS"
        $str3 = "IOCTL_READ_MEMORY"
        $str4 = "SMI Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

