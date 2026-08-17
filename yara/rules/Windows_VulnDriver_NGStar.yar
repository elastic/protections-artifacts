rule Windows_VulnDriver_NGStar_fd405192 {
    meta:
        author = "Elastic Security"
        id = "fd405192-bc3d-48b6-85a8-105fb070acc8"
        fingerprint = "dab41a7158cd2da10e2809735983311d409d9c47c5d71f00f66eca50f926d942"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Name: NGStar.sys, Version: <= 1.0.2.11"
        threat_name = "Windows.VulnDriver.NGStar"
        reference_sample = "4542b20be7adceb61fa5f538fed8c395951e775dbd7c4a2f7c6aee477c4d924e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 47 00 53 00 74 00 61 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0a][\x00-\x00][\x02-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x0b-\x0b][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "NGStar.pdb"
        $str2 = "IOCTL_UNLOCK_DEVICE"
        $str3 = "IOCTL_LOCK_DEVICE"
        $str4 = "NGStar.sys" wide
        $str5 = "NGStar Driver for Windows 2000/XP/Vista/7 (x64)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

