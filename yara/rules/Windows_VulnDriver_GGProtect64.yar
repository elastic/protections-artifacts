rule Windows_VulnDriver_GGProtect64_6da0d3ed {
    meta:
        author = "Elastic Security"
        id = "6da0d3ed-5cd7-4253-a71e-ad181861f72d"
        fingerprint = "ee1e9230dee4ecfe5da402cff0eed8a6a4736bbed1cac11b24fdbe54ca74166a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.2.6.6"
        threat_name = "Windows.VulnDriver.GGProtect64"
        reference_sample = "0aa69aee93c6be9bc82680a7df99c114591038ae02e6666fc6e42acb09643111"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 47 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x02-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x05][\x00-\x00][\x06-\x06][\x00-\x00]|[\x02-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "GGProtect64.pdb"
        $str2 = "IOCTL_GET_DRIVER_INFO_BY_DEVICE_NAME"
        $str3 = "IOCTL_GET_DRIVER_INFO_BY_DRIVER_NAME"
        $str4 = { 47 00 47 00 DF 79 F7 53 2D 00 89 5B 68 51 21 6A 57 57 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

