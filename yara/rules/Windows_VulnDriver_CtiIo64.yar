rule Windows_VulnDriver_CtiIo64_c51c48f1 {
    meta:
        author = "Elastic Security"
        id = "c51c48f1-aaac-4a9e-a8db-987b6f990d3b"
        fingerprint = "303bfd59f023c6ef7ba80ef267f76dabc66791061f5a168fa1c1ec80f0576aae"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.0.21.507"
        threat_name = "Windows.VulnDriver.CtiIo64"
        reference_sample = "2121a2bb8ebbf2e6e82c782b6f3c6b7904f686aa495def25cf1cf52a42e16109"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 74 00 69 00 49 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x14][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xfa][\x01-\x01])[\x15-\x15][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\xfb-\xfb][\x01-\x01][\x15-\x15][\x00-\x00])/
        $str1 = "CtiIo64.pdb"
        $str2 = "IOCTL_CTIIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_CTIIO_MAPPHYSTOLIN"
        $str4 = "CtiIo64 Driver Version 1.0" wide
        $str5 = "CTI IO driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

