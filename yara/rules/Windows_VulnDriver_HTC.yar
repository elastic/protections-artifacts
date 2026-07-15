rule Windows_VulnDriver_HTC_51077d74 {
    meta:
        author = "Elastic Security"
        id = "51077d74-2e96-480b-a974-dd49b100e6f0"
        fingerprint = "51d8ad75a983f504570f9d8af86d0987a98a6797662321726165e7f4552fb38e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: HTC CORPORATION, Version: <= 0.1.11.7"
        threat_name = "Windows.VulnDriver.HTC"
        reference_sample = "9d5e8700a434838eb63a0573178b4291f07a9d96dabfb4ead40253a3cd9edefd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 54 43 20 43 4F 52 50 4F 52 41 54 49 4F 4E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 69 00 76 00 65 00 52 00 52 00 41 00 75 00 64 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x06][\x00-\x00][\x0b-\x0b][\x00-\x00]|[\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00][\x0b-\x0b][\x00-\x00])/
        $str1 = "viverraudio.pdb"
        $str2 = "IOCTL_SIOCTL_METHOD_OUT_DIRECT"
        $str3 = "IOCTL_SIOCTL_METHOD_IN_DIRECT"
        $str4 = "VIVE Virtual Audio Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

