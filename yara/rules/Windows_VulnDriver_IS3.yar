rule Windows_VulnDriver_IS3_6a5e1c45 {
    meta:
        author = "Elastic Security"
        id = "6a5e1c45-b1c6-4e9c-841a-0b761317b29a"
        fingerprint = "8d111d2923ce68cc4a570497d891da881e04a95d007263687ab594eccd4e3f44"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: iS3, Inc., Version: <= 3.0.23.0"
        threat_name = "Windows.VulnDriver.IS3"
        reference_sample = "6bc0e1c104fac4a8caa4237c7ae181ca11a043a3ee26426aeb7a90dc40281fad"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 69 53 33 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 7A 00 6B 00 67 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x16][\x00-\x00]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x17-\x17][\x00-\x00])/
        $str1 = "szkg64.pdb"
        $str2 = "IOCTL_MSPROCESS_WAIT_REGISTRY_EVENT_H"
        $str3 = "IOCTL_MSPROCESS_MONITORIMAGELOADS_H"
        $str4 = "Stopzilla" wide
        $str5 = "szkg Device Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

