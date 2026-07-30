rule Windows_VulnDriver_Wistron_99bd2c09 {
    meta:
        author = "Elastic Security"
        id = "99bd2c09-8074-4d98-8dee-cac58c3aa5a6"
        fingerprint = "a0ebf678ca8c5d97e8752a07a03171047c655aeae9f34cea17fa9ed428b841fc"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Wistron Corporation"
        threat_name = "Windows.VulnDriver.Wistron"
        reference_sample = "4c776f34c6042d943baec3c13d7154a245aae8dd95e1933211fd19352c770676"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 69 73 74 72 6F 6E 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "Access.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_Wistron_b20bbaac {
    meta:
        author = "Elastic Security"
        id = "b20bbaac-ccb3-4f0d-aaab-dfd3855e8bd8"
        fingerprint = "3cbdb57dfa2c0e48bd04900eb607cbd04713bfef27babf8546fdf57a170f1331"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Wistron Corporation, Version: <= 1.0.0.1016"
        threat_name = "Windows.VulnDriver.Wistron"
        reference_sample = "d8fc8e3a1348393c5d7c3a84bcbae383d85a4721a751ad7afac5428e5e579b4e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 69 73 74 72 6F 6E 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 52 00 77 00 61 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xf7][\x03-\x03])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\xf8-\xf8][\x03-\x03][\x00-\x00][\x00-\x00])/
        $str1 = "WiRwaDrv.pdb"
        $str2 = "IOCTL_GPD_READ_PORT_ULONG"
        $str3 = "Wistron RWA Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

