rule Windows_VulnDriver_Zemana_a8ae6e90 {
    meta:
        author = "Elastic Security"
        id = "a8ae6e90-54f2-432a-bb2a-4e21ec11b9cf"
        fingerprint = "16ff200764264bc08ba392d714fa7a58bed2266facf432eef70688e98676cd26"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zemana Ltd., Version: <= 1.8.2.320"
        threat_name = "Windows.VulnDriver.Zemana"
        reference_sample = "036c1151a30a9c25afc961d7305c58cbf8f68e5e5c1e726565c9a8168c2f3cdb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 65 6D 61 6E 61 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x3f][\x01-\x01])[\x02-\x02][\x00-\x00]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x40-\x40][\x01-\x01][\x02-\x02][\x00-\x00])/
        $str1 = "Win8KeyCrypt64.pdb"
        $str2 = "IOCTL_KEYCRYPT_DEACTIVATE_ENCRYPTION"
        $str3 = "IOCTL_KEYCRYPT_SYNC_INDEXES"
        $str4 = "AntiLogger Free" wide
        $str5 = "Zemana AntiLogger Free" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Zemana_afcf22a9 {
    meta:
        author = "Elastic Security"
        id = "afcf22a9-b01b-45fc-a5a1-3e93a80ec1a4"
        fingerprint = "3caa4081828ede7631630e3e9d55f5e96e01036a684cc3d631e1c63911e91c73"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zemana Ltd., Version: <= 1.8.6.204"
        threat_name = "Windows.VulnDriver.Zemana"
        reference_sample = "2b34ca35bd4f61d8e1d62b6129bef0a64c4655e80d6d39da06cb27c08e6996a3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 65 6D 61 6E 61 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xcb][\x00-\x00][\x06-\x06][\x00-\x00]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\xcc-\xcc][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "KeyCrypt64.pdb"
        $str2 = "IOCTL_KEYCRYPT_DEACTIVATE_ENCRYPTION"
        $str3 = "IOCTL_KEYCRYPT_SYNC_INDEXES"
        $str4 = "AntiLogger SDK" wide
        $str5 = "Zemana AntiLogger SDK" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

rule Windows_VulnDriver_Zemana_28dbfa92 {
    meta:
        author = "Elastic Security"
        id = "28dbfa92-0f57-4201-b1fe-c6687b46d7f0"
        fingerprint = "a3b0e05aaa62ed2fb7f11662dfdd1de9f6ef81040f8ee66df44d4e2c591f1e60"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zemana Ltd., Version: <= 2.1.0.208"
        threat_name = "Windows.VulnDriver.Zemana"
        reference_sample = "c02eabc2e096f00e6e46fb3b5cf0062db5e1b9d92877b701d2ea0bf27cd82cbe"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 65 6D 61 6E 61 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xcf][\x00-\x00][\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\xd0-\xd0][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "zam64.pdb"
        $str2 = "AntiMalware" wide
        $str3 = "Zemana AntiMalware" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Zemana_74cfef25 {
    meta:
        author = "Elastic Security"
        id = "74cfef25-393c-4aa9-bfb4-07f881e7559a"
        fingerprint = "288837f7e7fab96e4d33bddaaaab28fdffa8d9455811fa1f2537a30743f66fd0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zemana Ltd., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Zemana"
        reference_sample = "c3a2dade7d95085d5af4bf9dc218c97f802440b6c1bd2fdac520cb1a376b7e84"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 65 6D 61 6E 61 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
        $str4 = "Audit drv" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3 and $str4
}

