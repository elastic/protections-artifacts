rule Windows_VulnDriver_WatchDog_879e37e1 {
    meta:
        author = "Elastic Security"
        id = "879e37e1-813f-4778-9dce-c5317f57e288"
        fingerprint = "8ff917baccb5fb6fbc0e6da9172609a9da38d558780f5fe9acf61da3d81066a7"
        creation_date = "2025-09-02"
        last_modified = "2026-07-29"
        threat_name = "Windows.VulnDriver.WatchDog"
        reference_sample = "5af1dae21425dda8311a2044209c308525135e1733eeff5dd20649946c6e054c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $wamsdk = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 61 00 6D 00 73 00 64 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $amsdk = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 6D 00 73 00 64 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x06][\x00-\x00])([\x00-\x64][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x63][\x00-\x00]))/
        $str1 = "WatchDog Antimalware Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and ($wamsdk or $amsdk) and $version and $str1
}

rule Windows_VulnDriver_WatchDog_2e17fccb {
    meta:
        author = "Elastic Security"
        id = "2e17fccb-8be8-4f61-bff5-f5abf5f6e3c3"
        fingerprint = "625b6234e42cebc89da8aa3c26c9f10909d6c7bc0821b5a2eb452f2898eb711e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: WATCHDOGDEVELOPMENT.COM, LLC, Version: <= 1.0.600.0"
        threat_name = "Windows.VulnDriver.WatchDog"
        reference_sample = "12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 41 54 43 48 44 4F 47 44 45 56 45 4C 4F 50 4D 45 4E 54 2E 43 4F 4D 2C 20 4C 4C 43 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 6D 00 73 00 64 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x01]|[\x00-\x57][\x02-\x02])|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x58-\x58][\x02-\x02])/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
        $str4 = "WatchDog Antimalware Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

rule Windows_VulnDriver_WatchDog_bff2fc23 {
    meta:
        author = "Elastic Security"
        id = "bff2fc23-d972-4f00-bc0f-b3970288bc6a"
        fingerprint = "2a5097cd87e47f98877aa546a9d370be0c4c34c1f36d9021427c7615f03dac79"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: WATCHDOGDEVELOPMENT.COM, LLC, Version: <= 0.3.1.0"
        threat_name = "Windows.VulnDriver.WatchDog"
        reference_sample = "6278bc785113831b2ec3368e2c9c9e89e8aca49085a59d8d38dac651471d6440"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 41 54 43 48 44 4F 47 44 45 56 45 4C 4F 50 4D 45 4E 54 2E 43 4F 4D 2C 20 4C 4C 43 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 73 00 64 00 6B 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "wsdk-driver.pdb"
        $str2 = "WatchDog Antivirus Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

