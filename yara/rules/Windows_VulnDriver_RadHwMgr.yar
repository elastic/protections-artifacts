rule Windows_VulnDriver_RadHwMgr_9692edd5 {
    meta:
        author = "Elastic Security"
        id = "9692edd5-ceed-4998-81ee-4f11e12ad32b"
        fingerprint = "918d0bd89ce73c00a3bdeb06712aa5a5fdf2b0d1abd2d8d871a3a73e1e0cd345"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: RadHwMgr.sys, Version: <= 9.9.0.1"
        threat_name = "Windows.VulnDriver.RadHwMgr"
        reference_sample = "7c79e5196c2f51d2ab16e40b9d5725a8bf6ae0aaa70b02377aedc0f4e93ca37f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 61 00 64 00 48 00 77 00 4D 00 67 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x08][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x09-\x09][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x09-\x09][\x00-\x00][\x09-\x09][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RadHwMgr.pdb"
        $str2 = "IOCTL_RADHWMGR_READ_IO"
        $str3 = "Radiant Systems, Inc.  Hardware Manager driver" wide
        $str4 = "Radiant Hardware Manager for P15xx Platform" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

