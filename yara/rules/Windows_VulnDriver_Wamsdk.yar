rule Windows_VulnDriver_Wamsdk_3d68f8e0 {
    meta:
        author = "Elastic Security"
        id = "3d68f8e0-3d78-4579-a715-f6f8956288d0"
        fingerprint = "c4fc02c93c01414fc821e43a678cb7c43c889e6f300788c03ed579f3639adf42"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: wamsdk.sys, Version: <= 1.1.100.0"
        threat_name = "Windows.VulnDriver.Wamsdk"
        reference_sample = "5065bdfacf80a1ee8c9baf6b73e4c630ab36d33e4230db658b8e20d235a89624"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 61 00 6D 00 73 00 64 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x63][\x00-\x00]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x64-\x64][\x00-\x00])/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
        $str4 = "WatchDog Antimalware Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

