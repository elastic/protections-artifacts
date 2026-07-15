rule Windows_VulnDriver_Cmdx_86e57b91 {
    meta:
        author = "Elastic Security"
        id = "86e57b91-a3c0-4fc7-b139-6ab2dccf8ad6"
        fingerprint = "41ac7404d93c00deca04b4736b4d9f68dd00f7afc0674f1f9fa1abcc89270f1c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: cmdx.exe, Version: <= 3.0.0.0"
        threat_name = "Windows.VulnDriver.Cmdx"
        reference_sample = "eb5fe9994119f97628217abda869306c268e4396153f42a6ceee8bf501673f0c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 6D 00 64 00 78 00 2E 00 65 00 78 00 65 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
        $str4 = "Advanced Malware Protection" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}

