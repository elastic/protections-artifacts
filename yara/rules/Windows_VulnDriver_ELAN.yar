rule Windows_VulnDriver_ELAN_1fc53608 {
    meta:
        author = "Elastic Security"
        id = "1fc53608-891c-4fb7-8b6b-da2da8dd4ef7"
        fingerprint = "7c022173a46bb219a70e2ebe9fd0431f4d4f1badbe5f31bcce7d989214657d33"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: ELAN Microelectronics Corporation"
        threat_name = "Windows.VulnDriver.ELAN"
        reference_sample = "be929ae99015fafa0ab55cb475035e8c1359db1b61e00507defc1919a3538385"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 4C 41 4E 20 4D 69 63 72 6F 65 6C 65 63 74 72 6F 6E 69 63 73 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $str1 = "WinIo64.pdb"
        $str2 = "IOCTL_WINIO_FREEALLOCPHYS"
        $str3 = "IOCTL_WINIO_UNMAPPHYSADDR"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

