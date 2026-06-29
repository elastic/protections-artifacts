rule Windows_VulnDriver_AMI_2f77d45b {
    meta:
        author = "Elastic Security"
        id = "2f77d45b-0edb-4a6b-b7e1-9151fac2d784"
        fingerprint = "9f10adcc19a4c6b3a013848afa317122855bd6b85347a0aa5474e5b45534b900"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Subject: American Megatrends, Inc."
        threat_name = "Windows.VulnDriver.AMI"
        reference_sample = "a7c8f4faf3cbb088cac7753d81f8ec4c38ccb97cd9da817741f49272e8d01200"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 6D 65 72 69 63 61 6E 20 4D 65 67 61 74 72 65 6E 64 73 2C 20 49 6E 63 2E }
        $str1 = "IOCTL_GENERICDRV_DEALLOC_BUFFER"
        $str2 = "IOCTL_GENERICDRV_PHY_TO_VIRTUAL"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}

