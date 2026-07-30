rule Windows_VulnDriver_ShenyangGeneralSoft_675f7350 {
    meta:
        author = "Elastic Security"
        id = "675f7350-137e-4453-aaa5-8448490bb3cd"
        fingerprint = "3eda5e5fcf3e1622de07c6a00e7ae3506790ff38b77df58bfb90ea790147f111"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Shenyang GeneralSoft Co., Ltd"
        threat_name = "Windows.VulnDriver.ShenyangGeneralSoft"
        reference_sample = "314a51fcf6e37eb8550a826df085d5c88c43eb1438682f3a6c33632d36956136"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 79 61 6E 67 20 47 65 6E 65 72 61 6C 53 6F 66 74 20 43 6F 2E 2C 20 4C 74 64 }
        $str1 = "IOCTL_GENERICDRV_DEALLOC_BUFFER"
        $str2 = "IOCTL_GENERICDRV_PHY_TO_VIRTUAL"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}

