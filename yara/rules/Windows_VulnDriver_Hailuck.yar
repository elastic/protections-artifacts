rule Windows_VulnDriver_Hailuck_feaee52b {
    meta:
        author = "Elastic Security"
        id = "feaee52b-cb49-4e06-98cd-68a6f1d252d5"
        fingerprint = "63cdebbfaee4fd6122d1e115391ab3b2b9100a8a297548eba1ce4bc2018f5e80"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: ShenZhen Hailuck Co.,Ltd."
        threat_name = "Windows.VulnDriver.Hailuck"
        reference_sample = "2e8c28298890f1684be3827bcdb0746a124a0ffe58d1c9a4c361c2e8b13cf735"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 5A 68 65 6E 20 48 61 69 6C 75 63 6B 20 43 6F 2E 2C 4C 74 64 2E }
        $str1 = "WinIo.pdb"
        $str2 = "IOCTL_WINIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_WINIO_MAPPHYSTOLIN"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}

