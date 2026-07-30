rule Windows_VulnDriver_RuidongtiandiInfoTech_35ac45b0 {
    meta:
        author = "Elastic Security"
        id = "35ac45b0-cbba-4706-a307-66194b6de97e"
        fingerprint = "1db8c5ad8ea0584c3297d41edd8a3bd9f2d8a6de6b68b8932a7d025468ac9377"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Beijing Ruidongtiandi Info.Tech.Co.,Ltd."
        threat_name = "Windows.VulnDriver.RuidongtiandiInfoTech"
        reference_sample = "ad938d15ecfd70083c474e1642a88b078c3cea02cdbddf66d4fb1c01b9b29d9a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 52 75 69 64 6F 6E 67 74 69 61 6E 64 69 20 49 6E 66 6F 2E 54 65 63 68 2E 43 6F 2E 2C 4C 74 64 2E }
        $str1 = "KApcHelper.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

