rule Windows_VulnDriver_IndParkShiSuanKeJi_692a1584 {
    meta:
        author = "Elastic Security"
        id = "692a1584-fad4-402a-82e6-be7e99c69552"
        fingerprint = "6041b11ddd1b5622ae67ea71f723ca635285b7f80e0df7082cc2e8608923be22"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Suzhou Ind. Park ShiSuanKeJi Co., Ltd."
        threat_name = "Windows.VulnDriver.IndParkShiSuanKeJi"
        reference_sample = "23787eb342fd38da73ce785023176f98304267c6f6fa8a50e718da096c7a7951"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 75 7A 68 6F 75 20 49 6E 64 2E 20 50 61 72 6B 20 53 68 69 53 75 61 6E 4B 65 4A 69 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "PhyDMACC.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

