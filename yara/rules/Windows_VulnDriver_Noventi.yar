rule Windows_VulnDriver_Noventi_1d9804d7 {
    meta:
        author = "Elastic Security"
        id = "1d9804d7-bf6e-4fb5-82e1-f9ebfbbb6039"
        fingerprint = "45c509c4e10a4018f33cc00ba0f661e9f387fb4fbc0dcd9b4cbcb1571a4be16e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NOVENTI Health SE"
        threat_name = "Windows.VulnDriver.Noventi"
        reference_sample = "5e238d351e16d4909ca394f1db0326a60d33c9ac7b4d78aefcf17a6d9cc72be9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 4F 56 45 4E 54 49 20 48 65 61 6C 74 68 20 53 45 }
        $str1 = "amifldrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

