rule Windows_VulnDriver_Yy_b8f7d8d3 {
    meta:
        author = "Elastic Security"
        id = "b8f7d8d3-44b2-4301-81bc-65f9d3dbbb8a"
        fingerprint = "9dd9a3fc852efee80cb14841092b0c9c43ddd32378ada3b50231a659d01e6161"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: YY Inc."
        threat_name = "Windows.VulnDriver.Yy"
        reference_sample = "dcd026fd2ff8d517e2779d67b3d2d5f9a7aa39f19c66fa8ff2cab66d5c6461c6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 59 59 20 49 6E 63 2E }
        $str1 = "YYProtect.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

