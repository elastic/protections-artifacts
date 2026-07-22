rule Windows_VulnDriver_LeiGod_0d493945 {
    meta:
        author = "Elastic Security"
        id = "0d493945-7fe2-4a4c-8dca-b69266b11b1b"
        fingerprint = "874d07ea2fdd0a7d28874c0977bde646a2decc88323757aba25b2a9dca1546db"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: 雷神（武汉）信息技术有限公司"
        threat_name = "Windows.VulnDriver.LeiGod"
        reference_sample = "58c071cfe72e9ee867bba85cbd0abe72eb223d27978d6f0650d0103553839b59"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E9 9B B7 E7 A5 9E EF BC 88 E6 AD A6 E6 B1 89 EF BC 89 E4 BF A1 E6 81 AF E6 8A 80 E6 9C AF E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $str1 = "wfp_win8_64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

