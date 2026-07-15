rule Windows_VulnDriver_CheatEngine_94bb1403 {
    meta:
        author = "Elastic Security"
        id = "94bb1403-ebf1-4d9d-8c81-be8183128b9f"
        fingerprint = "69f07b248bec6e6c94dd802928ba5590d23660c08435e8f2c35a60f21c644e32"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Cheat Engine"
        threat_name = "Windows.VulnDriver.CheatEngine"
        reference_sample = "626fae47811450d080d08c3d9fd890aa64bfecdc45eacd42a40850c1833c8763"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 65 61 74 20 45 6E 67 69 6E 65 }
        $str1 = "DBK64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

