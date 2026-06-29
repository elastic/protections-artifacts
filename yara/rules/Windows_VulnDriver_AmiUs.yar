rule Windows_VulnDriver_AmiUs_7d64ea79 {
    meta:
        author = "Elastic Security"
        id = "7d64ea79-28f8-49e3-a970-d7d97324addd"
        fingerprint = "58cbad3f8aec6f8394bfbb2ba2a38ca1418beedc6fecc96c0cad2cf902e60873"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Subject: AMI US HOLDINGS INC"
        threat_name = "Windows.VulnDriver.AmiUs"
        reference_sample = "09043c51719d4bf6405c9a7a292bb9bb3bcc782f639b708ddcc4eedb5e5c9ce9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 4D 49 20 55 53 20 48 4F 4C 44 49 4E 47 53 20 49 4E 43 }
        $str1 = "amifldrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

