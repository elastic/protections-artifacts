rule Windows_VulnDriver_RemkoWeijnen_36ce7287 {
    meta:
        author = "Elastic Security"
        id = "36ce7287-c057-411e-bdb3-32d3fc89a42a"
        fingerprint = "216dcbc650f3e6d9e85753319a76a1de921b1af593a9bfff3779f3a04cae9cb6"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Remko Weijnen"
        threat_name = "Windows.VulnDriver.RemkoWeijnen"
        reference_sample = "988960e31a258ea71cf93a7791ae8c91c8cefb6ad8a50cdbd1b07f73b524aa61"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 6D 6B 6F 20 57 65 69 6A 6E 65 6E }
        $str1 = "\\Device\\PhyMemPCIFilter" wide
        $seq1 = { 8B 48 04 83 E1 1F 8B 44 24 44 83 E0 E0 0B C1 89 44 24 44 48 8B 44 24 68 8B 48 08 83 E1 07 C1 E1 05 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $seq1
}

