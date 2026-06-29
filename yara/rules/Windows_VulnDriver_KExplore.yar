rule Windows_VulnDriver_KExplore_30925683 {
    meta:
        author = "Elastic Security"
        id = "30925683-a7d5-421f-bff7-5dd622356214"
        fingerprint = "7f5cb698a40b99f50f4246c61d47a1c6e99fd0c4baa830a7b6a514e567aafe7d"
        creation_date = "2026-05-22"
        last_modified = "2026-06-24"
        description = "Subject: Pavel Yosifovich"
        threat_name = "Windows.VulnDriver.KExplore"
        reference_sample = "5c237dcec01f5e31a78cf8c883e41d85c74675b1426379302b46b771d091dce6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 76 65 6C 20 59 6F 73 69 66 6F 76 69 63 68 }
        $str1 = "KRegExp.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_KExplore_929d04c4 {
    meta:
        author = "Elastic Security"
        id = "929d04c4-1ad9-4929-9b65-7528fe067883"
        fingerprint = "57ecb673ca1a789d6b6708a23c25a365a99a93f04cfdd1035c6f357ecf4980bf"
        creation_date = "2026-05-22"
        last_modified = "2026-06-24"
        description = "Subject: Pavel Yosifovich"
        threat_name = "Windows.VulnDriver.KExplore"
        reference_sample = "88a9b030ab81082629253c581fe0670019c766f32acfc78a6cdc1080ad272fe4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 76 65 6C 20 59 6F 73 69 66 6F 76 69 63 68 }
        $str1 = "KObjExp.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_KExplore_3fb07df2 {
    meta:
        author = "Elastic Security"
        id = "3fb07df2-c7bf-4ded-b9ea-9f16234a4e1b"
        fingerprint = "34d14ddfa4f95a47d61fd418616c71122c98f6df62194551acafa3f530af9aba"
        creation_date = "2026-05-22"
        last_modified = "2026-06-24"
        description = "Subject: Pavel Yosifovich"
        threat_name = "Windows.VulnDriver.KExplore"
        reference_sample = "c71e14961ac29165ddf6e5e8f9372e82fc79494da07afbfaf2ccfc9bd3bbbe18"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 76 65 6C 20 59 6F 73 69 66 6F 76 69 63 68 }
        $str1 = "KExplore.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

