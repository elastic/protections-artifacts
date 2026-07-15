rule Windows_VulnDriver_Bopsoft_923591e2 {
    meta:
        author = "Elastic Security"
        id = "923591e2-3c13-4d29-a78f-14d827300d65"
        fingerprint = "288663d012176cfd6d72a6b34ff2db690d44a113a54f6fc1aa0e7108c4b706ba"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Bopsoft"
        threat_name = "Windows.VulnDriver.Bopsoft"
        reference_sample = "b6cb163089f665c05d607a465f1b6272cdd5c949772ab9ce7227120cf61f971a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 6F 70 73 6F 66 74 }
        $str1 = "MemoryTest.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

