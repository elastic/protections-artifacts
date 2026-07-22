rule Windows_VulnDriver_PassMark_63fc2257 {
    meta:
        author = "Elastic Security"
        id = "63fc2257-552e-45c0-9fe3-f0a6d5a0fbd6"
        fingerprint = "43cc79589ef03c0281da171e78869fcf3db5b57399f29ce65a99873453e73a65"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: PassMark Software Pty Ltd"
        threat_name = "Windows.VulnDriver.PassMark"
        reference_sample = "035b96ff8b85d312be0f9df6271714392a802ec8bab59ae8229812ddc67ced5a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 73 73 4D 61 72 6B 20 53 6F 66 74 77 61 72 65 20 50 74 79 20 4C 74 64 }
        $str1 = "DirectIo32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_PassMark_183dd481 {
    meta:
        author = "Elastic Security"
        id = "183dd481-7052-4a19-aa58-1412e29a0928"
        fingerprint = "46509d10166ce40a7231c6ab6a309fb46682a97e768c7cda44007f3ebf0dd339"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: PassMark Software Pty Ltd"
        threat_name = "Windows.VulnDriver.PassMark"
        reference_sample = "31f4140c12ac31f5729a8de4dc051d3acd07783564604df831a2a6722c979192"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 73 73 4D 61 72 6B 20 53 6F 66 74 77 61 72 65 20 50 74 79 20 4C 74 64 }
        $str1 = "DirectIo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_PassMark_1ff60e4b {
    meta:
        author = "Elastic Security"
        id = "1ff60e4b-001f-42a6-bbb9-cbdbe0dece1e"
        fingerprint = "0cb391e8be4046c1b2cefea60468e304e67b643e87b210c1f0e599fb75f0dbcf"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: PassMark Software Pty Ltd"
        threat_name = "Windows.VulnDriver.PassMark"
        reference_sample = "8939116df1d6c8fd0ebd14b2d37b3dec38a8820aa666ecd487bc1bb794f2a587"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 73 73 4D 61 72 6B 20 53 6F 66 74 77 61 72 65 20 50 74 79 20 4C 74 64 }
        $str1 = "DirectIo64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

