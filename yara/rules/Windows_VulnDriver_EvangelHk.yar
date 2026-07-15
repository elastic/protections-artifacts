rule Windows_VulnDriver_EvangelHk_10b96965 {
    meta:
        author = "Elastic Security"
        id = "10b96965-b2c1-4be3-ae7a-b56a26aea7bf"
        fingerprint = "30543eddaa296d382a593e4e8e1a5225a17096fb6a983cfeab46e892e5dc1b4e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: EVANGEL TECHNOLOGY (HK) LIMITED"
        threat_name = "Windows.VulnDriver.EvangelHk"
        reference_sample = "d9f15d91397d1c8d01b6d6871c4f18f3a85ca85f091a92f4e9221524344ca5fe"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 56 41 4E 47 45 4C 20 54 45 43 48 4E 4F 4C 4F 47 59 20 28 48 4B 29 20 4C 49 4D 49 54 45 44 }
        $str1 = "kernel_hide_window.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

