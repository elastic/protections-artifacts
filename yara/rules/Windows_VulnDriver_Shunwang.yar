rule Windows_VulnDriver_Shunwang_af2d9593 {
    meta:
        author = "Elastic Security"
        id = "af2d9593-0dca-4d74-9d40-32458240aa7a"
        fingerprint = "66e5fe900534992a80e5487d58a97b5afc993372d63c2d83d74e60c7c10ce440"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Hangzhou Shunwang Technology Co.,Ltd"
        threat_name = "Windows.VulnDriver.Shunwang"
        reference_sample = "1aed62a63b4802e599bbd33162319129501d603cceeb5e1eb22fd4733b3018a3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 61 6E 67 7A 68 6F 75 20 53 68 75 6E 77 61 6E 67 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 4C 74 64 }
        $str1 = "rentdrv.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_Shunwang_80761e67 {
    meta:
        author = "Elastic Security"
        id = "80761e67-b58f-43b4-b876-58fcddf8046a"
        fingerprint = "26a5056ec04460f4c39729c3e204df5b982acffb5c47419eadf5f61b5b9e1d6b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Hangzhou Shunwang Technology Co.,Ltd"
        threat_name = "Windows.VulnDriver.Shunwang"
        reference_sample = "39c128ceabfb170ef5fdbe7f7740de48a9d9119df2e01763c25995cea1097785"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 61 6E 67 7A 68 6F 75 20 53 68 75 6E 77 61 6E 67 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 4C 74 64 }
        $str1 = "rentdrv_x64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

