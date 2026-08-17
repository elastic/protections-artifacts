rule Windows_VulnDriver_Novabench_7f2dc800 {
    meta:
        author = "Elastic Security"
        id = "7f2dc800-603a-4e5b-aebb-b931d74ba39d"
        fingerprint = "d59b3daab596e7a352274b67e13dfd2de66b2665971f4c6b26f37ddb6bf3ff19"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.Novabench"
        reference_sample = "b6a17c3a1ca599b9865889b3bc1780e566c6cd05c8c5c6a05d2a29fef7089880"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $serial = { 33 00 00 00 1F 98 00 C9 11 02 95 69 BE 00 00 00 00 00 1F }
        $str1 = "C:\\Users\\Nathan\\Projects\\novabench-win\\Novabench.Driver\\x64\\Release\\NovabenchDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $serial and $str1
}

