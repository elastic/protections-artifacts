rule Windows_VulnDriver_EchoDrv_d17ff31c {
    meta:
        author = "Elastic Security"
        id = "d17ff31c-59d1-4bea-be25-c6f7fe2b8c7b"
        fingerprint = "dcf828c8db88580faeaa78f4bcda5a01ff4e710cb3e1e0912a99665831a070b4"
        creation_date = "2023-10-31"
        last_modified = "2023-11-03"
        threat_name = "Windows.VulnDriver.EchoDrv"
        reference_sample = "ea3c5569405ed02ec24298534a983bcb5de113c18bc3fd01a4dd0b5839cd17b9"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "D:\\WACATACC\\Projects\\Programs\\Echo\\x64\\Release\\echo-driver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $str1
}

rule Windows_VulnDriver_EchoDrv_b8114f4d {
    meta:
        author = "Elastic Security"
        id = "b8114f4d-81c5-49dd-843e-9ba1b5b22642"
        fingerprint = "97df9f848d1b6f661fceb33da71e4be626f666094664e7104a471cb19b560c99"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.EchoDrv"
        reference_sample = "a41e9bb037cf1dc2237659b1158f0ed4e49b752b2f9dae4cc310933a9d1f1e47"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "W:\\Projects\\Programs\\Echo\x64\\Release\\echo-driver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

