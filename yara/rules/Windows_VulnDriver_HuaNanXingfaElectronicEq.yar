rule Windows_VulnDriver_HuaNanXingfaElectronicEq_45f0e147 {
    meta:
        author = "Elastic Security"
        id = "45f0e147-49ac-41f9-a99c-de3b3b9a85d0"
        fingerprint = "8c54b4057f84c8814eb5b9009a0ccaac2eca58606a60a3382dd01a4f68aac61a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Shenzhen Hua’nan Xingfa Electronic Equipment Firm"
        threat_name = "Windows.VulnDriver.HuaNanXingfaElectronicEq"
        reference_sample = "099ef4915d7899be543d891b48960c1d1604c55468c1377a6f71ce0e1a33c946"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 48 75 61 E2 80 99 6E 61 6E 20 58 69 6E 67 66 61 20 45 6C 65 63 74 72 6F 6E 69 63 20 45 71 75 69 70 6D 65 6E 74 20 46 69 72 6D }
        $str1 = "nullout.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

rule Windows_VulnDriver_HuaNanXingfaElectronicEq_f3f6d16c {
    meta:
        author = "Elastic Security"
        id = "f3f6d16c-e40b-496f-9e5d-ff4a539a8268"
        fingerprint = "581c07fa208f5238bed5456ee48b0d5d284eac5160faa7e2421437595ac57155"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Shenzhen Hua’nan Xingfa Electronic Equipment Firm"
        threat_name = "Windows.VulnDriver.HuaNanXingfaElectronicEq"
        reference_sample = "5c308aede12fefb8145c015a97d7844106df5469de97773cba3bd3d772dc7d24"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 48 75 61 E2 80 99 6E 61 6E 20 58 69 6E 67 66 61 20 45 6C 65 63 74 72 6F 6E 69 63 20 45 71 75 69 70 6D 65 6E 74 20 46 69 72 6D }
        $str1 = "xxxxxxxxx10.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

