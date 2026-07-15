rule Windows_VulnDriver_CleverSoarElectronic_ab08be6d {
    meta:
        author = "Elastic Security"
        id = "ab08be6d-084a-4b6d-ba26-6d9669350a7e"
        fingerprint = "8804190db2a4b404da9818649d5abd112abb3a571a991cee4d8484ffbf5147ef"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: CleverSoar Electronic Technology Co., Ltd."
        threat_name = "Windows.VulnDriver.CleverSoarElectronic"
        reference_sample = "e055fdfb914e3da936eb7745acb665f50346df9abac597cf43d487262a6a12d5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 6C 65 76 65 72 53 6F 61 72 20 45 6C 65 63 74 72 6F 6E 69 63 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "MyDriver1.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

