rule Windows_VulnDriver_Moyea_6c89a73e {
    meta:
        author = "Elastic Security"
        id = "6c89a73e-6ed0-4efd-8a76-0137c1cf38e9"
        fingerprint = "58867650386af24ae3e0d0c7370415bcdeac7fb090823068e5251be6b7643904"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Shenzhen Moyea Software"
        threat_name = "Windows.VulnDriver.Moyea"
        reference_sample = "0b9a7449bade14983a7520f2d57448823b85a22074ddb48f0e47b9c5442da68b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 4D 6F 79 65 61 20 53 6F 66 74 77 61 72 65 }
        $str1 = "phymem.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

