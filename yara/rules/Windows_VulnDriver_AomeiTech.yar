rule Windows_VulnDriver_AomeiTech_88f10426 {
    meta:
        author = "Elastic Security"
        id = "88f10426-a42d-4a3a-b2e8-1d4d747e2905"
        fingerprint = "08a1b101a665cd06918bf7a96d2572b3b4e3e2373ca7a6197997a2ac2e6bb271"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: CHENGDU AOMEI Tech Co., Ltd."
        threat_name = "Windows.VulnDriver.AomeiTech"
        reference_sample = "01d51df682136cce453bb1da8964073e6bc7297ce4dae7301c753bb618a69469"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 48 45 4E 47 44 55 20 41 4F 4D 45 49 20 54 65 63 68 20 43 6F 2E 2C 20 4C 74 64 2E }
        $str1 = "ampa.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

