rule Windows_VulnDriver_AppVkgr_d213a6a6 {
    meta:
        author = "Elastic Security"
        id = "d213a6a6-daf1-4e2e-ab5b-8b246d8a7ef6"
        fingerprint = "b5f7f2642e06d7ab0dd73b01121aea87e1f5de1699c45c8a627aeefa8e5d7c27"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.AppVkgr"
        reference_sample = "70b47bd596e76297ded3b096839082bc31f79ef58cdffeaac7308e8b9565a6d5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "C:\\Users\\Blluettw\\Downloads\\kprlRW(1)\\kprlRW\\x64\\Release\\kprl.pdb"
        $str2 = "[+] validate_hwnd=%llx\n"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}

