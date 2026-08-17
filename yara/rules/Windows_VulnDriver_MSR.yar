rule Windows_VulnDriver_MSR_adc5e74e {
    meta:
        author = "Elastic Security"
        id = "adc5e74e-cd75-4a69-ba57-cd9cfa2f8acb"
        fingerprint = "b06d234b77b58cf3625f783c2f45c6f5958e8205accd0cb54d1c33818d62819e"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.MSR"
        reference_sample = "6c6a4d07e95ab4212c2afefcb0ce37dc485fa56120b0419b636bd8bd326038c1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "c:\\work\\source\\git\\pcm\\src\\winmsrdriver\\objfre_win7_amd64\\amd64\\msr.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

