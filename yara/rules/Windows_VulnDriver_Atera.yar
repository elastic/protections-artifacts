rule Windows_VulnDriver_Atera_3b915e6a {
    meta:
        author = "Elastic Security"
        id = "3b915e6a-37ab-4a89-b6df-cfb0e8e90285"
        fingerprint = "bfee9fba4c5ef3cd329611f87259a7386af852ea4a80200e9cb0ee1288ed4fc3"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Atera Networks Ltd"
        threat_name = "Windows.VulnDriver.Atera"
        reference_sample = "14d00976162a5d3238d183704fd84b50c3c5dcc762cab3c8adb5faf0a3caab99"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 74 65 72 61 20 4E 65 74 77 6F 72 6B 73 20 4C 74 64 }
        $str1 = "WinRing0x64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

