rule Windows_VulnDriver_Killav_563be7d5 {
    meta:
        author = "Elastic Security"
        id = "563be7d5-7228-4f62-95fd-8b53b4f71d08"
        fingerprint = "206766a78a6361ab0818a6ca5f3d496a7d3d64171856ab319fdf0ae554027f72"
        creation_date = "2026-07-20"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.VulnDriver.Killav"
        reference_sample = "97bd65e98cdc4e93d49edd4ea905d43a61244df0fd3323e6649330de3b1be091"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "KernelDriver.pdb"
        $str2 = "\\DosDevices\\eb" wide
        $seq1 = { 8B 84 24 88 00 00 00 48 8D 0D E4 EE FF FF 0F B6 84 01 80 1C 00 00 8B 84 81 44 1C 00 00 48 03 C1 FF E0 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $seq1
}

