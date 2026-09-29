rule Windows_VulnDriver_Segurazo_955f5c75 {
    meta:
        author = "Elastic Security"
        id = "955f5c75-cf8f-41c6-b029-d3d778e43d6a"
        fingerprint = "5a2d7a5e785b1bec6d2e2ad9d1ebe238e20b31815294f1d595ea9963612a24cc"
        creation_date = "2026-09-09"
        last_modified = "2026-09-28"
        description = "Segurazo kernel driver with exposed IOCTL for process termination (0x999920DF)"
        threat_name = "Windows.VulnDriver.Segurazo"
        reference_sample = "9c84c22000de947c0551c46f04a1ee6f1e8d412aa3eefeb4533d13d144dbf583"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 61 00 6E 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 6B 00 64 00 2E 00 73 00 79 00 73 00 }
        $product_name = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 41 00 6E 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 }
        $product_version = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 31 00 2E 00 30 00 2E 00 31 00 2E 00 36 00 00 }
        $ioctl_df = { 81 FF DF 20 99 99 }
        $imp_terminate = "ZwTerminateProcess" ascii fullword
        $pdb = "SegurazoKD64.pdb" ascii fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $product_name and $product_version and $ioctl_df and $imp_terminate and $pdb
}

