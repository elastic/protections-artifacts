rule Windows_VulnDriver_Mst_a9534673 {
    meta:
        author = "Elastic Security"
        id = "a9534673-0e48-440e-93b9-2660a03c75ff"
        fingerprint = "4a428a7f83576a3e13a5246166f5405e13da700c8b29efb689f4aa6c2d563f62"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: MellanoxCert(Test), Version: <= 0.1.0.0"
        threat_name = "Windows.VulnDriver.Mst"
        reference_sample = "bf8d3377fc0834828afcc94165172333b2e1b58fb37d45be91a07d8d2e54d431"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 65 6C 6C 61 6E 6F 78 43 65 72 74 28 54 65 73 74 29 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6D 00 73 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "mst.pdb"
        $str2 = "IOCTL_PCI_WRITE_DWORD"
        $str3 = "IOCTL_PCI_GET_DEVICES"
        $str4 = "MST (Mellanox Support Tools)" wide
        $str5 = "MST Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}

