rule Windows_VulnDriver_HwRwDrv_cf6936dd {
    meta:
        author = "Elastic Security"
        id = "cf6936dd-a324-4c91-95ed-e2251d3914ee"
        fingerprint = "e55f27dcb5f54a610d967cd4837ca2b38c8446fd06e876eba2b8d36f4636a922"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Open Source Developer, Jun Liu, Version: <= 1.0.6.0"
        threat_name = "Windows.VulnDriver.HwRwDrv"
        reference_sample = "017933be6023795e944a2a373e74e2cc6885b5c9bc1554c437036250c20c3a7d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 70 65 6E 20 53 6F 75 72 63 65 20 44 65 76 65 6C 6F 70 65 72 2C 20 4A 75 6E 20 4C 69 75 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 77 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "HwRwDrv.pdb"
        $str2 = "Hardware read & write driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_HwRwDrv_8518e1f7 {
    meta:
        author = "Elastic Security"
        id = "8518e1f7-8020-4b6e-9ece-c35308a9c291"
        fingerprint = "3c19a47b0d26db4a0b9c20453e4c538cc7d00012df5e3b36fa86c704c33709e9"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Elitegroup Computer Systems Co LTD. , Version: <= 6.1.7600.16385"
        threat_name = "Windows.VulnDriver.HwRwDrv"
        reference_sample = "f2b95fc91fe33c1995c49c35e32124ece7d958ed7d3b7a5f325f2a30454b9256"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 6C 69 74 65 67 72 6F 75 70 20 43 6F 6D 70 75 74 65 72 20 53 79 73 74 65 6D 73 20 43 6F 20 4C 54 44 2E 20 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 77 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x1c]|[\x00-\xaf][\x1d-\x1d])|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x3f]|[\x00-\x00][\x40-\x40])[\xb0-\xb0][\x1d-\x1d]|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x40-\x40][\xb0-\xb0][\x1d-\x1d])/
        $str1 = "HwRwDrv.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "Hardware Read&Write Driver for x64." wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

