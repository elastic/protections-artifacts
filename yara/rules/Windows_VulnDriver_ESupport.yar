rule Windows_VulnDriver_ESupport_224a73ef {
    meta:
        author = "Elastic Security"
        id = "224a73ef-afa9-4329-b56c-e4f7aeef616f"
        fingerprint = "4f13c302fdd2f63758d6d9855f7277e128154427edbc47e49ec43e22d5947472"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: eSupport.com, Inc, Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.ESupport"
        reference_sample = "8cb62c5d41148de416014f80bd1fd033fd4d2bd504cb05b90eeb6992a382d58f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 65 53 75 70 70 6F 72 74 2E 63 6F 6D 2C 20 49 6E 63 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 67 00 65 00 6E 00 74 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Agent64.pdb"
        $str2 = "DriverAgent" wide
        $str3 = "DriverAgent Direct I/O for 64-bit Windows" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

