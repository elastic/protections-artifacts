rule Windows_VulnDriver_Ktapi_2e8de3f4 {
    meta:
        author = "Elastic Security"
        id = "2e8de3f4-4b08-46b7-b1bb-6cd7ae64eed6"
        fingerprint = "588a0486e8ff93163734d845ec19983533150295aee26b01916334d1c8d596f5"
        creation_date = "2026-07-20"
        last_modified = "2026-08-11"
        description = "Subject: Kontron AG, Version: <= 1.0.1899.0"
        threat_name = "Windows.VulnDriver.Ktapi"
        reference_sample = "7ee17efef04bb7c9de90d5210263ed6993f867e5a11f86e65e3bb1362c7de237"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4B 6F 6E 74 72 6F 6E 20 41 47 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6B 00 74 00 61 00 70 00 69 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\x6a][\x07-\x07])|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x6b-\x6b][\x07-\x07])/
        $str1 = "ktapi.pdb"
        $str2 = "KTAPI System Driver" wide
        $str3 = "Kontron Technology Application Programming Interface" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Ktapi_dbca1325 {
    meta:
        author = "Elastic Security"
        id = "dbca1325-6203-45ee-9ec1-7e9524fc27d4"
        fingerprint = "8103824489395b8bf970b763730a9cba87b09b844dc6e64f1e0a71e4fa14825d"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: Kontron AG, Version: <= 1.0.2118.0"
        threat_name = "Windows.VulnDriver.Ktapi"
        reference_sample = "89ba754861e11d9db4440b2b5db61fd5bee16752e4623c4271b8fdd0a666c677"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4B 6F 6E 74 72 6F 6E 20 41 47 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6B 00 74 00 61 00 70 00 69 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x07]|[\x00-\x45][\x08-\x08])|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x46-\x46][\x08-\x08])/
        $str1 = "ktapi.pdb"
        $str2 = "KTAPI System Driver" wide
        $str3 = "Kontron Technology Application Programming Interface" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

