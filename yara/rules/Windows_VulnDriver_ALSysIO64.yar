rule Windows_VulnDriver_ALSysIO64_d72c198d {
    meta:
        author = "Elastic Security"
        id = "d72c198d-c4ef-47c2-b1a5-0c0eaceb3a5f"
        fingerprint = "44ec39611b2ad6ffb5d02362e0750e90e2d67deae725893094096385ae3fc2d3"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Name: ALSysIO64.sys, Version: <= 2.0.0.1"
        threat_name = "Windows.VulnDriver.ALSysIO64"
        reference_sample = "3e9cba7db0f8836a12ffe10535c41df27b3f61c1dd3851118f2aadd47771cdf6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4C 00 53 00 79 00 73 00 49 00 4F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "CpuInfo.pdb"
        $str2 = "ALSysIO64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_ALSysIO64_befe8759 {
    meta:
        author = "Elastic Security"
        id = "befe8759-c3e9-4678-ac89-c10ebdc4cebd"
        fingerprint = "023117c7a77092612a269f3e1d5852d95e73c8c31af4040751d75b29a98c8d67"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.1.0.0"
        threat_name = "Windows.VulnDriver.ALSysIO64"
        reference_sample = "7a20ca8f9361eb892257b3693095ffeee61457dc4e22d9b119e3a9f3a1507069"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4C 00 53 00 79 00 73 00 49 00 4F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "ALSysIO64.pdb"
        $str2 = "ALSysIO64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

