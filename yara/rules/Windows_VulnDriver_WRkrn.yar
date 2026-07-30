rule Windows_VulnDriver_WRkrn_8851e7d2 {
    meta:
        author = "Elastic Security"
        id = "8851e7d2-d55c-46df-a4ca-44f55152727d"
        fingerprint = "cfd869b7f866579ffecf6856a1f52dcdd987eb4d3c9abb2f9628c383a91f48bb"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 9.0.40.19"
        threat_name = "Windows.VulnDriver.WRkrn"
        reference_sample = "061d9e1cbb06bee5bad025bbc190de1d83bc8298610a6eb525102d9600cfd683"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 52 00 6B 00 72 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x27][\x00-\x00]|[\x00-\x00][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\x12][\x00-\x00][\x28-\x28][\x00-\x00]|[\x00-\x00][\x00-\x00][\x09-\x09][\x00-\x00][\x13-\x13][\x00-\x00][\x28-\x28][\x00-\x00])/
        $str1 = "WRKrn.pdb"
        $str2 = "Webroot SecureAnywhere" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_WRkrn_2e366a1b {
    meta:
        author = "Elastic Security"
        id = "2e366a1b-732f-444a-b85f-815e0c208c91"
        fingerprint = "364d12693ad5e3ac56259a5e3df1f2cdc325e4409a84e667d0f276df80d5dec2"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: WRkrn.sys, Version: <= 9.0.27.43"
        threat_name = "Windows.VulnDriver.WRkrn"
        reference_sample = "c3e8dd1569cb951e2a34d710fddd5caafd348db34407940f80221fb32b178499"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 52 00 6B 00 72 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x1a][\x00-\x00]|[\x00-\x00][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\x2a][\x00-\x00][\x1b-\x1b][\x00-\x00]|[\x00-\x00][\x00-\x00][\x09-\x09][\x00-\x00][\x2b-\x2b][\x00-\x00][\x1b-\x1b][\x00-\x00])/
        $str1 = "wrkrn.pdb"
        $str2 = "Webroot SecureAnywhere" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}

