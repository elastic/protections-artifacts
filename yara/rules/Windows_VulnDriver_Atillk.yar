rule Windows_VulnDriver_Atillk_18316dd9 {
    meta:
        author = "Elastic Security"
        id = "18316dd9-0a58-4e06-bebd-13f3de45c054"
        fingerprint = "74d618e50edf662aae13e7577a02cfc54c5a15045b34acdb2f5714ce8c65a487"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        description = "Name: atillk64.sys, Version: 5.11.9.0"
        threat_name = "Windows.VulnDriver.Atillk"
        reference_sample = "ad40e6d0f77c0e579fb87c5106bf6de3d1a9f30ee2fbf8c9c011f377fa05f173"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 74 00 69 00 6C 00 6C 00 6B 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x0b][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x09][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x04][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x0a][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x0b][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x08][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Atillk_f9e8859c {
    meta:
        author = "Elastic Security"
        id = "f9e8859c-50f6-4e20-ba7d-f876ccb0457e"
        fingerprint = "63c95583762b75b832d30b646b07e9c88908d032b1c87355977089d4ae46e5b1"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Name: atillk64.sys, Version: <= 5.10.20.0"
        threat_name = "Windows.VulnDriver.Atillk"
        reference_sample = "11a9787831ac4f0657aeb5e7019c23acc39d8833faf28f85bd10d7590ea4cc5f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 74 00 69 00 6C 00 6C 00 6B 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x09][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0a-\x0a][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x14-\x14][\x00-\x00])/
        $str1 = "atikia64.pdb"
        $str2 = "Overclocking Tool" wide
        $str3 = "Overclocking Hardware Abstraction Sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Atillk_e44e31f5 {
    meta:
        author = "Elastic Security"
        id = "e44e31f5-a86f-47ce-bdaa-45f8e6ce8205"
        fingerprint = "19028e15c2d88eb67ec8287c8be79b3d303762d286506725cf14de905823a1ea"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Name: atillk64.sys, Version: <= 5.11.9.0"
        threat_name = "Windows.VulnDriver.Atillk"
        reference_sample = "6c6c5e35accc37c928d721c800476ccf4c4b5b06a1b0906dc5ff4df71ff50943"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 74 00 69 00 6C 00 6C 00 6B 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x0a][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0b-\x0b][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x0b-\x0b][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x09-\x09][\x00-\x00])/
        $str1 = "atillk64.pdb"
        $str2 = "ATI Diagnostics" wide
        $str3 = "ATI Diagnostics Hardware Abstraction Sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Atillk_20b69f9d {
    meta:
        author = "Elastic Security"
        id = "20b69f9d-ee0f-4a44-a038-a1ef58c87330"
        fingerprint = "4bfc077e6d2de3bf7ec949deaaf3237aec07c8e35decea2097939d36fe303b3a"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Name: atillk64.sys, Version: <= 5.10.20.0"
        threat_name = "Windows.VulnDriver.Atillk"
        reference_sample = "d2182b6ef3255c7c1a69223cd3c2d68eb8ba3112ce433cd49cd803dc76412d4b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 74 00 69 00 6C 00 6C 00 6B 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x09][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0a-\x0a][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x14-\x14][\x00-\x00])/
        $str1 = "atillk64.pdb"
        $str2 = "Overclocking Tool" wide
        $str3 = "Overclocking Hardware Abstraction Sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

