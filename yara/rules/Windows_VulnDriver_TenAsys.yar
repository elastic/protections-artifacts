rule Windows_VulnDriver_TenAsys_2d3c3dc8 {
    meta:
        author = "Elastic Security"
        id = "2d3c3dc8-7a31-4071-8408-fa53e63e0cb2"
        fingerprint = "f801a5685563b4569b722ca579e958a5cd992fcee09c40e5e52130a9c18735ac"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: TenAsys Corporation, Version: <= 6.4.21343.1"
        threat_name = "Windows.VulnDriver.TenAsys"
        reference_sample = "9399f35b90f09b41f9eeda55c8e37f6d1cb22de6e224e54567d1f0865a718727"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 6E 41 73 79 73 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 69 00 66 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x52]|[\x00-\x5e][\x53-\x53])|[\x04-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x5f-\x5f][\x53-\x53]|[\x04-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x5f-\x5f][\x53-\x53])/
        $str1 = "rtif64.pdb"
        $str2 = "INtime PnP RT Kernel Interface Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_TenAsys_191c955f {
    meta:
        author = "Elastic Security"
        id = "191c955f-7f2d-4ce3-b6b8-492ea3d47d0f"
        fingerprint = "b62051b8d3f9103f366041b1bdf72e0d94f4efcd6493c91de9e1a16691686b54"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: TenAsys Corporation, Version: <= 6.4.21343.1"
        threat_name = "Windows.VulnDriver.TenAsys"
        reference_sample = "a66b4420fa1df81a517e2bbea1a414b57721c67a4aa1df1967894f77e81d036e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 6E 41 73 79 73 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 69 00 66 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x52]|[\x00-\x5e][\x53-\x53])|[\x04-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x5f-\x5f][\x53-\x53]|[\x04-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x5f-\x5f][\x53-\x53])/
        $str1 = "rtif.pdb"
        $str2 = "INtime PnP RT Kernel Interface Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}

