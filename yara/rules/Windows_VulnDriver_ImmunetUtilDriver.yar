rule Windows_VulnDriver_ImmunetUtilDriver_27dfc52b {
    meta:
        author = "Elastic Security"
        id = "27dfc52b-3699-44e5-b0d1-ce36f6f02c53"
        fingerprint = "d3f347ed0aff8f7aa9c07437e2517755da37dbe86671a925712b9610f2a15ce4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 0.7.9.517"
        threat_name = "Windows.VulnDriver.ImmunetUtilDriver"
        reference_sample = "2e270063af92a4f37d3f828dbb444c9a6277ea0d15a5b808e66e3b66ca5f5a58"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 6D 00 6D 00 75 00 6E 00 65 00 74 00 55 00 74 00 69 00 6C 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x07-\x07][\x00-\x00][\x00-\x00][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x01]|[\x00-\x04][\x02-\x02])[\x09-\x09][\x00-\x00]|[\x07-\x07][\x00-\x00][\x00-\x00][\x00-\x00][\x05-\x05][\x02-\x02][\x09-\x09][\x00-\x00])/
        $str1 = "ImmunetUtilDriver.pdb"
        $str2 = "Cisco Secure Endpoint" wide
        $str3 = "ImmunetUtilDriver.sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

