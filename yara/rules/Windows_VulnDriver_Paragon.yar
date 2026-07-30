rule Windows_VulnDriver_Paragon_614bf8d0 {
    meta:
        author = "Elastic Security"
        id = "614bf8d0-0049-4902-802b-682897c669dd"
        fingerprint = "ef541207995f805a8b202803e9c6497868e2b936bccef66b029535e3ddc0fc19"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Paragon Software GmbH, Version: <= 10.1.25.431"
        threat_name = "Windows.VulnDriver.Paragon"
        reference_sample = "b80bea4c09dafb0bfd2ca067130a7ead64faba8f78599dad4d4291a4a29f3a23"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 61 67 6F 6E 20 53 6F 66 74 77 61 72 65 20 47 6D 62 48 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 62 00 69 00 6F 00 6E 00 74 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x18][\x00-\x00]|[\x01-\x01][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xae][\x01-\x01])[\x19-\x19][\x00-\x00]|[\x01-\x01][\x00-\x00][\x0a-\x0a][\x00-\x00][\xaf-\xaf][\x01-\x01][\x19-\x19][\x00-\x00])/
        $str1 = "Paragon System Utilities" wide
        $str2 = "A part of Paragon System Utilities" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

