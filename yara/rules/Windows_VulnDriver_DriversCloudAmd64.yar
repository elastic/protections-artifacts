rule Windows_VulnDriver_DriversCloudAmd64_068c4738 {
    meta:
        author = "Elastic Security"
        id = "068c4738-fe7f-4b10-9092-c14951688b22"
        fingerprint = "dfefcb40043cc84eb376e098a9f790334b523993bb0165178e009cd0a56aacb6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Cybelsoft, Version: <= 10.0.0.0"
        threat_name = "Windows.VulnDriver.DriversCloudAmd64"
        reference_sample = "2bc72d11fa0beda25dc1dbc372967db49bd3c3a3903913f0877bff6792724dfe"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 79 62 65 6C 73 6F 66 74 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 72 00 69 00 76 00 65 00 72 00 73 00 43 00 6C 00 6F 00 75 00 64 00 5F 00 61 00 6D 00 64 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "DriversCloud_amd64.pdb"
        $str2 = "DriversCloud.com" wide
        $str3 = "Driver NT DriversCloud" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

