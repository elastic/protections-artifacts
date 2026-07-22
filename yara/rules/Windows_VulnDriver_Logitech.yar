rule Windows_VulnDriver_Logitech_18fec1c0 {
    meta:
        author = "Elastic Security"
        id = "18fec1c0-deb9-4170-a928-7efbc33a0e9f"
        fingerprint = "16895ccb543f7027e17e25fce19f7de1279cb86460d3a2f2290d83a03b3a44c3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Logitech, Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Logitech"
        reference_sample = "e0cb07a0624ddfacaa882af49e3783ae02c9fbd0ab232541a05a95b4a8abd8ef"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 6F 67 69 74 65 63 68 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 67 00 43 00 6F 00 72 00 65 00 54 00 65 00 6D 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "LgCoreTemp.pdb"
        $str2 = "LgCoreTemp" wide
        $str3 = "CPU Core Temperature Monitor" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Logitech_83070104 {
    meta:
        author = "Elastic Security"
        id = "83070104-c856-4fef-af3f-e6410a07d96a"
        fingerprint = "5ae3e5c8350ba5639d427deffb686aa8dc6f80843ff8bc36c8d653b9f31f0682"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Logitech Inc, Version: <= 12.0.1278.0"
        threat_name = "Windows.VulnDriver.Logitech"
        reference_sample = "e86cb77de7b6a8025f9a546f6c45d135f471e664963cf70b381bee2dfd0fdef4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 6F 67 69 74 65 63 68 20 49 6E 63 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 76 00 35 00 36 00 31 00 61 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0c-\x0c][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\xfd][\x04-\x04])|[\x00-\x00][\x00-\x00][\x0c-\x0c][\x00-\x00][\x00-\x00][\x00-\x00][\xfe-\xfe][\x04-\x04])/
        $str1 = "lv561v64.pdb"
        $str2 = "Logitech Webcam Software" wide
        $str3 = "Logitech Video Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

