rule Windows_VulnDriver_Srvnetbus_5892298e {
    meta:
        author = "Elastic Security"
        id = "5892298e-597f-437a-ae9c-b6df3d32546e"
        fingerprint = "da99b40acf5bdbb2c6f0e413a3cbd74befd2d45e75d4118ed16198108a37c75a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: JCOS Media, Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Srvnetbus"
        reference_sample = "029dbf6d8dc920a32b3c7a2057513d3741b20b7f6e7aa23b113859a8049214df"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4A 43 4F 53 20 4D 65 64 69 61 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 72 00 76 00 6E 00 65 00 74 00 62 00 75 00 73 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "gejoriejo.pdb"
        $str2 = "srvnetbus" wide
        $str3 = "System File" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

