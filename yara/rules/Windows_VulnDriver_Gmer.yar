rule Windows_VulnDriver_Gmer_4aa15040 {
    meta:
        author = "Elastic Security"
        id = "4aa15040-1cde-4eb7-af62-654a879146a0"
        fingerprint = "1740c57451461b2635762242bd0f43d7d8c1b2ba9bf95f089c38f1d378234c78"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: GMEREK Systemy Komputerowe Przemyslaw Gmerek, Version: <= 2.0.6983.0"
        threat_name = "Windows.VulnDriver.Gmer"
        reference_sample = "0052aa88e42055a2eed5ddd17c3499c692360155e5e031a211edfcef577acce3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 4D 45 52 45 4B 20 53 79 73 74 65 6D 79 20 4B 6F 6D 70 75 74 65 72 6F 77 65 20 50 72 7A 65 6D 79 73 6C 61 77 20 47 6D 65 72 65 6B }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 67 00 6D 00 65 00 72 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x1a]|[\x00-\x46][\x1b-\x1b])|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x47-\x47][\x1b-\x1b])/
        $str1 = "gmer64.pdb"
        $str2 = "GMER Driver http://www.gmer.net" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

rule Windows_VulnDriver_Gmer_6c0971b9 {
    meta:
        author = "Elastic Security"
        id = "6c0971b9-5587-43ba-b395-4a1f55c3fde8"
        fingerprint = "055d5276454bd380595271f0e91dfaa545efd9e47fbcf1e8d5df4ad2c4ac757d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: gmer.sys, Version: <= 1.0.15.4809"
        threat_name = "Windows.VulnDriver.Gmer"
        reference_sample = "876cf88b59424dc3273eb499916cf2a45cff48451c07b7930f5a44bcafd409b0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 67 00 6D 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x11]|[\x00-\xc8][\x12-\x12])[\x0f-\x0f][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\xc9-\xc9][\x12-\x12][\x0f-\x0f][\x00-\x00])/
        $str1 = "gmer.pdb"
        $str2 = "GMER Driver http://www.gmer.net" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

