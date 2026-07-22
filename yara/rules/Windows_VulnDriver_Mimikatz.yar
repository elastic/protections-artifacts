rule Windows_VulnDriver_Mimikatz_5a6e0ac2 {
    meta:
        author = "Elastic Security"
        id = "5a6e0ac2-7af3-4933-9e6d-920b24997be5"
        fingerprint = "2c50451836a6580f464642a35be2e89e9d3fbf8bd57a01c935236d9595f62756"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Benjamin Delpy"
        threat_name = "Windows.VulnDriver.Mimikatz"
        reference_sample = "083a311875173f8c4653e9bbbabb689d14aa86b852e7fa9f5512fc60e0fd2c43"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }
        $str1 = "mimikatz.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $str1
}

rule Windows_VulnDriver_Mimikatz_9e777c57 {
    meta:
        author = "Elastic Security"
        id = "9e777c57-d109-4a5a-ace5-75eadc967148"
        fingerprint = "fc5c736543f542604489695d5245374b4d2bbf7ccb643fa8bcf027b727e9b286"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Benjamin Delpy, Version: <= 2.2.0.0"
        threat_name = "Windows.VulnDriver.Mimikatz"
        reference_sample = "083f821d90e607ed93221e71d4742673e74f573d0755a96ad17d1403f65a2254"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6D 00 69 00 6D 00 69 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "mimidrv.pdb"
        $str2 = "mimidrv (mimikatz)" wide
        $str3 = "mimidrv for Windows (mimikatz)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Mimikatz_43e90c6a {
    meta:
        author = "Elastic Security"
        id = "43e90c6a-ed07-48aa-ab19-58b782a2543d"
        fingerprint = "128fbe5268edc054a685020329d285dda6650cfec5427c8ed1512fd465af3fae"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Open Source Developer, Benjamin Delpy, Version: <= 2.1.1.0"
        threat_name = "Windows.VulnDriver.Mimikatz"
        reference_sample = "21617210249d2a35016e8ca6bd7a1edda25a12702a2294d56010ee8148637f5a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 70 65 6E 20 53 6F 75 72 63 65 20 44 65 76 65 6C 6F 70 65 72 2C 20 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6D 00 69 00 6D 00 69 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "mimidrv.pdb"
        $str2 = "mimidrv (mimikatz)" wide
        $str3 = "mimidrv for Windows (mimikatz)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

rule Windows_VulnDriver_Mimikatz_11556ea8 {
    meta:
        author = "Elastic Security"
        id = "11556ea8-d2b5-488a-beba-3149a7b9984a"
        fingerprint = "4cff64faabc66be451a206610eea5e20021963896223e275bff21fca0f31abd4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Benjamin Delpy"
        threat_name = "Windows.VulnDriver.Mimikatz"
        reference_sample = "af7ca247bf229950fb48674b21712761ac650d33f13a4dca44f61c59f4c9ac46"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }
        $str1 = "mimidrv.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}

