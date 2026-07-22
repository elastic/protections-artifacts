rule Windows_VulnDriver_Probmon_091a7ff6 {
    meta:
        author = "Elastic Security"
        id = "091a7ff6-5545-460e-9174-58c0e34df16a"
        fingerprint = "d94bb519f30cb1616c48dd97be1d714199dd099b73e726465aee3bea11cb0da4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: ITM System Co.,LTD, Version: <= 3.0.0.6"
        threat_name = "Windows.VulnDriver.Probmon"
        reference_sample = "c2026232d39f5b0a8e9f15da8cb8f74e550b9498ae3b4015fb17fcc5d580d98b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 54 4D 20 53 79 73 74 65 6D 20 43 6F 2E 2C 4C 54 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 62 00 6D 00 6F 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x05][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Probmon.pdb"
        $str2 = "ITM SYSTEM File Filter Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

