rule Windows_VulnDriver_ItlsFFN_a443d7fa {
    meta:
        author = "Elastic Security"
        id = "a443d7fa-56e5-4275-a886-fdceeaf7991d"
        fingerprint = "ea07c7be4a72d42147abd90c7e23ded92f0950a47804e0cc5ccea6595a84ce4b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: ITM System Co.,Ltd, Version: <= 2015.3.27.1936"
        threat_name = "Windows.VulnDriver.ItlsFFN"
        reference_sample = "01714295a16acc253e50be2c068974ac621b9635a9c328b4dc578cecb03b06f9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 54 4D 20 53 79 73 74 65 6D 20 43 6F 2E 2C 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 74 00 6C 00 73 00 46 00 46 00 4E 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xde][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\xdf-\xdf][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\xdf-\xdf][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x1a][\x00-\x00]|[\x03-\x03][\x00-\x00][\xdf-\xdf][\x07-\x07]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\x8f][\x07-\x07])[\x1b-\x1b][\x00-\x00]|[\x03-\x03][\x00-\x00][\xdf-\xdf][\x07-\x07][\x90-\x90][\x07-\x07][\x1b-\x1b][\x00-\x00])/
        $str1 = "ItlsOTN.pdb"
        $str2 = "ItlsFFN (TM) NE \"2015\" for Windows" wide
        $str3 = "Windows Mini-Filter Monitor Network Edition" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

