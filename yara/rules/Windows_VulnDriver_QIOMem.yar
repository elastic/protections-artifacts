rule Windows_VulnDriver_QIOMem_228b3edf {
    meta:
        author = "Elastic Security"
        id = "228b3edf-03e3-49cd-b577-fd4e37f5d05d"
        fingerprint = "d8d5e20ead86eead12f410ff686d8924a8645d1b1b244cabe362638e69c7adc8"
        creation_date = "2026-07-20"
        last_modified = "2026-08-11"
        description = "Subject: WDKTestCert 1,130752733198717037, Version: <= 5.0.0.0"
        threat_name = "Windows.VulnDriver.QIOMem"
        reference_sample = "6abd8d0d541bcf9e257c65122216b1d2ae92cbf8a3a3cb7ce340846e66c449ca"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 44 4B 54 65 73 74 43 65 72 74 20 31 2C 31 33 30 37 35 32 37 33 33 31 39 38 37 31 37 30 33 37 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 51 00 49 00 4F 00 4D 00 65 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "QIOMem.pdb"
        $str2 = "Generic IO & Memory Access" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

