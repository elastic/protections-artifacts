rule Windows_VulnDriver_Nxeng_027b476e {
    meta:
        author = "Elastic Security"
        id = "027b476e-cc2b-4e2d-95de-8fd8f4cefc3a"
        fingerprint = "7e8324ada7947724ea40522c59bb56045882be42e4fd8e030f46e9207cd7270f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 0.0.0.0"
        threat_name = "Windows.VulnDriver.Nxeng"
        reference_sample = "68d698a978b8ea3bf467bdea2d75ef3099826c3a0d4a1ddb95b078f48f0ae7a1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 78 00 65 00 6E 00 67 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]/
        $str1 = "nxeng_init"
        $str2 = "Huorong eXtendible Stream Scan Engine" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}

