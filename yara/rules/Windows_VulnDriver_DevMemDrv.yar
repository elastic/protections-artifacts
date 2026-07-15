rule Windows_VulnDriver_DevMemDrv_2be96754 {
    meta:
        author = "Elastic Security"
        id = "2be96754-8d47-47d2-95ae-c7c8bcb95289"
        fingerprint = "baca005a6b9dcdeb9e47cd0e894b884861d6a8147de764434a43244f5c1cbaae"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: ACCULOGIC, INC., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.DevMemDrv"
        reference_sample = "b93020428f6d9ca700ab70a14911c7efcbcb1f9b659054add0dd3e7657511eb3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 43 43 55 4C 4F 47 49 43 2C 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 64 00 65 00 76 00 4D 00 65 00 6D 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "devMem.pdb"
        $str2 = "Integrator" wide
        $str3 = "devMemDrv" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

