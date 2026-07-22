rule Windows_VulnDriver_Portwell_5732be53 {
    meta:
        author = "Elastic Security"
        id = "5732be53-43d8-4502-b80d-94f2d6c5edf3"
        fingerprint = "a070f5db389ca67e28b15716b910905a9216a65eca90ccbb7e8e0bad6663550b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Portwell Inc., Version: <= 0.1.0.0"
        threat_name = "Windows.VulnDriver.Portwell"
        reference_sample = "2f0b16ed90b8c15bf52a7c32699dbe0dbcd38fc02ed2ddb4e1ba35487177b6c5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 6F 72 74 77 65 6C 6C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 6F 00 72 00 74 00 77 00 65 00 6C 00 6C 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "portwell.pdb"
        $str2 = "portwell driver" wide
        $str3 = "kernel mode driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

