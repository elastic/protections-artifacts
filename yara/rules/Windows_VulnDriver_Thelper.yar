rule Windows_VulnDriver_Thelper_441debda {
    meta:
        author = "Elastic Security"
        id = "441debda-c3f0-4a3b-a4cc-e8bdffd84848"
        fingerprint = "9c908ac4acb5c722adbf5916061d899cf9d7d301c8a5248799bc4dfb7db6b548"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: T.E.C Solutions (G.Z.)Limited, Version: <= 4.71.408.0"
        threat_name = "Windows.VulnDriver.Thelper"
        reference_sample = "7e783b0a0ff4710306bb3bca29296cf962ae77abc81245a99f12a9039158226f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 2E 45 2E 43 20 53 6F 6C 75 74 69 6F 6E 73 20 28 47 2E 5A 2E 29 4C 69 6D 69 74 65 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 74 00 68 00 65 00 6C 00 70 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x46][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x47-\x47][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\x97][\x01-\x01])|[\x47-\x47][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00][\x98-\x98][\x01-\x01])/
        $str1 = "THlpDrv.pdb"
        $str2 = "OCular THelper" wide
        $str3 = "THelper Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

