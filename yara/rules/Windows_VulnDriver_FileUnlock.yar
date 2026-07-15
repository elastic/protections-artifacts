rule Windows_VulnDriver_FileUnlock_a021fda5 {
    meta:
        author = "Elastic Security"
        id = "a021fda5-1eb9-4589-af3b-373cc8f24d5b"
        fingerprint = "692ba9b210578806eaa3853baf0669838055786ea43bc30182d66248f71e3c4d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: FileUnlock.sys, Version: <= 1.3.0.20"
        threat_name = "Windows.VulnDriver.FileUnlock"
        reference_sample = "756841a4f6021b12e299f0572ac793d34549f1d503ff65bab366e043841bb18c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 46 00 69 00 6C 00 65 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x13][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "FileUnlock" wide
        $str3 = "File unlock driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}

