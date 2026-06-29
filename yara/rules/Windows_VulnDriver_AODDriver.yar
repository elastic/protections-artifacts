rule Windows_VulnDriver_AODDriver_59f991c1 {
    meta:
        author = "Elastic Security"
        id = "59f991c1-efa3-4b79-b12a-fee7e9b9194c"
        fingerprint = "2a144b9df6d63e48f18cd2364901a1806cff2ddccddc269d11644339b73906dc"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Name: AODDriver.sys, Version: <= 3.2.0.0"
        threat_name = "Windows.VulnDriver.AODDriver"
        reference_sample = "81d54ebef1716e195955046ffded498a5a7e325bf83e7847893aa3b0b3776d05"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4F 00 44 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AODDriver.pdb"
        $str2 = "AMD OverDrive Service Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

