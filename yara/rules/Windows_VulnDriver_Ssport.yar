rule Windows_VulnDriver_Ssport_d2320848 {
    meta:
        author = "Elastic Security"
        id = "d2320848-86c0-4b1b-9248-b1239b8ec4c1"
        fingerprint = "de6653522697f4059a0f8cf414a0e06fc9444f9aa50198be78af96e57967ce98"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: SSPORT.sys, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Ssport"
        reference_sample = "b7ddfe870f76851a7dee6687d1ef48fb70e52b400ffe950021d58c2ad9e51959"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 53 00 50 00 4F 00 52 00 54 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SSPORT64.pdb"
        $str2 = "Port Contention Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}

