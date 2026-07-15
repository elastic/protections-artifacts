rule Windows_VulnDriver_Hwdetectng_0a1834fa {
    meta:
        author = "Elastic Security"
        id = "0a1834fa-d9ee-4bf5-8a69-b1bf5599752a"
        fingerprint = "40ce1c9d451ad64e059a2a2e734e3fb39f29094515f17bbf9ab0062e70d10296"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: iNFERRE, Version: <= 6.0.6000.16386"
        threat_name = "Windows.VulnDriver.Hwdetectng"
        reference_sample = "43136de6b77ef85bc661d401723f38624e93c4408d758bc9f27987f2b4511fee"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 69 4E 46 45 52 52 45 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 68 00 77 00 64 00 65 00 74 00 65 00 63 00 74 00 6E 00 67 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x16]|[\x00-\x6f][\x17-\x17])|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x3f]|[\x00-\x01][\x40-\x40])[\x70-\x70][\x17-\x17]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x02-\x02][\x40-\x40][\x70-\x70][\x17-\x17])/
        $str1 = "HwDetectNG.pdb"
        $str2 = "hwdetectng.sys" wide
        $str3 = "HWDetectNG" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

