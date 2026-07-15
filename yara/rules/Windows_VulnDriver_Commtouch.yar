rule Windows_VulnDriver_Commtouch_cb231bdd {
    meta:
        author = "Elastic Security"
        id = "cb231bdd-c465-4fda-a23b-7b76903fb5c9"
        fingerprint = "ad2d44b98ab2f9312f4ed2a8e6aefce4ff7ad0a93f4f03e555c45b7cec2de47b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Commtouch, Inc., Version: <= 5.4.11.1"
        threat_name = "Windows.VulnDriver.Commtouch"
        reference_sample = "cbb8239a765bf5b2c1b6a5c8832d2cab8fef5deacadfb65d8ed43ef56d291ab6"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 6F 6D 6D 74 6F 75 63 68 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 6D 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x0b-\x0b][\x00-\x00])/
        $str1 = "AMP.pdb"
        $str2 = "CYREN AMP 5" wide
        $str3 = "AMP Minifilter" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}

