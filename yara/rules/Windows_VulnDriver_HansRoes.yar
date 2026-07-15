rule Windows_VulnDriver_HansRoes_b1205169 {
    meta:
        author = "Elastic Security"
        id = "b1205169-63e0-4938-9204-7eba9a1e5eed"
        fingerprint = "2825f9989cdaf19dfc90b60fe110cb435703a120d3463a17d82bd32cd806cbe5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Hans Roes, Version: <= 367.3269.61.64"
        threat_name = "Windows.VulnDriver.HansRoes"
        reference_sample = "9f4ce6ab5e8d44f355426d9a6ab79833709f39b300733b5b251a0766e895e0e5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 61 6E 73 20 52 6F 65 73 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\x6e][\x01-\x01])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0b]|[\x00-\xc4][\x0c-\x0c])[\x6f-\x6f][\x01-\x01][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\xc5-\xc5][\x0c-\x0c][\x6f-\x6f][\x01-\x01][\x00-\xff][\x00-\xff][\x00-\x3c][\x00-\x00]|[\xc5-\xc5][\x0c-\x0c][\x6f-\x6f][\x01-\x01][\x00-\x3f][\x00-\x00][\x3d-\x3d][\x00-\x00]|[\xc5-\xc5][\x0c-\x0c][\x6f-\x6f][\x01-\x01][\x40-\x40][\x00-\x00][\x3d-\x3d][\x00-\x00])/
        $str1 = "Fairplay_7.pdb"
        $str2 = "MTA San Andreas" wide
        $str3 = "Multi Theft Auto patch driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}

